"""
Main entry point. Run this script to start watching the inbox folder.
Usage: python watcher.py
"""

import time
import shutil
import logging
import logging.handlers
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

# Ensure this script's directory is importable even when launched from
# Task Scheduler or under embeddable Python (which omits the script dir
# from sys.path via python._pth).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import config
from parsers.f5_parser import parse_f5
from parsers.log360_parser import parse_log360
from pipeline.deduplicator import is_duplicate, mark_seen, load_existing_hashes
from pipeline.prioritizer import prioritize
from pipeline.correlator import correlate
from storage.db import insert_vulnerability, insert_event, flag_correlation, get_connection

_LOG_FILE = _HERE / "watcher.log"
_log_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Rotating file handler: keeps history so success/failure is provable even
# though the watcher runs hidden via Task Scheduler (no visible console).
_file_handler = logging.handlers.RotatingFileHandler(
    _LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
)
_file_handler.setFormatter(_log_fmt)

# Console handler too, for when the watcher is run manually from a terminal.
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_log_fmt)

logging.basicConfig(level=logging.INFO, handlers=[_file_handler, _console_handler])
log = logging.getLogger(__name__)


def detect_source(filepath: str) -> str:
    """Guess file source from filename prefix, extension, or content tag."""
    path = Path(filepath)
    name = path.stem.lower()
    ext  = path.suffix.lower()
    if name.startswith("f5"):
        return "f5"
    if name.startswith("log360") or name.startswith("l360"):
        return "log360"
    # Excel exports only come from Log360 — F5 is XML-only
    if ext in (".xlsx", ".xlsm"):
        return "log360"
    # Fallback: peek at the file (text formats only)
    with open(filepath, "r", errors="ignore") as f:
        head = f.read(512)
    if "<scanner_vulnerabilities" in head or "<ScanResults" in head or "<F5" in head or "CVE" in head:
        return "f5"
    return "log360"


_in_flight = set()
_in_flight_lock = threading.Lock()


def process_file(filepath: str):
    path = Path(filepath)
    key = os.path.normcase(os.path.abspath(filepath))

    # Watchdog often fires both on_created and on_moved for a single drop on
    # Windows. Claim the path atomically so only one thread processes it.
    with _in_flight_lock:
        if key in _in_flight:
            return
        if not os.path.exists(filepath):
            return
        _in_flight.add(key)

    log.info("Detected new file: %s", path.name)

    try:
        source = detect_source(filepath)
        log.info("Source identified as: %s", source)

        if source == "f5":
            records = parse_f5(filepath)
        else:
            records = parse_log360(filepath)

        log.info("Parsed %d records from %s", len(records), path.name)

        conn = get_connection()
        inserted = 0

        for record in records:
            record["source_file"] = path.name

            # ── Deduplication ─────────────────────────────────────────────
            # For Log360 events (point-in-time happenings), a duplicate hash
            # means the same event was already recorded — skip entirely.
            # For F5 vulnerabilities (persistent state), we let duplicates
            # through so the storage layer can update severity/status and
            # log to vulnerability_changes if anything actually changed.
            if source == "log360" and is_duplicate(record):
                log.debug("Duplicate skipped: %s on %s", record.get("event_id"), record.get("host"))
                continue

            # ── Prioritization ────────────────────────────────────────────
            record = prioritize(record)

            # ── Store ──────────────────────────────────────────────────────
            if source == "f5":
                rec_id = insert_vulnerability(conn, record)
            else:
                rec_id = insert_event(conn, record)

            mark_seen(record)
            inserted += 1

            # ── Correlation ───────────────────────────────────────────────
            correlation = correlate(conn, record)
            if correlation:
                flag_correlation(conn, correlation)
                log.warning(
                    "CORRELATION DETECTED: %s on host %s — possible exploitation",
                    correlation.get("vuln_id"), correlation.get("host"),
                )

        conn.close()
        log.info("Inserted %d new records from %s", inserted, path.name)

        try:
            if config.KEEP_PROCESSED:
                dest = Path(config.PROCESSED_DIR) / path.name
                shutil.move(filepath, dest)
                log.info("Moved to processed: %s", dest)
            else:
                os.remove(filepath)
                log.info("Deleted processed file: %s", path.name)
        except FileNotFoundError:
            pass

    except FileNotFoundError:
        # Another watcher instance (or our own move) already claimed the file.
        # This is benign — just say so and move on without a stack trace.
        log.info("Skipped %s: already handled by another worker.", path.name)
    except Exception as exc:
        log.error("Failed to process %s: %s", path.name, exc, exc_info=True)
        try:
            dest = Path(config.FAILED_DIR) / path.name
            shutil.move(filepath, dest)
            # Drop a plain-English reason beside the failed file so anyone
            # browsing failed/ sees *why* without reading the watcher log.
            note = dest.with_suffix(dest.suffix + ".error.txt")
            note.write_text(
                f"File:   {path.name}\n"
                f"Failed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Reason: {type(exc).__name__}: {exc}\n",
                encoding="utf-8",
            )
        except FileNotFoundError:
            pass
    finally:
        with _in_flight_lock:
            _in_flight.discard(key)


class InboxHandler(FileSystemEventHandler):
    # Watchdog fires on_created for new files and on_moved when a file is
    # renamed/saved-into-folder by some OS copy operations.
    def on_created(self, event):
        if not event.is_directory:
            # Brief pause so the file is fully written before we open it
            time.sleep(0.5)
            process_file(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            time.sleep(0.5)
            process_file(event.dest_path)


def main():
    for folder in (config.INBOX_DIR, config.PROCESSED_DIR, config.FAILED_DIR):
        os.makedirs(folder, exist_ok=True)

    # Pre-load known hashes from the DB so restarts don't try to re-insert
    conn = get_connection()
    load_existing_hashes(conn)
    conn.close()

    # Process any files left in the inbox before we started watching
    pending = [p for p in Path(config.INBOX_DIR).iterdir() if p.is_file()]
    if pending:
        log.info("Found %d file(s) waiting in inbox; processing before watching.", len(pending))
        for p in pending:
            process_file(str(p))

    log.info("Watching inbox: %s", config.INBOX_DIR)
    handler = InboxHandler()
    observer = Observer()
    observer.schedule(handler, config.INBOX_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Stopping watcher...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
