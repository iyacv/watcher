import os
from dotenv import load_dotenv

load_dotenv()

# ── Folder paths ──────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
INBOX_DIR     = os.path.join(BASE_DIR, "inbox")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")
FAILED_DIR    = os.path.join(BASE_DIR, "failed")

# ── SQLite ────────────────────────────────────────────────────────────────────
DB_PATH = os.getenv("DB_PATH", os.path.join(BASE_DIR, "capstone.db"))

# ── Correlation window ────────────────────────────────────────────────────────
CORRELATION_WINDOW_MINUTES = 60

# ── Aging threshold ───────────────────────────────────────────────────────────
AGING_THRESHOLD_DAYS = 7

# ── Severity order (highest first) ───────────────────────────────────────────
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ── Keep processed files? ─────────────────────────────────────────────────────
# False (default): delete the file after successful processing to save disk.
# True: move to processed/ for audit trail.
KEEP_PROCESSED = os.getenv("KEEP_PROCESSED", "false").lower() in ("true", "1", "yes")
