import hashlib
import json
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


def _normalize_severity(raw: str) -> str:
    mapping = {
        "critical":    "critical",
        "high":        "high",
        "medium":      "medium",
        "moderate":    "medium",
        "low":         "low",
        "info":        "info",
        "informational": "info",
        "warning":     "medium",
    }
    return mapping.get(raw.strip().lower(), "low")


def _make_hash(host: str, event_id: str, timestamp: str) -> str:
    key = f"{host}|{event_id}|{timestamp}"
    return hashlib.sha256(key.encode()).hexdigest()


def _text(el, *tags) -> str:
    for tag in tags:
        child = el.find(tag)
        if child is not None and child.text:
            return child.text.strip()
    return ""


def _record(event_id, timestamp, host, event_type, severity, user, description):
    sev = _normalize_severity(severity)
    ts  = timestamp or datetime.utcnow().isoformat()
    return {
        "source":      "log360",
        "host":        host.strip(),
        "event_id":    event_id.strip(),
        "event_type":  event_type.strip(),
        "severity":    sev,
        "user":        user.strip() if user else "",
        "description": description.strip() if description else "",
        "detected_at": ts,
        "raw_hash":    _make_hash(host, event_id, ts),
    }


def _parse_xml(filepath: str) -> list:
    tree = ET.parse(filepath)
    root = tree.getroot()
    records = []

    events = root.findall(".//Event") + root.findall(".//event")
    for ev in events:
        records.append(_record(
            event_id    = _text(ev, "EventID", "eventId", "event_id"),
            timestamp   = _text(ev, "Timestamp", "timestamp", "Time", "time"),
            host        = _text(ev, "SourceHost", "sourceHost", "source_host", "Host", "host") or "unknown",
            event_type  = _text(ev, "EventType", "eventType", "event_type", "Type", "type"),
            severity    = _text(ev, "Severity", "severity") or "low",
            user        = _text(ev, "User", "user", "Username", "username"),
            description = _text(ev, "Description", "description", "Message", "message"),
        ))
    return records


def _parse_json(filepath: str) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    events = data if isinstance(data, list) else data.get("events", data.get("Events", []))
    records = []

    for ev in events:
        records.append(_record(
            event_id    = str(ev.get("event_id") or ev.get("EventID") or ev.get("eventId") or ""),
            timestamp   = ev.get("timestamp") or ev.get("Timestamp") or ev.get("time") or "",
            host        = ev.get("source_host") or ev.get("SourceHost") or ev.get("host") or "unknown",
            event_type  = ev.get("event_type") or ev.get("EventType") or ev.get("type") or "",
            severity    = ev.get("severity") or ev.get("Severity") or "low",
            user        = ev.get("user") or ev.get("User") or ev.get("username") or "",
            description = ev.get("description") or ev.get("Description") or ev.get("message") or "",
        ))
    return records


def parse_log360(filepath: str) -> list:
    if Path(filepath).suffix.lower() == ".json":
        return _parse_json(filepath)
    return _parse_xml(filepath)
