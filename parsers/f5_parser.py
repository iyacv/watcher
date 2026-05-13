import hashlib
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


def _normalize_severity(raw: str) -> str:
    mapping = {
        "critical":      "critical",
        "high":          "high",
        "medium":        "medium",
        "moderate":      "medium",
        "low":           "low",
        "info":          "info",
        "informational": "info",
    }
    return mapping.get((raw or "").strip().lower(), "low")


def _host_from_url(url: str) -> str:
    if not url:
        return "unknown"
    parsed = urlparse(url.strip())
    return parsed.hostname or url.strip()


def _make_hash(host: str, url: str, name: str, attack_type: str, cookie: str) -> str:
    key = f"{host}|{url}|{name}|{attack_type or ''}|{cookie or ''}"
    return hashlib.sha256(key.encode()).hexdigest()


def _text(el, *tags) -> str:
    for tag in tags:
        child = el.find(tag)
        if child is not None and child.text:
            return child.text.strip()
    return ""


def _record(name, url, attack_type, cookie, severity, score, status, opened, fallback_ts):
    sev  = _normalize_severity(severity)
    host = _host_from_url(url)
    ts   = opened or fallback_ts
    try:
        cvss = float(score) if score not in (None, "") else None
    except (TypeError, ValueError):
        cvss = None
    return {
        "source":      "f5",
        "host":        host,
        "url":         url.strip() if url else None,
        "name":        (name or "").strip(),
        "attack_type": (attack_type.strip() or None) if attack_type else None,
        "cookie":      (cookie.strip() or None) if cookie else None,
        "severity":    sev,
        "cvss":        cvss,
        "status":      (status or "open").strip().lower(),
        "detected_at": ts,
        "raw_hash":    _make_hash(host, url or "", name or "", attack_type or "", cookie or ""),
        "aged":        False,
    }


def _file_mtime(filepath: str) -> str:
    try:
        return datetime.fromtimestamp(Path(filepath).stat().st_mtime).isoformat(timespec="seconds")
    except OSError:
        return datetime.utcnow().isoformat(timespec="seconds")


def _parse_xml(filepath: str) -> list:
    tree = ET.parse(filepath)
    root = tree.getroot()
    fallback_ts = _file_mtime(filepath)
    records = []

    # Real F5 scanner XML uses <scanner_vulnerabilities>/<vulnerability>.
    # Also tolerate the older capitalized form.
    vulns = root.findall(".//vulnerability") + root.findall(".//Vulnerability")
    for v in vulns:
        records.append(_record(
            name        = _text(v, "name", "Name"),
            url         = _text(v, "url", "URL", "Url"),
            attack_type = _text(v, "attack_type", "AttackType"),
            cookie      = _text(v, "cookie", "Cookie"),
            severity    = _text(v, "threat", "Threat", "severity", "Severity") or "low",
            score       = _text(v, "score", "Score", "cvss", "CVSS"),
            status      = _text(v, "status", "Status") or "open",
            opened      = _text(v, "opened", "Opened"),
            fallback_ts = fallback_ts,
        ))
    return records


def _parse_json(filepath: str) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        items = data
    else:
        items = data.get("vulnerabilities") or data.get("scanner_vulnerabilities") or []

    fallback_ts = _file_mtime(filepath)
    records = []
    for v in items:
        records.append(_record(
            name        = v.get("name", ""),
            url         = v.get("url", ""),
            attack_type = v.get("attack_type") or "",
            cookie      = v.get("cookie") or "",
            severity    = v.get("threat") or v.get("severity") or "low",
            score       = v.get("score") if v.get("score") is not None else v.get("cvss"),
            status      = v.get("status") or "open",
            opened      = v.get("opened") or "",
            fallback_ts = fallback_ts,
        ))
    return records


def parse_f5(filepath: str) -> list:
    if Path(filepath).suffix.lower() == ".json":
        return _parse_json(filepath)
    return _parse_xml(filepath)
