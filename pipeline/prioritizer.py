"""
Prioritizer — adjusts severity based on business rules before storage.

Rules applied in order (first match wins for escalation):
  1. CVSS >= 9.0 → always critical
  2. Vulnerability is in a known high-value target list → escalate one level
  3. Aging: if detected_at is more than AGING_THRESHOLD_DAYS old → escalate one level
"""

from datetime import datetime, timezone

import config

_HIGH_VALUE_HOSTS = {
    "192.168.1.1",
    "10.0.0.1",
}

_SEVERITY_UP = {
    "info":     "low",
    "low":      "medium",
    "medium":   "high",
    "high":     "critical",
    "critical": "critical",
}


def _escalate(sev: str) -> str:
    return _SEVERITY_UP.get(sev, sev)


def _parse_dt(ts: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(tz=timezone.utc)


def prioritize(record: dict) -> dict:
    sev = record.get("severity", "low")

    # Rule 1: CVSS score override
    cvss = record.get("cvss") or 0.0
    if float(cvss) >= 9.0:
        sev = "critical"

    # Rule 2: High-value target
    if record.get("host") in _HIGH_VALUE_HOSTS:
        sev = _escalate(sev)

    # Rule 3: Aging — only applies to F5 vulns with a detected_at
    if record.get("source") == "f5" and record.get("detected_at"):
        age = datetime.now(tz=timezone.utc) - _parse_dt(record["detected_at"])
        if age.days >= config.AGING_THRESHOLD_DAYS:
            sev = _escalate(sev)
            record["aged"] = True

    record["severity"] = sev
    return record
