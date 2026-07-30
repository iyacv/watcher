
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
    # All escalation rules use F5/CVSS semantics. Log360 events use their own
    # native vocabulary (error/failure/warning/information/success) which we
    # don't try to escalate they describe Windows event outcomes, not
    # vulnerability risk.
    if record.get("source") != "f5":
        return record

    sev = record.get("severity", "low")

    # Rule 1: CVSS score override
    cvss = record.get("cvss") or 0.0
    if float(cvss) >= 9.0:
        sev = "critical"

    # Rule 2: High-value target
    if record.get("host") in _HIGH_VALUE_HOSTS:
        sev = _escalate(sev)

    # Rule 3: Aging
    if record.get("detected_at"):
        age = datetime.now(tz=timezone.utc) - _parse_dt(record["detected_at"])
        if age.days >= config.AGING_THRESHOLD_DAYS:
            sev = _escalate(sev)
            record["aged"] = True

    record["severity"] = sev
    return record
