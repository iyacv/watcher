import hashlib
import json
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


def _normalize_severity(raw: str) -> str:
    mapping = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "moderate": "medium",
        "low":      "low",
        "info":     "info",
        "informational": "info",
    }
    return mapping.get(raw.strip().lower(), "low")


def _make_hash(host: str, vuln_id: str, severity: str) -> str:
    key = f"{host}|{vuln_id}|{severity}"
    return hashlib.sha256(key.encode()).hexdigest()


def _text(el, *tags) -> str:
    for tag in tags:
        child = el.find(tag)
        if child is not None and child.text:
            return child.text.strip()
    return ""


def _record(host, port, vuln_id, name, severity, cvss, description, remediation, scan_date):
    sev = _normalize_severity(severity)
    return {
        "source":      "f5",
        "host":        host.strip(),
        "port":        int(port) if port else None,
        "vuln_id":     vuln_id.strip(),
        "name":        name.strip(),
        "severity":    sev,
        "cvss":        float(cvss) if cvss else None,
        "description": description.strip() if description else "",
        "remediation": remediation.strip() if remediation else "",
        "detected_at": scan_date or datetime.utcnow().isoformat(),
        "raw_hash":    _make_hash(host, vuln_id, sev),
        "status":      "open",
        "aged":        False,
    }


def _parse_xml(filepath: str) -> list:
    tree = ET.parse(filepath)
    root = tree.getroot()
    records = []

    scans = root.findall(".//Scan")
    if not scans:
        scans = [root]

    for scan in scans:
        scan_date = _text(scan, "ScanDate", "scan_date") or datetime.utcnow().date().isoformat()
        host = _text(scan, "Target/Host", "target/host") or "unknown"
        port = _text(scan, "Target/Port", "target/port")

        for vuln in scan.findall(".//Vulnerability") + scan.findall(".//vulnerability"):
            records.append(_record(
                host        = host,
                port        = port,
                vuln_id     = _text(vuln, "ID", "id"),
                name        = _text(vuln, "Name", "name"),
                severity    = _text(vuln, "Severity", "severity") or "low",
                cvss        = _text(vuln, "CVSS", "cvss"),
                description = _text(vuln, "Description", "description"),
                remediation = _text(vuln, "Remediation", "remediation"),
                scan_date   = scan_date,
            ))
    return records


def _parse_json(filepath: str) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    scans = data if isinstance(data, list) else [data]
    records = []

    for scan in scans:
        scan_date = scan.get("scan_date", datetime.utcnow().date().isoformat())
        target    = scan.get("target", {})
        host      = target.get("host", "unknown")
        port      = target.get("port")

        for vuln in scan.get("vulnerabilities", []):
            records.append(_record(
                host        = host,
                port        = port,
                vuln_id     = vuln.get("id", ""),
                name        = vuln.get("name", ""),
                severity    = vuln.get("severity", "low"),
                cvss        = vuln.get("cvss", 0),
                description = vuln.get("description", ""),
                remediation = vuln.get("remediation", ""),
                scan_date   = scan_date,
            ))
    return records


def parse_f5(filepath: str) -> list:
    if Path(filepath).suffix.lower() == ".json":
        return _parse_json(filepath)
    return _parse_xml(filepath)
