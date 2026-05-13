"""
Generates a Log360 sample .xlsx that matches the watcher's expected format.
Run once: python samples/_make_log360_sample.py
Produces: samples/log360_events_20260513.xlsx
"""
from openpyxl import Workbook
from pathlib import Path

OUT = Path(__file__).parent / "log360_events_20260513.xlsx"

# Each row: (time, log source, event id, display name, source, severity)
EVENTS = [
    ("2026-05-13 09:01:12", "ad1nsmi2022",   "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 09:01:45", "ad1nsmi2022",   "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 09:02:03", "ad1nsmi2022",   "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 09:02:30", "ad1nsmi2022",   "4740", "A user account was locked out",                  "microsoft-windows-security-auditing",  "warning"),
    ("2026-05-13 09:05:18", "ltop-nttc-226", "4624", "An account was successfully logged on",          "microsoft-windows-security-auditing",  "success"),
    ("2026-05-13 09:05:19", "ltop-nttc-226", "4672", "Special privileges assigned to new logon",       "microsoft-windows-security-auditing",  "information"),
    ("2026-05-13 09:08:42", "ltop-nttc-226", "4688", "A new process has been created",                 "microsoft-windows-security-auditing",  "success"),
    ("2026-05-13 09:12:01", "dtp-itsmi-067", "1102", "The audit log was cleared",                      "microsoft-windows-eventlog",           "warning"),
    ("2026-05-13 09:15:33", "dtp-itsmi-067", "4720", "A user account was created",                     "microsoft-windows-security-auditing",  "information"),
    ("2026-05-13 09:18:09", "dtp-itsmi-067", "4732", "A member was added to a security-enabled local group", "microsoft-windows-security-auditing", "warning"),
    ("2026-05-13 09:22:45", "lt-nsmi-2025004", "10028", "DCOM was unable to communicate with the computer", "microsoft-windows-distributedcom", "error"),
    ("2026-05-13 09:23:11", "lt-nsmi-2025004", "10028", "DCOM was unable to communicate with the computer", "microsoft-windows-distributedcom", "error"),
    ("2026-05-13 09:25:30", "lt-nsmi-2025004", "10016", "The application-specific permission settings do not grant Local Activation permission", "microsoft-windows-distributedcom", "warning"),
    ("2026-05-13 09:31:18", "ad2nsmi2022",   "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 09:31:19", "ad2nsmi2022",   "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 09:31:21", "ad2nsmi2022",   "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 09:31:22", "ad2nsmi2022",   "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 09:31:55", "ad2nsmi2022",   "4740", "A user account was locked out",                  "microsoft-windows-security-auditing",  "warning"),
    ("2026-05-13 09:40:02", "dtp-itsmi-063", "7045", "A service was installed in the system",          "microsoft-windows-service-control-manager", "information"),
    ("2026-05-13 09:42:18", "dtp-itsmi-063", "7036", "The service entered the running state",          "microsoft-windows-service-control-manager", "success"),
    ("2026-05-13 09:50:11", "ltp-itsmi-463", "10016", "The application-specific permission settings...", "microsoft-windows-distributedcom",   "warning"),
    ("2026-05-13 09:55:44", "ltp-itsmi-463", "4634", "An account was logged off",                      "microsoft-windows-security-auditing",  "information"),
    ("2026-05-13 10:02:08", "lt-nsmi-2025033", "4648", "A logon was attempted using explicit credentials", "microsoft-windows-security-auditing", "information"),
    ("2026-05-13 10:08:15", "lt-nsmi-2025033", "4625", "An account failed to log on",                  "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 10:12:00", "dtp-itsmi-062", "4719", "System audit policy was changed",                "microsoft-windows-security-auditing",  "warning"),
    ("2026-05-13 10:15:30", "dtp-itsmi-062", "4624", "An account was successfully logged on",          "microsoft-windows-security-auditing",  "success"),
    ("2026-05-13 10:22:48", "fs-prod-01",    "4663", "An attempt was made to access an object",        "microsoft-windows-security-auditing",  "information"),
    ("2026-05-13 10:30:11", "fs-prod-01",    "5152", "The Windows Filtering Platform blocked a packet", "microsoft-windows-security-auditing", "warning"),
    ("2026-05-13 10:33:55", "fs-prod-01",    "5157", "The Windows Filtering Platform has blocked a connection", "microsoft-windows-security-auditing", "warning"),
    ("2026-05-13 10:40:02", "web-stage-02",  "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 10:40:33", "web-stage-02",  "4625", "An account failed to log on",                    "microsoft-windows-security-auditing",  "failure"),
    ("2026-05-13 10:45:17", "web-stage-02",  "4624", "An account was successfully logged on",          "microsoft-windows-security-auditing",  "success"),
]

wb = Workbook()
ws = wb.active
ws.title = "Events"

ws.append(["All Events"])
ws.append([])
ws.append(["Time", "Log Source", "Event ID", "Display Name", "Source", "Severity"])
for row in EVENTS:
    ws.append(list(row))

wb.save(OUT)
print(f"Wrote {OUT} with {len(EVENTS)} events")
