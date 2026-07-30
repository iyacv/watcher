"""
Batch generator -- one standalone log per file:

  - 5 F5 vulnerability XMLs (ScanDate 2026-05-19 .. 2026-05-23).
    Each file = a SINGLE <Scan> block for one target.

  - 5 Log360 event-list xlsx (report dates 2026-05-12 .. 2026-05-16).
    Each file = Time / Log Source / Event ID / Display Name / Source /
    Severity rows (one event per row), with severities varied per file.

Run once: python samples/_make_batch_samples.py
"""
import random
from pathlib import Path
from openpyxl import Workbook

HERE = Path(__file__).parent
ROOT = HERE.parent

# ---------------------------------------------------------------- F5 XMLs ----
# (host, port, target name, [ (id, name, severity, cvss, desc, remediation), ... ])
F5_SCANS = [
    ("2026-05-19", "192.168.1.30", "443", "Crew Training LMS", [
        ("CVE-2025-0282", "Stack-Based Buffer Overflow in VPN Gateway", "Critical", "9.0",
         "A stack-based buffer overflow in the SSL-VPN component of the crew training gateway allows an unauthenticated remote attacker to achieve code execution by sending an oversized request to the IF-T/TLS handshake. Exploitation grants root-level access to the appliance.",
         "Apply the emergency vendor patch and rotate all VPN gateway credentials. Run the integrity checker tool to confirm the appliance has not been compromised. Restrict management interface access to trusted IPs only."),
        ("CVE-2024-38856", "Apache OFBiz Authentication Bypass", "Critical", "9.8",
         "An authentication bypass in the override view functionality of the LMS backend allows an unauthenticated attacker to reach screens that should require login, including the program export endpoint, leading to remote code execution via a crafted ProgramExport request.",
         "Upgrade Apache OFBiz to 18.12.15 or later. Block access to the /webtools and /accounting paths from external networks. Review web server logs for ProgramExport requests."),
        ("XSS-2026-019", "Stored Cross-Site Scripting in Course Feedback", "Medium", "6.4",
         "The course feedback form stores trainee comments without output encoding. A crafted comment containing a script payload executes in the browser of any instructor who later reviews the feedback, allowing session hijacking of privileged accounts.",
         "HTML-encode all stored user content on output. Apply a strict Content-Security-Policy. Sanitize existing feedback records in the database for embedded markup."),
    ]),
    ("2026-05-20", "192.168.1.40", "8443", "Document Management Portal", [
        ("CVE-2023-34362", "SQL Injection in Managed File Transfer", "Critical", "9.8",
         "The document management portal runs a vulnerable managed file transfer component. An unauthenticated SQL injection in the file transfer web interface allows attackers to deploy a web shell and exfiltrate stored crew certification documents.",
         "Apply the emergency security patch immediately. Inspect the web directories for unauthorized .aspx files. Rotate database service account credentials and review file transfer audit logs."),
        ("CVE-2022-1388", "iControl REST Authentication Bypass", "High", "9.8",
         "The management interface exposes the iControl REST API which can be reached without authentication by manipulating the connection and X-F5-Auth-Token headers, allowing arbitrary command execution on the appliance.",
         "Restrict management access to a dedicated administrative network. Apply the vendor patch. Disable the iControl REST endpoint on self IPs if not required."),
        ("INFO-2026-020", "Verbose Error Messages Disclose Stack Traces", "Low", "3.5",
         "Application errors on the document portal return full stack traces and internal file paths to the client. This discloses framework versions and server-side directory structure that aids an attacker in crafting targeted exploits.",
         "Disable debug mode in production. Return generic error pages to clients and log detailed errors server-side only. Review responses for other sensitive information leakage."),
    ]),
    ("2026-05-21", "192.168.1.50", "443", "Crew Certification API", [
        ("CVE-2024-3400", "Command Injection in GlobalProtect Feature", "Critical", "10.0",
         "A command injection vulnerability in the gateway fronting the certification API allows an unauthenticated attacker to execute arbitrary OS commands with elevated privileges by manipulating the session cookie value during the authentication flow.",
         "Apply the vendor hotfix. Enable Threat Prevention signatures for this CVE. Inspect device telemetry for unexpected file creation under the gateway temp directories."),
        ("CVE-2024-27198", "Authentication Bypass in CI/CD Web Interface", "High", "8.8",
         "The build server fronting the certification API deployment pipeline allows an unauthenticated attacker to forge a valid session by abusing an alternative URL path, gaining full administrative control and the ability to inject malicious build steps.",
         "Upgrade the CI/CD server to the fixed release. Rotate all build agent tokens and admin credentials. Audit recently created administrative accounts and build configurations."),
        ("TLS-2026-021", "Weak TLS Cipher Suites Enabled", "Medium", "5.3",
         "The API endpoint negotiates legacy TLS 1.0 and CBC-mode cipher suites. A man-in-the-middle attacker on the path can downgrade the connection and attempt to recover plaintext from intercepted traffic.",
         "Disable TLS 1.0/1.1 and all CBC and RC4 cipher suites. Require TLS 1.2+ with AEAD ciphers. Enable HSTS with a long max-age."),
    ]),
    ("2026-05-22", "192.168.1.60", "8080", "Trainee Self-Service Portal", [
        ("CVE-2021-44228", "Log4Shell Remote Code Execution", "Critical", "10.0",
         "The self-service portal logs user-controlled input through a vulnerable Log4j 2 version. A crafted User-Agent or form value containing a JNDI lookup string triggers remote class loading and code execution on the application server.",
         "Upgrade Log4j to 2.17.1 or later. Set log4j2.formatMsgNoLookups=true as an interim mitigation. Hunt application logs for jndi: strings and review outbound LDAP/RMI connections."),
        ("CVE-2023-22515", "Broken Access Control in Collaboration Suite", "High", "9.8",
         "A broken access control flaw lets an unauthenticated attacker create administrator accounts on the trainee portal's collaboration module, taking full control of the instance.",
         "Upgrade to the fixed release. Audit the user table for unexpected administrator accounts created recently. Block the setup endpoints from external networks."),
        ("CSRF-2026-022", "Missing Anti-CSRF Tokens on Profile Update", "Medium", "5.4",
         "Profile and password-change forms on the trainee portal do not include anti-CSRF tokens. An attacker can host a malicious page that silently changes a logged-in trainee's email or password.",
         "Implement per-session anti-CSRF tokens on all state-changing requests. Set SameSite=Lax on session cookies. Re-prompt for the current password on sensitive changes."),
    ]),
    ("2026-05-23", "192.168.1.70", "443", "Maritime Records Database Frontend", [
        ("CVE-2023-34362", "SQL Injection in Records Search", "Critical", "9.8",
         "The records database frontend passes the crew search parameter directly into a SQL query. An unauthenticated attacker can extract the entire seafarer records table, including passport and certificate numbers, via UNION-based injection.",
         "Use parameterized queries for all database access. Apply WAF virtual-patching rules for the search endpoint. Review database audit logs for large SELECT operations."),
        ("CVE-2024-21762", "Out-of-Bounds Write in SSL VPN", "High", "9.6",
         "An out-of-bounds write in the SSL-VPN appliance protecting the records database allows a remote unauthenticated attacker to execute arbitrary code via specially crafted requests.",
         "Apply the vendor patch immediately. Disable SSL-VPN if not required until patched. Review VPN logs for crashes and unexpected sessions."),
        ("HDR-2026-023", "Missing Security Response Headers", "Low", "3.1",
         "The records frontend does not set X-Frame-Options, X-Content-Type-Options, or a Content-Security-Policy header, increasing exposure to clickjacking and MIME-sniffing attacks.",
         "Add X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and a restrictive Content-Security-Policy to all responses. Verify via an external header scanner."),
    ]),
]

F5_HEAD = """<?xml version="1.0" encoding="UTF-8"?>
<!-- F5 Web Application Scanner - Vulnerability Report Export -->
<!-- Organization : NYK-FIL Maritime E Training Inc.         -->
<!-- Scan Date    : {date}                               -->
<!-- Report ID    : NYKFIL-{rid}                     -->
<!-- Target       : {tname} -->
<ScanResults>

  <Scan>
    <ScanDate>{date}</ScanDate>
    <Target>
      <Host>{host}</Host>
      <Port>{port}</Port>
    </Target>
    <Vulnerabilities>
"""

F5_VULN = """
      <Vulnerability>
        <ID>{vid}</ID>
        <Name>{name}</Name>
        <Severity>{sev}</Severity>
        <CVSS>{cvss}</CVSS>
        <Description>{desc}</Description>
        <Remediation>{rem}</Remediation>
      </Vulnerability>
"""

F5_TAIL = """
    </Vulnerabilities>
  </Scan>

</ScanResults>
"""

for i, (date, host, port, tname, vulns) in enumerate(F5_SCANS, start=1):
    compact = date.replace("-", "")
    rid = f"{date[:4]}-{compact[4:]}-{i:03d}"
    parts = [F5_HEAD.format(date=date, rid=rid, tname=tname, host=host, port=port)]
    for (vid, name, sev, cvss, desc, rem) in vulns:
        parts.append(F5_VULN.format(vid=vid, name=name, sev=sev, cvss=cvss,
                                    desc=desc, rem=rem))
    parts.append(F5_TAIL)
    out = ROOT / f"vulnerabilities_{compact}.xml"
    out.write_text("".join(parts), encoding="utf-8")
    print(f"Wrote {out.name}  ({tname}, {len(vulns)} vulns)")

# ------------------------------------------------------------- Log360 xlsx ---
# Event templates: (log source, event id, display name, source)
EVENT_TEMPLATES = [
    ("ad1nsmi2022",   "4625", "An account failed to log on",                          "microsoft-windows-security-auditing"),
    ("ad2nsmi2022",   "4625", "An account failed to log on",                          "microsoft-windows-security-auditing"),
    ("ad1nsmi2022",   "4740", "A user account was locked out",                        "microsoft-windows-security-auditing"),
    ("ltop-nttc-226", "4624", "An account was successfully logged on",                "microsoft-windows-security-auditing"),
    ("ltop-nttc-226", "4672", "Special privileges assigned to new logon",             "microsoft-windows-security-auditing"),
    ("ltop-nttc-226", "4688", "A new process has been created",                       "microsoft-windows-security-auditing"),
    ("dtp-itsmi-067", "1102", "The audit log was cleared",                            "microsoft-windows-eventlog"),
    ("dtp-itsmi-067", "4720", "A user account was created",                           "microsoft-windows-security-auditing"),
    ("dtp-itsmi-067", "4732", "A member was added to a security-enabled local group", "microsoft-windows-security-auditing"),
    ("lt-nsmi-2025004", "10028", "DCOM was unable to communicate with the computer",  "microsoft-windows-distributedcom"),
    ("lt-nsmi-2025004", "10016", "Local Activation permission not granted",           "microsoft-windows-distributedcom"),
    ("dtp-itsmi-063", "7045", "A service was installed in the system",                "microsoft-windows-service-control-manager"),
    ("dtp-itsmi-063", "7036", "The service entered the running state",                "microsoft-windows-service-control-manager"),
    ("lt-nsmi-2025033", "4648", "A logon was attempted using explicit credentials",   "microsoft-windows-security-auditing"),
    ("dtp-itsmi-062", "4719", "System audit policy was changed",                      "microsoft-windows-security-auditing"),
    ("fs-prod-01",    "4663", "An attempt was made to access an object",              "microsoft-windows-security-auditing"),
    ("fs-prod-01",    "5152", "The Windows Filtering Platform blocked a packet",      "microsoft-windows-security-auditing"),
    ("fs-prod-01",    "5157", "The Windows Filtering Platform blocked a connection",  "microsoft-windows-security-auditing"),
    ("web-stage-02",  "4634", "An account was logged off",                            "microsoft-windows-security-auditing"),
    ("web-stage-02",  "4624", "An account was successfully logged on",                "microsoft-windows-security-auditing"),
]

SEVERITIES = ["error", "warning", "information", "success", "failure"]

XLSX_DATES = [
    "2026-05-12", "2026-05-13", "2026-05-14", "2026-05-15", "2026-05-16",
]

for idx, date in enumerate(XLSX_DATES):
    rng = random.Random(20260512 + idx)  # deterministic, but different per file
    n_events = rng.randint(28, 42)

    wb = Workbook()
    ws = wb.active
    ws.title = "Events"
    ws.append(["All Events"])
    ws.append([])
    ws.append(["Time", "Log Source", "Event ID", "Display Name", "Source", "Severity"])

    # build a time-sorted set of events for the day
    minutes = sorted(rng.sample(range(9 * 60, 17 * 60), n_events))
    for m in minutes:
        src, eid, dname, source = rng.choice(EVENT_TEMPLATES)
        sev = rng.choice(SEVERITIES)
        ts = f"{date} {m // 60:02d}:{m % 60:02d}:{rng.randint(0, 59):02d}"
        ws.append([ts, src, eid, dname, source, sev])

    out = ROOT / f"DirectReportsAll_Events_{date}_00-08-14.xlsx"
    wb.save(out)
    print(f"Wrote {out.name}  ({n_events} events)")

print("Done.")
