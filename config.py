import os
from dotenv import load_dotenv

load_dotenv()

# ── Folder paths ──────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
INBOX_DIR     = os.path.join(BASE_DIR, "inbox")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")
FAILED_DIR    = os.path.join(BASE_DIR, "failed")

# ── MySQL ─────────────────────────────────────────────────────────────────────
DB_HOST     = os.getenv("DB_HOST", "localhost")
DB_PORT     = int(os.getenv("DB_PORT", 3306))
DB_NAME     = os.getenv("DB_NAME", "capstone_security")
DB_USER     = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

# ── Correlation window ────────────────────────────────────────────────────────
CORRELATION_WINDOW_MINUTES = 60

# ── Aging threshold ───────────────────────────────────────────────────────────
AGING_THRESHOLD_DAYS = 7

# ── Severity order (highest first) ───────────────────────────────────────────
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
