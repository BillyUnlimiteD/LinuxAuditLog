"""
Global configuration constants.
Numeric/path overrides can be set in .env (loaded by acquire.py before this module is imported).
No credentials are stored here.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Output directories — override via JOBS_DIR / RULES_DIR env vars
JOBS_DIR      = Path(os.environ.get("JOBS_DIR",      str(BASE_DIR / "jobs")))
RULES_DIR     = Path(os.environ.get("RULES_DIR",     str(BASE_DIR / "rules")))
TEMPLATES_DIR = Path(os.environ.get("TEMPLATES_DIR", str(BASE_DIR / "templates")))

# Acquisition defaults — override via env vars
DEFAULT_TIME_WINDOW_HOURS  = int(os.environ.get("TIME_WINDOW_HOURS",  "72"))
MAX_LOG_LINES_PER_SOURCE   = int(os.environ.get("LOG_MAX_LINES",      "50000"))
SSH_CONNECT_TIMEOUT        = int(os.environ.get("SSH_CONNECT_TIMEOUT","30"))
SSH_COMMAND_TIMEOUT        = int(os.environ.get("SSH_COMMAND_TIMEOUT","60"))
SSH_LARGE_COMMAND_TIMEOUT  = int(os.environ.get("SSH_LARGE_TIMEOUT",  "120"))

# Maximum number of *.log files downloaded by the broad sweep.
# Override via MAX_LOG_FILES env var.  0 = unlimited.
MAX_LOG_FILES_SWEEP        = int(os.environ.get("MAX_LOG_FILES",      "0"))

# Compression
COMPRESS_LOGS = True

# Analysis thresholds (used by ioc_engine, overridden by individual rules)
DEFAULT_BRUTE_FORCE_THRESHOLD = 10
DEFAULT_BRUTE_FORCE_WINDOW_SEC = 300

# Report
TOOL_VERSION = "1.0.0"
TOOL_NAME = "LinuxAuditLog"
REPORT_CLASSIFICATION = "CONFIDENCIAL — USO RESTRINGIDO"

# Language — ES (español) or EN (English).  Override via LANGUAGE env var or .env.
LANGUAGE = os.environ.get("LANGUAGE", "ES").upper()
if LANGUAGE not in ("ES", "EN"):
    LANGUAGE = "ES"

# Log source priorities (order matters for deduplication)
PREFERRED_LOG_SOURCES = ["journalctl_json", "journalctl_export", "file_log"]

# SFTP file size limit for direct download (bytes). Above this, use streaming.
SFTP_SIZE_LIMIT = 50 * 1024 * 1024  # 50 MB

# SigmaHQ repository reference for update_rules.py
SIGMA_GITHUB_REPO = "SigmaHQ/sigma"
SIGMA_LINUX_PATHS = [
    "rules/linux/auditd",
    "rules/linux/builtin",
    "rules/linux/network",
    "rules/linux/process_creation",
    "rules/linux/other",
]
SIGMA_WEB_PATHS = [
    "rules/web",
]

JOBS_DIR.mkdir(exist_ok=True)
