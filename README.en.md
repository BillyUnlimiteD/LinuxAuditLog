# LinuxAuditLog v1.6.1

**Remote forensic acquisition and Linux security analysis agent**

Remote forensic acquisition tool over SSH with local deterministic analysis, forensic report generation (Spanish or English), automatic PDF export, and AI-ready prompts for each finding. No credentials on disk. No cloud service dependencies.

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Two-Stage Architecture](#4-two-stage-architecture)
5. [Output Structure](#5-output-structure)
6. [Automatic PDF Generation](#6-automatic-pdf-generation)
7. [AI Prompts Report](#7-ai-prompts-report)
8. [Updating the Rules Dictionary](#8-updating-the-rules-dictionary)
9. [YAML Rule Format](#9-yaml-rule-format)
10. [Adding Custom Rules](#10-adding-custom-rules)
11. [IOC Engine — Performance](#11-ioc-engine--performance)
12. [Security Considerations](#12-security-considerations)
13. [Environment Variable Reference](#13-environment-variable-reference)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Requirements

| Component | Minimum version | Required | Notes |
|---|---|---|---|
| Python | 3.11 | Yes | Required for everything |
| pandoc | 2.x | No | Better PDF quality |
| TeX Live / MiKTeX | any | No | PDF with pandoc + XeLaTeX |
| wkhtmltopdf | 0.12.x | No | Alternative to XeLaTeX |

> Python dependencies (including `xhtml2pdf` for PDF without pandoc) are installed automatically by `setup_env.py`.

> **Remote access:** the SSH user must be able to run `journalctl`, `systemctl`, `ss`/`netstat` and `ps`, and read `/var/log/`. Root is not required (see `SSH_ROOT_PASS` for elevated access).

---

## 2. Installation

No prior installation required. The `run` scripts handle everything on first execution: they download `uv`, install Python 3.11 locally in `.tools/`, create the virtual environment and install dependencies. On subsequent runs they use the paths saved in `.env` without internet access.

**Automatically installed packages:**
`asyncssh`, `duckdb`, `jinja2`, `pyyaml`, `requests`, `markdown`, `xhtml2pdf`

---

## 3. Quick Start

### Step 1 — Configure credentials

Create the `.env` file in the project root with the target host details:

```bash
cp .env.example .env      # Linux / macOS
copy .env.example .env    # Windows
```

Edit `.env` with the real credentials:

```ini
SSH_HOST=192.168.1.100
SSH_USER=admin
SSH_PASS=your_password
SSH_PORT=22
LANGUAGE=EN   # EN = English report, ES = Spanish report
# Optional: root password to access protected logs (see section 12)
# SSH_ROOT_PASS=root_password
```

> `.env` is in `.gitignore` and **never uploaded to the repository**. Credentials are loaded into memory at startup and destroyed when the SSH connection closes.

### Step 2 — Run

Launch the script for your platform. On first execution it installs everything automatically:

```powershell
# Windows PowerShell (recommended on Windows)
.\run.ps1
```

```cmd
REM Windows CMD
run.bat
```

```bash
# Linux / macOS / WSL
bash run.sh
```

> If PowerShell blocks script execution: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

When complete, the working directory is at `jobs/<YYYYMMDD_HHMMSS_host>/`. The Markdown report **and its PDF** are generated automatically — no additional steps required.

> System environment variables take **priority** over `.env`. If a variable is already defined in the environment, the `.env` value is ignored.

### Report language

Set `LANGUAGE=ES` for a Spanish report or `LANGUAGE=EN` for an English report in your `.env`. Defaults to `ES` if not set.

---

## 4. Two-Stage Architecture

```
┌─────────────────────────────────────────────────────────┐
│  STAGE A — REMOTE ACQUISITION (SSH)                     │
│                                                         │
│  1. Ephemeral SSH connection (asyncssh)                 │
│  2. OS, kernel and init system detection                │
│     (systemd / OpenRC / runit / s6 / SysV)              │
│  3. Active services and ports inventory                 │
│  4. Log export (journalctl + files)                     │
│     - Persistent root channel: su root on connect       │
│       (SSH_ROOT_PASS), all commands run as root         │
│     - Recursive sweep: /var/log /var/opt /opt           │
│       /srv /var/www — no file limit                     │
│     - Rotated log collection (secure-YYYYMMDD.gz,       │
│       auth.log.2.gz, etc.) for extended coverage        │
│     - Conversion to structured JSONL at source          │
│     - Fallback: sudo -n → unprivileged                  │
│     - Limit: 50,000 lines per source                    │
│  5. SHA-256 hash of all artifacts (MANIFEST)            │
│  6. Explicit SSH connection close                       │
│  7. Credential destruction from memory                  │
└─────────────────────────────────────────────────────────┘
                          │  (no network from here)
                          ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE B — LOCAL ANALYSIS (no connection)               │
│                                                         │
│  1. Log normalization → unified JSONL                   │
│     - Stage A JSONL parser (structured format)          │
│     - Linux audit log parser (type=SYSCALL, AVC...)     │
│     - JSONL cache on re-runs without changes            │
│  2. Rule Advisor: rule coverage by service              │
│     (creates stubs for unknown services)                │
│  3. Unified timeline → time-sorted CSV                  │
│  4. IOC Engine: evaluates 48 YAML rules (pattern/       │
│     threshold/sequence) with MITRE ATT&CK mapping       │
│     (case-insensitive service index: ~83x speedup)      │
│  5. Correlation by IP, user and service (DuckDB)        │
│  6. Forensic report generation in Markdown              │
│  7. Automatic PDF generation of the report              │
│  8. AI prompts report generation (.md + .pdf)           │
│     (one prompt per finding, ready to copy/paste)       │
└─────────────────────────────────────────────────────────┘
```

**Minimum impact principle:** Stage A only runs read-only commands. It does not write files to the remote host, does not install agents, and does not modify any configuration.

---

## 5. Output Structure

Each run generates an independent working directory:

```
jobs/
└── 20240115_143022_192-168-1-100/
    ├── 01_evidence/
    │   ├── raw/
    │   │   ├── logs/
    │   │   │   ├── journalctl_system.gz
    │   │   │   ├── auth.log.gz
    │   │   │   ├── nginx_access.gz
    │   │   │   └── ...
    │   │   ├── system_info.json
    │   │   ├── services_inventory.json
    │   │   ├── ports_inventory.json
    │   │   └── acquisition_log.json
    │   ├── MANIFEST.json          <- SHA-256 hashes of all artifacts
    │   └── MANIFEST.sig.json      <- manifest signature
    │
    ├── 02_analysis/
    │   ├── all_entries.jsonl      <- unified log entries (cache)
    │   ├── timeline.csv           <- chronologically sorted events
    │   ├── correlations.json      <- IP/user/service correlations
    │   └── rule_coverage.json     <- rule coverage by service
    │
    └── 03_report/
        ├── report_20240115_143022_192-168-1-100.md        <- forensic report
        ├── report_20240115_143022_192-168-1-100.pdf       <- PDF report
        ├── ai_prompts_20240115_143022_192-168-1-100.md    <- AI prompts
        ├── ai_prompts_20240115_143022_192-168-1-100.pdf   <- AI prompts PDF
        ├── convert_to_pdf.sh      <- Linux/macOS conversion (manual)
        ├── convert_to_pdf.bat     <- Windows conversion (manual)
        └── convert_to_pdf.py      <- Python conversion (manual)
```

### Key file descriptions

| File | Description |
|---|---|
| `MANIFEST.json` | Artifact list with SHA-256 hash, size and relative path |
| `acquisition_log.json` | Acquisition log: commands executed, errors, timestamps |
| `all_entries.jsonl` | All normalized log entries in JSONL format (cache) |
| `timeline.csv` | Unified timeline: timestamp, hostname, service, src_ip, user, message |
| `correlations.json` | Statistical summary: most active IPs, users, errors per service |
| `rule_coverage.json` | Which rules were applied to which detected services |
| `report_<job_id>.md` | Complete forensic report in Markdown |
| `report_<job_id>.pdf` | Report PDF, generated automatically at end of analysis |
| `ai_prompts_<job_id>.md` | AI-ready prompts, one per finding (Markdown) |
| `ai_prompts_<job_id>.pdf` | AI prompts report PDF |

---

## 6. Automatic PDF Generation

The forensic report PDF is generated **automatically** at the end of Stage B. No additional scripts need to be run.

### PDF conversion engine

The system tries available engines in this order of preference:

1. `pandoc + XeLaTeX` — highest typographic quality, full Unicode support
2. `pandoc + wkhtmltopdf` — good quality, no TeX dependencies
3. `pandoc (html)` — basic HTML output via pandoc
4. **`xhtml2pdf`** — **default engine**, pure Python, no system dependencies

`xhtml2pdf` is included in `requirements.txt` and always available. On most installations it will be the active engine.

### Regenerate PDF manually

If you need to regenerate the PDF from an existing report, from the job's `03_report/` directory:

```powershell
# Windows PowerShell / CMD
convert_to_pdf.bat
```

```bash
# Linux / macOS / WSL
bash convert_to_pdf.sh
```

### README / manual PDF

To generate a PDF of this documentation (requires venv created):

```powershell
# Windows PowerShell
.venv\Scripts\python.exe scripts/readme_to_pdf.py
```

```bash
# Linux / macOS / WSL
.venv/bin/python scripts/readme_to_pdf.py
```

### Install pandoc (better typographic quality)

```bash
# Ubuntu / Debian
sudo apt install pandoc texlive-xetex texlive-lang-english

# macOS
brew install pandoc && brew install --cask mactex

# Windows — download installers:
# pandoc:  https://pandoc.org/installing.html
# MiKTeX:  https://miktex.org/download
```

> Without pandoc, `xhtml2pdf` generates the PDF directly from Python without additional dependencies.

---

## 7. AI Prompts Report

At the end of each analysis, the system automatically generates a second report (`ai_prompts_<job_id>.md` and its PDF) with a structured prompt for each detected security finding. The prompt is designed to be copied and pasted directly into any AI (Claude, ChatGPT, Gemini, etc.) for immediate expert assistance.

### Content of each prompt

Each prompt includes five context blocks followed by a structured assistance request:

| Block | Description |
|---|---|
| **System context** | OS, hostname, kernel, architecture, init system, analyzed host |
| **Security alert** | Rule ID, title, severity, confidence, MITRE technique, dates |
| **Alert description** | Full description of what the rule detects |
| **Affected entities** | Users, IPs and services involved with event counts |
| **Detected events** | Up to 5 real log lines from the system with extracted fields |
| **Initial recommendation** | What the rule suggests as a first remediation step |
| **Possible false positives** | Context so the AI does not over-react |

### Assistance request included in each prompt

The prompts ask the AI to answer five concrete questions:

1. **Evaluation** — Is this a real indicator of compromise or a false positive?
2. **Forensic investigation** — Concrete commands to confirm or rule out the finding
3. **Impact** — Most likely attack scenario if the finding is real
4. **Immediate remediation** — Actions prioritized by urgency
5. **Prevention** — Configurations or controls to prevent recurrence

### Usage

The PDF file is generated in `03_report/` alongside the forensic report. Open it, find the finding of interest, copy the prompt text block and paste it directly into the AI:

```
03_report/
├── report_<job_id>.pdf          <- forensic report
└── ai_prompts_<job_id>.pdf      <- AI prompts (this file)
```

---

## 8. Updating the Rules Dictionary

The project includes a script to download rules from the **SigmaHQ** community and convert them to the local format. Requires the venv to be created (created the first time you run `run.ps1` / `run.sh` / `run.bat`):

```powershell
# Windows PowerShell
.venv\Scripts\python.exe scripts/update_rules.py --dry-run   # preview without changes
.venv\Scripts\python.exe scripts/update_rules.py              # update
.venv\Scripts\python.exe scripts/update_rules.py --force      # overwrite existing
.venv\Scripts\python.exe scripts/update_rules.py --token ghp_xxxxxxxxxxxx
```

```bash
# Linux / macOS / WSL
.venv/bin/python scripts/update_rules.py --dry-run
.venv/bin/python scripts/update_rules.py
.venv/bin/python scripts/update_rules.py --force
.venv/bin/python scripts/update_rules.py --token ghp_xxxxxxxxxxxx
```

Rules are saved in the `rules/` directory with the same category structure.

---

## 9. YAML Rule Format

All rules reside in `rules/` and follow this schema:

```yaml
id: LIN-AUTH-001                    # Unique identifier
title: SSH Brute Force Detection    # Descriptive title
category: auth                      # Main category
subcategory: brute_force            # Subcategory
mitre_technique: T1110.001          # MITRE ATT&CK technique
mitre_tactic: credential_access     # MITRE ATT&CK tactic
severity: high                      # critical / high / medium / low
confidence: high                    # high / medium / low
enabled: true                       # true = active, false = disabled

description: >
  Detailed description of what this rule detects.

service: sshd                       # Service this applies to (* = all)

detection:
  type: pattern                     # See types below

false_positives:
  - Legitimate administration

recommendation: >
  Recommended remediation steps.

references:
  - "https://attack.mitre.org/techniques/T1110/"

tags:
  - ssh
  - brute_force
```

### Detection types

#### `pattern` — Regex matching

```yaml
detection:
  type: pattern
  patterns:
    - regex: "Failed password for (?P<user>\\S+) from (?P<src_ip>[\\d.]+)"
    - regex: "Invalid user (?P<user>\\S+) from (?P<src_ip>[\\d.]+)"
```

Each pattern can use named groups (`?P<name>`) that are extracted as affected entities.

#### `threshold` — Frequency threshold

```yaml
detection:
  type: threshold
  patterns:
    - regex: "Failed password for (?P<user>\\S+) from (?P<src_ip>[\\d.]+)"
  aggregation:
    field: src_ip        # Group by this extracted field
    count: 10            # Number of occurrences to trigger
    window_sec: 300      # Time window in seconds
```

Triggers when the `field` exceeds `count` matches within `window_sec` seconds.

#### `sequence` — Ordered event pair

```yaml
detection:
  type: sequence
  patterns:
    - regex: "Failed password.*from (?P<src_ip>[\\d.]+)"   # Event 1
    - regex: "Accepted.*from (?P<src_ip>[\\d.]+)"           # Event 2
  aggregation:
    window_sec: 3600    # Event 2 must occur within this window
```

Triggers when event 2 occurs after event 1 within the time window.

### Rules directory (48 rules included)

```
rules/
├── linux/
│   ├── auth/       ssh_brute_force, sudo_abuse, privilege_escalation,
│   │               account_manipulation, failed_logins_spike,
│   │               ssh_success_from_new_ip, sudo_password_bruteforce,
│   │               credentials_in_cmdline, sudoers_enumeration
│   ├── process/    suspicious_execution, cron_abuse, reverse_shell,
│   │               docker_abuse, docker_defense_evasion,
│   │               git_abuse, git_data_exposure
│   └── network/    port_scanning, suspicious_connections,
│                   firewall_removal, cifs_remote_mount
├── web/            sqli, path_traversal, lfi_rfi, rce, ssrf,
│                   web_scanning, xss, web_git_repository_theft,
│                   web_config_file_disclosure, web_backup_file_enumeration,
│                   web_vcs_metadata_exposure, web_etc_file_access
└── services/       nginx, apache2, httpd, mysql, samba, tuned,
                    php-fpm, zabbix, rsyslog, chronyd, dbus,
                    networkmanager, polkit, sendmail, irqbalance,
                    timedatex, getty@tty1, user@1001,
                    clamav, yum, memcached
                    (+ auto-generated stubs for unknown services)
```

### New rules (v1.1.0)

| ID | Title | MITRE | Severity |
|---|---|---|---|
| LIN-AUTH-007 | Sudo Password Brute-Force | T1110.001 | critical |
| LIN-AUTH-008 | Plaintext Credentials in Command-Line | T1552.003 | high |
| LIN-AUTH-009 | Sudoers File Enumeration | T1069.001 | high |
| LIN-NET-003 | Firewall Software Removal or Replacement | T1562.004 | critical |
| LIN-NET-004 | CIFS/SMB Remote Mount (Interactive) | T1021.002 | medium |
| LIN-PROC-004 | Docker Container Escape / Privileged Abuse | T1611 | critical |
| LIN-PROC-005 | Docker Defense Evasion | T1610 | high |
| LIN-PROC-006 | Git Hook / Credential Helper Abuse | T1195.001 | high |
| LIN-PROC-007 | Git Data Exposure | T1213 | medium |

### New rules (v1.3.0)

| ID | Title | MITRE | Severity |
|---|---|---|---|
| SVC-CLAMAV-001 | ClamAV Malware Detection / Antivirus Evasion | T1562.001 | high |
| SVC-YUM-001 | Package Manager Abuse (yum/dnf) | T1072 | high |
| SVC-MEMCACHED-001 | Memcached Unauthorized Access / Exposure | T1046 | high |

### New rules (v1.4.0)

| ID | Title | MITRE | Severity |
|---|---|---|---|
| WEB-GIT-001 | Git Repository Theft via Web | T1213 | high |
| WEB-CONFIG-001 | Configuration File Disclosure via Web | T1552.001 | high |
| WEB-BACKUP-001 | Backup File Enumeration via Web | T1083 | medium |
| WEB-VCS-001 | VCS Metadata Exposure (SVN/HG/BZR/CVS) | T1213 | high |
| WEB-ETC-001 | /etc/ File Access via Web (LFI/Path Traversal) | T1083 | critical |

### Engine and pipeline improvements (v1.4.0)

| Component | Improvement |
|---|---|
| Stage A — Collection | Rotated logs from logrotate (CentOS: `secure-YYYYMMDD.gz`, Debian: `auth.log.2.gz`) collected automatically for up to 60-day coverage |
| Stage A — Conversion | All plain text files converted to structured JSONL during acquisition (timestamp, service, pid, message) |
| Stage B — Normalizer | Dedicated parser for Stage A JSONL format; Linux audit log parser (`type=SYSCALL`, `USER_LOGIN`, `AVC`, etc.) with service mapping |
| Stage B — IOC engine | Service filter now case-insensitive (fixed false negatives with `NetworkManager`, `CROND`) |
| Reporting — PDF | Fixed tables: artifact names without `var_log_` prefix, timestamps in `YYYY-MM-DD HH:MM` format instead of full ISO |

### New rules (v1.5.0)

| ID | Title | MITRE | Severity |
|---|---|---|---|
| WEB-GIT-001 | Git Repository Theft via Web | T1213 | high |
| WEB-CONFIG-001 | Configuration File Disclosure via Web | T1552.001 | high |
| WEB-BACKUP-001 | Backup File Enumeration via Web | T1083 | medium |
| WEB-VCS-001 | VCS Metadata Exposure (SVN/HG/BZR/CVS) | T1213 | high |
| WEB-ETC-001 | /etc/ File Access via Web (LFI/Path Traversal) | T1083 | critical |

### Platform updates (v1.5.0)

| Component | Improvement |
|---|---|
| Multi-language | Reports in Spanish (`LANGUAGE=ES`) or English (`LANGUAGE=EN`) selectable from `.env` |
| Templates | Separate templates per language: `report.es.md.j2`, `report.en.md.j2`, `prompts.es.md.j2`, `prompts.en.md.j2` |
| Documentation | `README.en.md` added — full English documentation |
| Web rules | 5 new rules for web attack detection: .git repository theft, config file disclosure, backup enumeration, VCS metadata exposure, /etc/ access via LFI |
| Config | `LANGUAGE` variable added to `config.py` and `.env.example` |

### New rules (v1.6.0) — OWASP, Linux and services

**Web (9 rules):**

| ID | Title | MITRE | Severity |
|---|---|---|---|
| WEB-008 | XXE Injection Attempt | T1190 | high |
| WEB-009 | Insecure Deserialization Attack Attempt | T1190 | critical |
| WEB-010 | Log4Shell / Log4j RCE (CVE-2021-44228) | T1190 | critical |
| WEB-011 | Shellshock CGI Attack (CVE-2014-6271) | T1190 | critical |
| WEB-012 | Open Redirect / Unvalidated URL Redirect | T1204 | medium |
| WEB-013 | HTTP Header Injection / CRLF Injection | T1190 | high |
| WEB-014 | WordPress Attack Patterns (xmlrpc, wp-login) | T1110.001 | high |
| WEB-015 | Directory Listing Exposure / Sensitive File Discovery | T1083 | medium |
| WEB-016 | Dangerous HTTP Method Abuse (TRACE/PUT/WebDAV) | T1190 | medium |

**Linux (6 rules):**

| ID | Title | MITRE | Severity |
|---|---|---|---|
| LIN-AUTH-010 | SSH Authorized Keys Tampering | T1098.004 | high |
| LIN-PROC-008 | Log Tampering / Audit Log Clearing | T1070.002 | critical |
| LIN-PROC-009 | Crypto Mining Activity | T1496 | high |
| LIN-PROC-010 | Kernel Module Loading / Rootkit Indicators | T1547.006 | critical |
| LIN-NET-005 | DNS Tunneling / Data Exfiltration via DNS | T1048.003 | high |
| LIN-NET-006 | Email Relay Abuse / SMTP Spam Sending | T1071.003 | high |

**Services (5 rules):**

| ID | Title | MITRE | Severity |
|---|---|---|---|
| SVC-REDIS-001 | Redis Unauthorized Access / RCE via CONFIG SET | T1190 | critical |
| SVC-POSTGRES-001 | PostgreSQL Auth Failures / COPY PROGRAM RCE | T1190 | high |
| SVC-TOMCAT-001 | Apache Tomcat Manager Brute Force / WAR RCE | T1190 | critical |
| SVC-POSTFIX-001 | Postfix Mail Relay Abuse / SMTP Brute Force | T1071.003 | high |
| SVC-FTP-001 | FTP Brute Force / Anonymous Login Abuse | T1110.001 | high |

### Engine and rule fixes (v1.6.1)

| Component | Fix |
|---|---|
| Stage B — Normalizer | **Critical bug:** Apache and Nginx logs converted to JSONL by Stage A (`.jsonl.gz` files) were silently dropped. The dispatcher detected `"access"` or `"error"` in the filename and called the wrong parser, causing all lines to fail. Stage A JSONL content detection now takes priority over filename-based checks. |
| Stage B — Normalizer | **Service bug:** Stage A assigned `service: "unknown"` to log formats it didn't recognise (Apache combined access log, Nginx error log). Rules with `service: apache2` or `service: nginx` were never evaluated. New `_infer_service_from_path` function deduces the correct service from the file path. |
| `rules/services/nginx.yaml` | **Regex bug:** The 5xx large-body pattern captured `src_ip=1.1` (from the `HTTP/1.1` version field) instead of the real client IP. Fixed by explicitly consuming the quoted request field. |
| `rules/services/nginx.yaml` | **Regex bug:** The scanner User-Agent pattern never matched any log line. It was missing explicit traversal of the referer field (present between the status code and the UA in combined log format). Rewritten using the same structure as `apache2.yaml`. |
| `README.en.md` | `LANGUAGE` variable documented in quick start, report language, and environment variable reference sections. |

> **Note:** For existing jobs, delete `02_analysis/all_entries.jsonl` to force a full re-parse with the fixes applied.

### OWASP Top 10 (2021) Coverage — v1.6.0

| # | Category | Key rules | Status |
|---|---|---|---|
| A01 | Broken Access Control | path_traversal, lfi_rfi, web_etc_file_access, open_redirect | ✅ Covered |
| A02 | Cryptographic Failures | redis (cleartext), postfix (plaintext SMTP), vsftpd (FTP) | Partial |
| A03 | Injection | sqli, xss, rce, lfi_rfi, xxe_injection, http_header_injection | ✅ Covered |
| A04 | Insecure Design | Not detectable in access logs | N/A |
| A05 | Security Misconfiguration | web_scanning, git_exposure, directory_listing, http_method_abuse | ✅ Covered |
| A06 | Vulnerable Components | log4shell, shellshock, yum | ✅ Covered |
| A07 | Auth Failures | ssh_brute_force, failed_logins, wordpress_attacks, ftp_bruteforce | ✅ Covered |
| A08 | Software Integrity / Deserialization | insecure_deserialization | ✅ Covered |
| A09 | Logging Failures | log_tampering | ✅ Covered |
| A10 | SSRF | ssrf | ✅ Covered |

---

## 10. Adding Custom Rules

### Option A — Create manually

1. Create a YAML file in the corresponding subdirectory of `rules/`.
2. Follow the format described in the previous section.
3. Set `enabled: true`.
4. Run `run.ps1` / `run.sh` / `run.bat` — the new rule will be loaded automatically.

### Option B — Complete an auto-generated stub

When a service without rules is detected, the system automatically creates a disabled stub at `rules/services/<service>.yaml`. To activate it:

1. Open the stub file.
2. Replace `PLACEHOLDER_PATTERN` with a valid regex for the service's logs.
3. Change `enabled: false` to `enabled: true`.
4. Adjust `severity`, `confidence` and `recommendation`.

### Option C — Download from SigmaHQ

See section [8. Updating the Rules Dictionary](#8-updating-the-rules-dictionary).

---

## 11. IOC Engine — Performance

The Stage B IOC engine evaluates each rule against the complete set of normalized log entries. In v1.1.0 two optimizations were added that reduced analysis time from ~180 seconds to ~2 seconds (**~83x speedup**) on a corpus of 109,000 entries.

### Optimization 1 — Service index

Log entries are pre-grouped by `service` field in a `defaultdict(list)`. Rules with `service: <name>` only iterate entries for that service instead of 100K+ total. Rules with `service: "*"` still evaluate the full set.

### Optimization 2 — Anchor pre-filter

Before invoking the (expensive) regex engine, the system extracts the longest literal substring from each regex pattern. This "anchor" is checked with `str.__contains__` (C-speed) on the lowercased message:

- If the anchor is **absent** → entry is discarded without running any regex.
- If the anchor is **present** → the full regex is evaluated.

In practice the pre-filter discards ~99% of entries before the regex engine touches them, eliminating backtracking overhead on complex patterns.

### Normalizer JSONL cache

On re-runs (Stage B with no log changes), the normalizer detects that `all_entries.jsonl` is newer than all log files in `logs_dir` and loads the cached JSONL directly, without decompressing or re-parsing the original `.gz` files.

### Timing reference

| Stage | v1.0.0 (109K entries) | v1.1.0 (109K entries) | v1.4.0+ (375K entries) |
|---|---|---|---|
| Normalization (first time) | ~0.8 s | ~0.8 s | ~3 s |
| Normalization (cache hit) | ~0.8 s | ~0.7 s | ~0.5 s |
| IOC Engine | ~180 s | ~2.2 s | ~7 s |
| Total (first analysis) | ~181 s | ~3 s | ~10 s |
| Total (re-analysis with cache) | ~181 s | ~2.9 s | ~7.5 s |

> v1.4.0+ data corresponds to a real 60-day acquisition (1440h) on CentOS 7 with 54 artifacts and 375,928 normalized entries.

---

## 12. Security Considerations

### Credentials

- SSH credentials are read from the `.env` file or from system environment variables.
- System environment variables take **priority** over `.env`.
- Stored in memory in an `EphemeralSession` object.
- Destroyed (overwritten with zeros) immediately upon SSH connection close, even if an error occurs.
- **Never** written to logs or the generated report.
- The `.env` file is in `.gitignore` and must never be uploaded to the repository.

### Persistent root channel (SSH_ROOT_PASS)

Some log files (like `/var/log/audit/audit.log`) are only readable by `root`. If the SSH user lacks sufficient permissions and direct root SSH login is disabled on the server, define `SSH_ROOT_PASS` in `.env`:

```ini
SSH_ROOT_PASS=root_password
```

When this variable is defined, Stage A opens **one persistent PTY channel** at the start of the SSH connection and runs `su root` once. All acquisition commands (services inventory, ports, processes and log download) are routed through that channel and run as `root` for the entire session. At the end of the stage, the channel is cleanly closed. The escalation does **not** require modifying `sshd_config` or enabling `PermitRootLogin`. The root password is destroyed along with the other credentials when the session closes.

> **Security:** `SSH_ROOT_PASS` is only used in the active session and is never logged or included in the report. If root log access is not needed, omit this variable.

### Fallback: sudo -n and unprivileged execution

If `SSH_ROOT_PASS` is not defined, commands are first attempted with `sudo -n` (non-interactive mode, requires a `NOPASSWD` entry in sudoers). If that fails, it retries without privileges. With the root channel active this fallback is not used.

### Extended log sweep

Stage A runs `find` over five directories to discover non-standard log files:

```
/var/log   /var/opt   /opt   /srv   /var/www
```

Only non-empty `*.log` files (`-size +0c`) are included. To prevent path injection, each returned path is validated against a safe pattern before being used in a read command. The maximum number of files is configurable via `MAX_LOG_FILES` (default: unlimited).

### SSH connection

- By default, `asyncssh` verifies the host key against `~/.ssh/known_hosts`.
- If the host is not in `known_hosts`, the connection will fail with `HostKeyNotVerifiable`.
- To register the host before the first connection:

```bash
ssh-keyscan -H 192.168.1.100 >> ~/.ssh/known_hosts
```

> **Warning:** Do not disable host key verification in production environments. It is vulnerable to MITM attacks.

### Evidence integrity

- All collected artifacts are hashed with **SHA-256** before closing the connection.
- `MANIFEST.json` + `MANIFEST.sig.json` allow verifying that artifacts have not been modified.

### Minimal impact on remote host

- Only **read** commands are executed on the remote host.
- No agents installed, no configurations modified, no files written.
- 50,000 line limit per log source to avoid overload.

---

## 13. Environment Variable Reference

Variables can be defined in the `.env` file or as system environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SSH_HOST` | Yes | — | IP or hostname of the host to analyze |
| `SSH_USER` | Yes | — | SSH username |
| `SSH_PASS` | Yes | — | SSH password |
| `SSH_PORT` | No | `22` | SSH port |
| `SSH_ROOT_PASS` | No | — | Root password for persistent root channel (all commands run as root) |
| `LANGUAGE` | No | `ES` | Report language: `ES` (Spanish) or `EN` (English) |
| `TIME_WINDOW_HOURS` | No | `72` | Log time window to export (hours). E.g.: 1440 = 60 days |
| `LOG_MAX_LINES` | No | `50000` | Maximum lines per log source |
| `MAX_LOG_FILES` | No | `0` | Maximum `*.log` files in sweep (0 = unlimited) |
| `SSH_CONNECT_TIMEOUT` | No | `30` | SSH connection timeout (seconds) |
| `SSH_COMMAND_TIMEOUT` | No | `60` | Normal SSH command timeout (seconds) |
| `SSH_LARGE_TIMEOUT` | No | `120` | Heavy SSH command timeout, e.g. journal export (seconds) |

### .env file

The `.env` file in the project root is loaded automatically by the `run` scripts. Edit it with real credentials before running:

```ini
SSH_HOST=192.168.1.100
SSH_USER=admin
SSH_PASS=your_password
SSH_PORT=22
LANGUAGE=EN   # EN = English report
# SSH_ROOT_PASS=root_password   # Optional: to read root logs
```

To create from the template:

```bash
cp .env.example .env      # Linux / macOS
copy .env.example .env    # Windows
```

---

## 14. Troubleshooting

### `[X] Missing required environment variable(s): SSH_HOST, SSH_USER, SSH_PASS`

The `.env` file does not exist or the variables are not defined. Create `.env` from the template:

```bash
copy .env.example .env    # Windows
cp .env.example .env      # Linux / macOS
```

Then edit `.env` with your real credentials.

### `[X] Authentication failed — verify SSH_USER and SSH_PASS`

The credentials in `.env` are incorrect. Verify username and password.

### `[X] Host key not verifiable`

The host is not in `~/.ssh/known_hosts`. Solution:

```bash
ssh-keyscan -H <host> >> ~/.ssh/known_hosts
```

### `[X] Could not connect — timeout`

The host is not reachable from this machine. Verify network connectivity and that the SSH port is open:

```bash
ssh -p 22 user@host    # manual connectivity test
```

### `Missing: asyncssh, yaml, jinja2`

Dependencies are not installed. The `run` scripts install them automatically at startup — simply run again:

```powershell
.\run.ps1        # Windows PowerShell
```

```bash
bash run.sh      # Linux / macOS / WSL
```

### Root logs not collected (`/var/log/audit/audit.log`, `/var/log/secure`)

If the SSH user does not have access to protected logs and permission errors appear in `acquisition_log.json`, define `SSH_ROOT_PASS` in `.env`:

```ini
SSH_ROOT_PASS=root_password
```

The system will open a persistent PTY channel at session start, run `su root` once, and all subsequent commands (services, ports, processes, logs) will run as root. This also resolves issues with `journalctl` on RHEL/CentOS hosts where the SSH user is not in the `systemd-journal` group.

### Zero-size log files skipped

`*.log` files of 0 bytes are detected before the download attempt and silently skipped. They do not generate permission errors. If an expected log does not appear in the evidence, verify that the file is not empty on the remote host.

### Report is empty or has no findings

- Check `jobs/<job_id>/01_evidence/raw/acquisition_log.json` to see which commands failed.
- If the SSH user does not have `journalctl` permissions, system logs will not be exported.
- Check `jobs/<job_id>/02_analysis/rule_coverage.json` to see which rules were applied.

### PDF generation error

Without pandoc, the system uses `xhtml2pdf` automatically. If the PDF is not generated, run the `run` script again — it will reinstall dependencies automatically. For better PDF quality install pandoc:

```bash
# Ubuntu/Debian
sudo apt install pandoc texlive-xetex texlive-lang-english
# macOS
brew install pandoc && brew install --cask mactex
# Windows — download from https://pandoc.org/installing.html
```

### `duckdb` not available — limited correlations

If DuckDB is not installed, the correlator uses a pure Python fallback. For full functionality:

```bash
.venv\Scripts\pip install duckdb
```

### IOC engine slow on re-analysis

If analysis time is high on re-runs, verify that `all_entries.jsonl` exists and is newer than the files in `01_evidence/raw/logs/`. If the log files have a modification date later than the cache, the normalizer re-parses everything. This is expected after a new acquisition.

---

## License

All dependencies are open source (MIT, Apache 2.0 or BSD). No commercial licenses required.

---

*LinuxAuditLog v1.6.1 — Linux remote forensic acquisition tool*

*Developed by Gonzalo Serrano in collaboration with [Claude Code](https://claude.ai/code) (Anthropic).*
