"""
LogNormalizer — Stage B, step 1.

Reads all exported log artifacts from 01_evidence/raw/logs/
and produces a unified list of LogEntry dicts.

Supported formats:
  - journalctl JSON  (one JSON object per line, REALTIME_TIMESTAMP)
  - Traditional syslog  (RFC 3164: "Mon DD HH:MM:SS host svc[pid]: msg")
  - Apache/Nginx combined access log
  - Generic "YYYY-MM-DD HH:MM:SS level message" fallback

All content is treated as untrusted. No eval, no exec, no shell.
Remote instructions embedded in log messages are never followed.
"""
import gzip
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.job import JobContext


# syslog priority number → label
_PRIORITY = {"0": "emerg", "1": "alert", "2": "crit", "3": "error",
             "4": "warn", "5": "notice", "6": "info", "7": "debug"}

# Linux audit log: type=SYSCALL msg=audit(1234567890.123:42): ...
_RE_AUDIT = re.compile(
    r"^type=(?P<atype>\w+)\s+msg=audit\((?P<epoch>\d+)(?:\.\d+)?:\d+\):\s*(?P<msg>.+)$"
)

# Audit event type → service label (most common types)
_AUDIT_TYPE_SVC = {
    "SYSCALL": "audit-syscall", "EXECVE": "audit-syscall",
    "PATH": "audit-fs", "CWD": "audit-fs", "OPEN": "audit-fs",
    "USER_LOGIN": "pam", "USER_AUTH": "pam", "USER_ACCT": "pam",
    "USER_START": "pam", "USER_END": "pam", "CRED_ACQ": "pam",
    "CRED_DISP": "pam", "CRED_REFR": "pam",
    "USER_CMD": "sudo", "USER_ERR": "pam",
    "ADD_USER": "useradd", "DEL_USER": "userdel",
    "ADD_GROUP": "groupadd", "DEL_GROUP": "groupdel",
    "GRP_MGMT": "groupmod", "ACCT_LOCK": "pam", "ACCT_UNLOCK": "pam",
    "CRYPTO_KEY_USER": "sshd", "CRYPTO_SESSION": "sshd",
    "USER_LOGOUT": "pam", "LOGIN": "pam",
    "ANOM_PROMISCUOUS": "audit-net", "ANOM_LOGIN_FAILURES": "pam",
    "AVC": "selinux", "SELINUX_ERR": "selinux",
    "NETFILTER_PKT": "audit-net", "SOCKET_CONNECT": "audit-net",
    "SOCKADDR": "audit-net",
    "CONFIG_CHANGE": "audit-config", "DAEMON_START": "auditd",
    "DAEMON_END": "auditd", "DAEMON_CONFIG": "auditd",
    "KERNEL": "kernel", "KERN_MODULE": "kernel",
}

# RFC 3164 syslog regex
_RE_SYSLOG = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<svc>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<msg>.+)$"
)

# Apache/Nginx combined log
_RE_APACHE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]{2,10})\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>[\d-]+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<ua>[^"]*)")?'
)

# Apache/Nginx error log
_RE_APACHE_ERR = re.compile(
    r'^\[(?P<time>[^\]]+)\]\s+\[(?P<level>[^\]]+)\].*?(?P<msg>.+)$'
)

# Generic ISO timestamp
_RE_ISO = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?:\[?(?P<level>DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|ALERT|EMERG(?:ENCY)?)\]?\s+)?'
    r'(?P<msg>.+)$',
    re.IGNORECASE,
)

# Months for syslog parsing
_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
           "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}


class LogNormalizer:
    def __init__(self, job: JobContext) -> None:
        self.job = job
        self._stats: dict = {
            "total_entries": 0,
            "by_source": {},
            "by_service": {},
            "by_level": {},
            "parse_errors": 0,
            "time_range": {"earliest": None, "latest": None},
        }

    def normalize_all(self) -> list[dict]:
        """Parse every file under logs_dir. Returns list of LogEntry dicts.

        On re-runs, if the cached all_entries.jsonl is newer than every log file,
        the cache is loaded directly — skipping decompression and re-parsing.
        """
        cache_path = self.job.analysis("all_entries.jsonl")
        logs_dir = self.job.logs_dir

        # ── Cache check ───────────────────────────────────────────────
        if cache_path.exists() and logs_dir.exists():
            try:
                cache_mtime = cache_path.stat().st_mtime
                log_files = [p for p in logs_dir.iterdir() if p.is_file()]
                if log_files and all(p.stat().st_mtime <= cache_mtime for p in log_files):
                    entries = self._load_cache(cache_path)
                    if entries:
                        return entries
            except OSError:
                pass  # fall through to full parse

        # ── Full parse ────────────────────────────────────────────────
        entries: list[dict] = []

        if not logs_dir.exists():
            return entries

        for path in sorted(logs_dir.iterdir()):
            if path.is_file():
                file_entries = self._parse_file(path)
                entries.extend(file_entries)
                self._stats["by_source"][path.name] = len(file_entries)

        # Sort by timestamp (entries without a timestamp go last)
        entries.sort(key=lambda e: e.get("ts_epoch", 0))

        self._stats["total_entries"] = len(entries)
        if entries:
            ts_list = [e["ts_epoch"] for e in entries if e.get("ts_epoch")]
            if ts_list:
                self._stats["time_range"]["earliest"] = _epoch_to_iso(min(ts_list))
                self._stats["time_range"]["latest"] = _epoch_to_iso(max(ts_list))

        # Persist normalized entries to analysis dir
        with open(cache_path, "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")

        return entries

    def _load_cache(self, cache_path: Path) -> list[dict]:
        """Load previously normalized entries from JSONL cache."""
        entries: list[dict] = []
        try:
            with open(cache_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            return []

        if not entries:
            return []

        # Rebuild stats from cached data (lightweight pass)
        self._stats["total_entries"] = len(entries)
        for e in entries:
            svc = e.get("service", "unknown")
            lvl = e.get("level", "info")
            self._stats["by_source"].setdefault(e.get("source_file", "?").split("/")[-1], 0)
            self._stats["by_service"][svc] = self._stats["by_service"].get(svc, 0) + 1
            self._stats["by_level"][lvl] = self._stats["by_level"].get(lvl, 0) + 1
        ts_list = [e["ts_epoch"] for e in entries if e.get("ts_epoch")]
        if ts_list:
            self._stats["time_range"]["earliest"] = _epoch_to_iso(min(ts_list))
            self._stats["time_range"]["latest"] = _epoch_to_iso(max(ts_list))

        return entries

    def get_stats(self) -> dict:
        return self._stats

    # ------------------------------------------------------------------
    # File dispatcher
    # ------------------------------------------------------------------

    def _parse_file(self, path: Path) -> list[dict]:
        content = _read_file(path)
        if not content:
            return []

        name = path.name.lower()
        sample = content[:2000]

        # ── Stage A pre-converted JSONL must be checked FIRST ──────────
        # Stage A converts every plain-text log (access, error, syslog…)
        # to JSONL and renames it with .jsonl/.jsonl.gz.  The resulting
        # filename still contains keywords like "access" or "error", so
        # the filename-based checks below would dispatch it to the wrong
        # parser and drop all entries.  Content detection wins over name.
        if sample.strip().startswith("{") and '"ts_epoch"' in sample and '"source_file"' in sample:
            return self._parse_stage_a_jsonl(content, str(path))

        # journalctl JSON (highest fidelity, always named consistently)
        if ("journal" in name and name.endswith(".json.gz")) or (
            "journal" in name and name.endswith(".json")
        ):
            return self._parse_journalctl_json(content, str(path))

        # journalctl JSON by content (inconsistently-named files)
        if sample.strip().startswith("{") and "__REALTIME_TIMESTAMP" in sample:
            return self._parse_journalctl_json(content, str(path))

        if "access" in name or name.endswith("access_log") or "access_log" in name:
            return self._parse_apache_access(content, str(path))

        if "error" in name and ("nginx" in name or "apache" in name or "httpd" in name):
            return self._parse_apache_error(content, str(path))

        # Linux audit log format: type=XXXX msg=audit(...)
        first_line = sample.splitlines()[0] if sample.splitlines() else ""
        if _RE_AUDIT.match(first_line):
            return self._parse_audit_log(content, str(path))

        # Try syslog format
        if _RE_SYSLOG.match(first_line):
            return self._parse_syslog(content, str(path))

        # Generic fallback
        return self._parse_generic(content, str(path))

    # ------------------------------------------------------------------
    # Format parsers
    # ------------------------------------------------------------------

    def _parse_journalctl_json(self, content: str, source: str) -> list[dict]:
        entries = []
        service_key = source.split("/")[-1].split("_")[1] if "_" in source else "system"

        for line in content.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                self._stats["parse_errors"] += 1
                continue

            ts_usec = _safe_int(obj.get("__REALTIME_TIMESTAMP", 0))
            ts_epoch = ts_usec / 1_000_000 if ts_usec else 0
            ts_iso = _epoch_to_iso(ts_epoch) if ts_epoch else None

            svc = (
                obj.get("SYSLOG_IDENTIFIER")
                or (obj.get("_SYSTEMD_UNIT", "").replace(".service", ""))
                or service_key
            )[:64]

            message = obj.get("MESSAGE", "")
            if isinstance(message, list):
                message = " ".join(str(b) for b in message)
            message = str(message)[:4096]

            level = _PRIORITY.get(str(obj.get("PRIORITY", "6")), "info")

            entry = _make_entry(
                timestamp=ts_iso,
                ts_epoch=ts_epoch,
                hostname=obj.get("_HOSTNAME", "unknown")[:128],
                service=svc,
                pid=str(obj.get("_PID", ""))[:10],
                level=level,
                message=message,
                source_file=source,
                raw=line[:1024],
            )
            entries.append(entry)
            self._update_service_stats(svc, level)

        return entries

    def _parse_syslog(self, content: str, source: str) -> list[dict]:
        entries = []
        year = datetime.now(timezone.utc).year

        for line in content.splitlines():
            line = line.rstrip("\r")
            if not line:
                continue
            m = _RE_SYSLOG.match(line)
            if not m:
                self._stats["parse_errors"] += 1
                continue

            month_str = m.group("month").lower()
            month = _MONTHS.get(month_str, 1)
            day = int(m.group("day"))
            time_str = m.group("time")
            hh, mm, ss = [int(x) for x in time_str.split(":")]

            try:
                dt = datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
                ts_epoch = dt.timestamp()
                ts_iso = dt.isoformat()
            except ValueError:
                ts_epoch = 0
                ts_iso = None

            svc = m.group("svc")[:64]
            entry = _make_entry(
                timestamp=ts_iso,
                ts_epoch=ts_epoch,
                hostname=m.group("host")[:128],
                service=svc,
                pid=m.group("pid") or "",
                level="info",
                message=m.group("msg")[:4096],
                source_file=source,
                raw=line[:1024],
            )
            entries.append(entry)
            self._update_service_stats(svc, "info")

        return entries

    def _parse_apache_access(self, content: str, source: str) -> list[dict]:
        entries = []
        service = "nginx" if "nginx" in source.lower() else "apache2"

        for line in content.splitlines():
            line = line.rstrip("\r")
            if not line:
                continue
            m = _RE_APACHE.match(line)
            if not m:
                self._stats["parse_errors"] += 1
                continue

            ts_epoch, ts_iso = _parse_apache_time(m.group("time"))
            status = m.group("status")
            level = "error" if status and status.startswith(("4", "5")) else "info"

            entry = _make_entry(
                timestamp=ts_iso,
                ts_epoch=ts_epoch,
                hostname="webserver",
                service=service,
                pid="",
                level=level,
                message=f'{m.group("method")} {m.group("uri")} {m.group("proto")} -> {status}',
                source_file=source,
                raw=line[:1024],
            )
            entry["extracted"] = {
                "src_ip": m.group("src_ip"),
                "http_method": m.group("method"),
                "uri": m.group("uri")[:512],
                "http_status": status,
                "user": m.group("user") if m.group("user") != "-" else None,
                "user_agent": m.group("ua")[:256] if m.group("ua") else None,
            }
            entries.append(entry)
            self._update_service_stats(service, level)

        return entries

    def _parse_apache_error(self, content: str, source: str) -> list[dict]:
        entries = []
        service = "nginx" if "nginx" in source.lower() else "apache2"

        for line in content.splitlines():
            line = line.rstrip("\r")
            if not line:
                continue
            m = _RE_APACHE_ERR.match(line)
            if not m:
                continue
            entry = _make_entry(
                timestamp=None,
                ts_epoch=0,
                hostname="webserver",
                service=f"{service}_error",
                pid="",
                level=m.group("level").lower()[:16],
                message=m.group("msg")[:4096],
                source_file=source,
                raw=line[:1024],
            )
            entries.append(entry)
            self._update_service_stats(service, "error")

        return entries

    def _parse_generic(self, content: str, source: str) -> list[dict]:
        entries = []
        service = Path(source).name.split(".")[0][:32]

        for line in content.splitlines():
            line = line.rstrip("\r")
            if not line:
                continue
            m = _RE_ISO.match(line)
            if m:
                ts_iso = m.group("ts")
                try:
                    ts_epoch = datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    ts_epoch = 0
                level = (m.group("level") or "info").lower()
                msg = m.group("msg")
            else:
                ts_iso = None
                ts_epoch = 0
                level = "info"
                msg = line

            entry = _make_entry(
                timestamp=ts_iso,
                ts_epoch=ts_epoch,
                hostname="unknown",
                service=service,
                pid="",
                level=level,
                message=msg[:4096],
                source_file=source,
                raw=line[:1024],
            )
            entries.append(entry)

        return entries

    def _parse_stage_a_jsonl(self, content: str, source: str) -> list[dict]:
        """Parse JSONL files pre-converted by Stage A's _convert_text_logs_to_json().

        These files already carry our LogEntry schema (timestamp, ts_epoch,
        hostname, service, pid, level, message, source_file, raw, extracted).
        We deserialise each line and pass values directly through _make_entry
        so stats are updated and the cache format stays consistent.

        When Stage A couldn't identify the service (stored as "unknown"), we
        infer it from the source file path so that service-scoped IOC rules
        (service: apache2, service: nginx, …) can evaluate these entries.
        """
        inferred_svc = _infer_service_from_path(source)
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                self._stats["parse_errors"] += 1
                continue

            svc = str(obj.get("service", "unknown"))[:64]
            if svc == "unknown" and inferred_svc:
                svc = inferred_svc
            lvl = str(obj.get("level", "info"))
            entry = _make_entry(
                timestamp=obj.get("timestamp"),
                ts_epoch=float(obj.get("ts_epoch", 0)),
                hostname=str(obj.get("hostname", "unknown"))[:128],
                service=svc,
                pid=str(obj.get("pid", ""))[:10],
                level=lvl,
                message=str(obj.get("message", ""))[:4096],
                source_file=source,
                raw=str(obj.get("raw", ""))[:1024],
            )
            entry["extracted"] = obj.get("extracted") or {}
            entries.append(entry)
            self._update_service_stats(svc, lvl)

        return entries

    def _parse_audit_log(self, content: str, source: str) -> list[dict]:
        """Parse Linux audit log format: type=XXXX msg=audit(epoch.xxx:serial): body

        Extracts event type, timestamp, pid, and body.  Maps event type to a
        meaningful service label so IOC rules can filter on audit-syscall, pam,
        sudo, selinux, etc. instead of generic 'unknown'.
        """
        entries = []
        for line in content.splitlines():
            line = line.rstrip("\r")
            if not line:
                continue
            m = _RE_AUDIT.match(line)
            if not m:
                # Continuation lines (EXECVE args etc.) — attach to previous entry as raw
                self._stats["parse_errors"] += 1
                continue

            atype = m.group("atype")
            epoch_str = m.group("epoch")
            msg_body = m.group("msg")[:4096]

            try:
                ts_epoch = float(epoch_str)
                ts_iso = _epoch_to_iso(ts_epoch)
            except ValueError:
                ts_epoch = 0
                ts_iso = None

            svc = _AUDIT_TYPE_SVC.get(atype, "auditd")
            level = "info"
            # Flag anomaly / error types as higher severity
            if atype.startswith("ANOM_") or atype.startswith("ERR") or "FAIL" in atype:
                level = "warn"
            if atype in ("AVC", "SELINUX_ERR", "KERN_MODULE"):
                level = "warn"

            # Extract pid from body if present
            pid = ""
            pid_m = re.search(r"\bpid=(\d+)", msg_body)
            if pid_m:
                pid = pid_m.group(1)

            entry = _make_entry(
                timestamp=ts_iso,
                ts_epoch=ts_epoch,
                hostname="unknown",
                service=svc,
                pid=pid,
                level=level,
                message=f"type={atype} {msg_body}",
                source_file=source,
                raw=line[:1024],
            )
            entries.append(entry)
            self._update_service_stats(svc, level)

        return entries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_service_stats(self, service: str, level: str) -> None:
        self._stats["by_service"][service] = self._stats["by_service"].get(service, 0) + 1
        self._stats["by_level"][level] = self._stats["by_level"].get(level, 0) + 1


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _infer_service_from_path(source: str) -> str:
    """Infer a service label from a log file path.

    Stage A's generic converter assigns service='unknown' to log formats it
    doesn't recognise (e.g. Apache combined access log, nginx error log).
    This function maps the file path back to the expected service label so
    that IOC rules with a service filter can evaluate those entries.

    Returns an empty string when no inference is possible (caller keeps the
    original value in that case).
    """
    s = source.lower()
    # Apache / httpd
    if "apache2" in s or "httpd" in s or "apache" in s:
        if "error" in s:
            return "apache2_error"
        return "apache2"
    # Nginx
    if "nginx" in s:
        if "error" in s:
            return "nginx_error"
        return "nginx"
    # Common auth / system logs
    if "auth.log" in s or "var_log_auth" in s:
        return "sshd"
    if "secure" in s and "var_log" in s:
        return "sshd"
    if "syslog" in s or "messages" in s:
        return "syslog"
    return ""


def _make_entry(
    timestamp: Optional[str],
    ts_epoch: float,
    hostname: str,
    service: str,
    pid: str,
    level: str,
    message: str,
    source_file: str,
    raw: str,
) -> dict:
    return {
        "timestamp": timestamp,
        "ts_epoch": ts_epoch,
        "hostname": hostname,
        "service": service,
        "pid": pid,
        "level": level,
        "message": message,
        "source_file": source_file,
        "raw": raw,
        "extracted": {},
    }


def _read_file(path: Path) -> str:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        else:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
    except Exception:
        return ""


def _safe_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _parse_apache_time(time_str: str) -> tuple[float, Optional[str]]:
    """Parse Apache time: '13/Apr/2026:14:30:00 +0000'"""
    try:
        dt = datetime.strptime(time_str.strip(), "%d/%b/%Y:%H:%M:%S %z")
        return dt.timestamp(), dt.isoformat()
    except ValueError:
        return 0, None
