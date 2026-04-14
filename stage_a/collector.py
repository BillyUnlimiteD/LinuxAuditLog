"""
RemoteCollector — Phases 2, 3, and 4 of Stage A.

Runs read-only commands remotely, captures stdout, writes output
directly to local files. No temporary files are created on the
remote server.

Principles:
- All commands are hardcoded. No command is derived from remote data.
- Output is length-limited to prevent memory exhaustion.
- Every failure is logged as a limitation (not a crash).
- SFTP is used only for direct log file download when journalctl is unavailable.
"""
import asyncio
import gzip
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import config
from core.job import JobContext


# RFC 3164 syslog regex for parsing
_RE_SYSLOG = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<svc>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<msg>.+)$"
)

# Generic timestamp regex for various log formats
_RE_GENERIC_TS = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)?\s*(?P<service>\S+)?(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.+)$"
)


def _parse_log_line_to_json(line: str, source_file: str, hostname: str = "unknown") -> dict:
    """
    Convert a single log line to structured JSON format.

    Args:
        line: Raw log line text
        source_file: Path to the source file
        hostname: Hostname to assign if not found in log

    Returns:
        Dict with structured log entry
    """
    line = line.strip()
    if not line:
        return None

    # Try syslog format first
    syslog_match = _RE_SYSLOG.match(line)
    if syslog_match:
        groups = syslog_match.groupdict()
        # Convert syslog timestamp to ISO format (approximate for current year)
        try:
            month = groups['month']
            day = int(groups['day'])
            time_str = groups['time']
            # Create approximate datetime (using current year)
            current_year = datetime.now().year
            dt_str = f"{current_year} {month} {day:02d} {time_str}"
            dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
            timestamp = dt.isoformat()
            ts_epoch = int(dt.timestamp())
        except:
            timestamp = None
            ts_epoch = 0

        return {
            "timestamp": timestamp,
            "ts_epoch": ts_epoch,
            "hostname": groups.get('host', hostname),
            "service": groups.get('svc', 'unknown'),
            "pid": groups.get('pid', ''),
            "level": "info",  # Default level
            "message": groups.get('msg', line),
            "source_file": source_file,
            "raw": line,
            "extracted": {}
        }

    # Try generic timestamp format
    generic_match = _RE_GENERIC_TS.match(line)
    if generic_match:
        groups = generic_match.groupdict()
        timestamp_str = groups.get('timestamp')

        # Try to parse timestamp
        timestamp = None
        ts_epoch = 0
        try:
            # Handle different timestamp formats
            if timestamp_str:
                # ISO format
                if '-' in timestamp_str and ':' in timestamp_str:
                    dt = datetime.fromisoformat(timestamp_str.replace(' ', 'T'))
                    timestamp = dt.isoformat()
                    ts_epoch = int(dt.timestamp())
                # Syslog format
                elif len(timestamp_str.split()) == 3:
                    month, day, time_str = timestamp_str.split()
                    current_year = datetime.now().year
                    dt_str = f"{current_year} {month} {int(day):02d} {time_str}"
                    dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
                    timestamp = dt.isoformat()
                    ts_epoch = int(dt.timestamp())
        except:
            pass

        return {
            "timestamp": timestamp,
            "ts_epoch": ts_epoch,
            "hostname": groups.get('hostname', hostname),
            "service": groups.get('service', 'unknown'),
            "pid": groups.get('pid', ''),
            "level": "info",
            "message": groups.get('message', line),
            "source_file": source_file,
            "raw": line,
            "extracted": {}
        }

    # Fallback for unrecognized formats
    return {
        "timestamp": None,
        "ts_epoch": 0,
        "hostname": hostname,
        "service": "unknown",
        "pid": "",
        "level": "info",
        "message": line,
        "source_file": source_file,
        "raw": line,
        "extracted": {}
    }


def _convert_text_logs_to_json(text_content: str, source_file: str, hostname: str = "unknown") -> str:
    """
    Convert text log content to JSON Lines format.

    Args:
        text_content: Raw text content of log file
        source_file: Path to source file
        hostname: Default hostname

    Returns:
        JSON Lines string with structured log entries
    """
    json_lines = []
    for line in text_content.splitlines():
        if line.strip():
            entry = _parse_log_line_to_json(line, source_file, hostname)
            if entry:
                json_lines.append(json.dumps(entry, ensure_ascii=False))

    return '\n'.join(json_lines)
_TIMEOUT_DEFAULT     = config.SSH_COMMAND_TIMEOUT
_TIMEOUT_LARGE       = config.SSH_LARGE_COMMAND_TIMEOUT
_MAX_COMMAND_OUTPUT  = config.MAX_LOG_LINES_PER_SOURCE

# Syslog files attempted on ALL systems.
# On systemd hosts these complement journalctl (RHEL/CentOS keeps plain-text
# copies of /var/log/secure and /var/log/messages alongside the journal).
# The varlog sweep only finds *.log files, so extensionless paths like
# /var/log/secure and /var/log/messages would be missed without this list.
_FALLBACK_LOG_FILES = [
    "/var/log/auth.log",      # Debian/Ubuntu
    "/var/log/secure",        # RHEL/CentOS — auth/SSH events
    "/var/log/syslog",        # Debian/Ubuntu
    "/var/log/messages",      # RHEL/CentOS — general syslog
    "/var/log/kern.log",      # Debian/Ubuntu
    "/var/log/daemon.log",    # Debian/Ubuntu
    "/var/log/maillog",       # RHEL/CentOS — mail events
    "/var/log/boot.log",      # RHEL/CentOS — boot messages (root-only)
    "/var/log/cron",          # RHEL/CentOS — cron events (no .log extension)
]

# Web server log paths to attempt
_WEB_LOG_PATHS = [
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
]

# Service name → candidate log paths in /var/log/
# Paths ending in * are treated as globs (resolved via ls on the remote host).
# Keys must match the unit name without .service suffix (lowercase).
_SERVICE_LOG_MAP: dict[str, list[str]] = {
    # Databases
    "mysql":         ["/var/log/mysql/error.log", "/var/log/mysql.log", "/var/log/mysqld.log"],
    "mysqld":        ["/var/log/mysql/error.log", "/var/log/mysql.log", "/var/log/mysqld.log"],
    "mysqld_safe":   ["/var/log/mysql/error.log", "/var/log/mysql.log"],
    "mariadb":       ["/var/log/mysql/error.log", "/var/log/mariadb/mariadb.log"],
    "mariadbd":      ["/var/log/mysql/error.log", "/var/log/mariadb/mariadb.log"],
    "postgresql":    ["/var/log/postgresql/postgresql-*.log"],
    "postgres":      ["/var/log/postgresql/postgresql-*.log"],
    "mongod":        ["/var/log/mongodb/mongod.log"],
    "redis":         ["/var/log/redis/redis-server.log", "/var/log/redis.log"],
    "redis-server":  ["/var/log/redis/redis-server.log", "/var/log/redis.log"],
    "elasticsearch": ["/var/log/elasticsearch/elasticsearch.log",
                      "/var/log/elasticsearch/*.log"],
    "opensearch":    ["/var/log/opensearch/opensearch.log"],
    "memcached":     ["/var/log/memcached.log"],
    "rabbitmq":      ["/var/log/rabbitmq/rabbit@*.log"],
    # Mail
    "postfix":       ["/var/log/mail.log", "/var/log/maillog"],
    "master":        ["/var/log/mail.log", "/var/log/maillog"],
    "dovecot":       ["/var/log/dovecot.log", "/var/log/mail.log"],
    "sendmail":      ["/var/log/maillog", "/var/log/mail.log"],
    "exim":          ["/var/log/exim4/mainlog", "/var/log/exim4/rejectlog"],
    # FTP
    "vsftpd":        ["/var/log/vsftpd.log"],
    "proftpd":       ["/var/log/proftpd/proftpd.log", "/var/log/proftpd/auth.log"],
    "pure-ftpd":     ["/var/log/pure-ftpd/pure-ftpd.log"],
    # DNS
    "named":         ["/var/log/named/default", "/var/named/data/named_stats.txt"],
    "bind9":         ["/var/log/named/default"],
    "unbound":       ["/var/log/unbound/unbound.log"],
    # File sharing
    "smb":           ["/var/log/samba/log.smbd", "/var/log/samba/log.nmbd"],
    "smbd":          ["/var/log/samba/log.smbd"],
    "nmbd":          ["/var/log/samba/log.nmbd"],
    # Security / firewall
    "fail2ban":      ["/var/log/fail2ban.log"],
    "ufw":           ["/var/log/ufw.log"],
    # Proxy / load balancer
    "haproxy":       ["/var/log/haproxy.log"],
    "varnish":       ["/var/log/varnish/varnishncsa.log"],
    # PHP-FPM (Remi repo on CentOS uses versioned names and non-standard paths)
    "php-fpm":        ["/var/log/php-fpm.log", "/var/log/php-fpm/error.log"],
    "php56-php-fpm":  ["/var/opt/remi/php56/log/php-fpm/error.log",
                       "/var/opt/remi/php56/log/php-fpm/www-error.log"],
    "php70-php-fpm":  ["/var/opt/remi/php70/log/php-fpm/error.log",
                       "/var/opt/remi/php70/log/php-fpm/www-error.log"],
    "php74-php-fpm":  ["/var/opt/remi/php74/log/php-fpm/error.log"],
    "php80-php-fpm":  ["/var/opt/remi/php80/log/php-fpm/error.log"],
    "php81-php-fpm":  ["/var/opt/remi/php81/log/php-fpm/error.log"],
    "php82-php-fpm":  ["/var/opt/remi/php82/log/php-fpm/error.log"],
    "php8.2-fpm":     ["/var/log/php8.2-fpm.log"],
    "php8.1-fpm":     ["/var/log/php8.1-fpm.log"],
    "php8.0-fpm":     ["/var/log/php8.0-fpm.log"],
    "php7.4-fpm":     ["/var/log/php7.4-fpm.log"],
    # Monitoring / security
    "zabbix-agent":   ["/var/log/zabbix/zabbix_agentd.log"],
    "zabbix-agent2":  ["/var/log/zabbix/zabbix_agent2.log"],
    "clamd":          ["/var/log/clamav/clamd.log", "/var/log/clamd.log"],
    "clamav-daemon":  ["/var/log/clamav/clamd.log", "/var/log/clamd.log"],
    "freshclam":      ["/var/log/freshclam.log", "/var/log/clamav/freshclam.log"],
    "clamav-freshclam": ["/var/log/freshclam.log", "/var/log/clamav/freshclam.log"],
    # Mail
    "sendmail":       ["/var/log/maillog", "/var/log/mail.log"],
    "sm-client":      ["/var/log/maillog", "/var/log/mail.log"],
    # Docker
    "docker":         [],   # logs via journalctl -u docker
    "dockerd":        [],
    "containerd":     [],
}


class _RootChannel:
    """Persistent su-root shell for the duration of Stage A acquisition.

    A single PTY process runs 'su root', authenticated once at startup.
    All subsequent commands are written to its stdin and output is
    collected up to a randomly-generated sentinel string, avoiding the
    need to spawn a new PTY process for every privileged command.

    Usage:
        channel = await _RootChannel.create(conn, root_pass, acq_log)
        if channel:
            output = await channel.run("journalctl -u sshd", timeout=60)
            await channel.close()
    """

    def __init__(self, proc, sentinel: str) -> None:
        self._proc = proc
        self._sentinel = sentinel
        self._lock = asyncio.Lock()

    @classmethod
    async def create(
        cls, conn, root_pass: str, acq_log: dict
    ) -> "Optional[_RootChannel]":
        """Spawn su root, authenticate, verify uid=0.  Returns None on failure."""
        import secrets as _secrets
        sentinel = _secrets.token_hex(10)

        try:
            proc = await conn.create_process(
                "su root",
                request_pty=True,
                term_type="dumb",
            )

            # Wait for the su password prompt.
            buf = ""
            try:
                while "assword" not in buf:
                    chunk = await asyncio.wait_for(proc.stdout.read(256), timeout=10)
                    if not chunk:
                        break
                    buf += chunk
            except asyncio.TimeoutError:
                pass

            # Send root password.
            proc.stdin.write(root_pass + "\n")

            # Silence the shell completely:
            #   stty -echo  — suppress command echo
            #   PS1/PS2=''  — suppress shell prompts so they never appear in output
            proc.stdin.write("stty -echo; PS1=''; PS2=''\n")

            # Verify root shell with a test command + unique marker.
            verify_marker = f"__VERIFY_{sentinel}__"
            proc.stdin.write(f"id; echo '{verify_marker}'\n")

            verify_buf = ""
            try:
                loop = asyncio.get_running_loop()
                deadline = loop.time() + 12
                while verify_marker not in verify_buf:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        break
                    chunk = await asyncio.wait_for(
                        proc.stdout.read(65536), timeout=min(remaining, 3)
                    )
                    if not chunk:
                        break
                    verify_buf += chunk
            except asyncio.TimeoutError:
                pass

            clean = verify_buf.replace("\r\n", "\n").replace("\r", "")
            if "uid=0" in clean or "(root)" in clean:
                acq_log["root_escalation"] = "success — running as root via persistent su channel"
                return cls(proc, sentinel)

            # Auth failed.
            hint = "authentication failure"
            lower = clean.lower()
            if any(s in lower for s in ("failure", "incorrect", "sorry", "denied")):
                hint = "wrong password or PAM rejected su"
            elif verify_marker not in clean:
                hint = "no response from root shell (timeout or su disabled)"
            acq_log["errors"].append({
                "phase": 0,
                "cmd": "su root (channel setup)",
                "error": f"root escalation failed: {hint}",
            })
            try:
                proc.stdin.write("exit\n")
            except Exception:
                pass
            return None

        except Exception as exc:
            acq_log["errors"].append({
                "phase": 0,
                "cmd": "su root (channel setup)",
                "error": f"root channel error: {str(exc)[:200]}",
            })
            return None

    async def run(self, cmd: str, timeout: int) -> "Optional[str]":
        """Send *cmd* to the persistent root shell and return its stdout output.

        Returns None if the channel's stdin is dead (caller should fall back
        to normal execution).  Returns "" for commands that produce no output.
        """
        async with self._lock:
            marker = f"__DONE_{self._sentinel}__"
            try:
                self._proc.stdin.write(f"{cmd}; echo '{marker}'\n")
            except Exception:
                return None  # channel is dead

            parts: list[str] = []
            # Cap each individual read at 30 s so the deadline is checked
            # regularly regardless of how large the command output is.
            _READ_SLICE = 30
            try:
                loop = asyncio.get_running_loop()
                deadline = loop.time() + timeout
                while True:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        break
                    chunk = await asyncio.wait_for(
                        self._proc.stdout.read(65536),
                        timeout=min(remaining, _READ_SLICE),
                    )
                    if not chunk:
                        break
                    parts.append(chunk)
                    combined = "".join(parts)
                    if marker in combined:
                        output = combined[: combined.index(marker)]
                        return output.replace("\r\n", "\n").replace("\r", "")
            except asyncio.TimeoutError:
                pass

            return "".join(parts).replace("\r\n", "\n").replace("\r", "")

    async def close(self) -> None:
        """Send exit to the root shell and wait for it to terminate."""
        try:
            self._proc.stdin.write("exit\n")
            await asyncio.wait_for(self._proc.wait(), timeout=5)
        except Exception:
            pass


class RemoteCollector:
    def __init__(
        self,
        conn,
        job: JobContext,
        system_info: dict,
        acq_log: dict,
        root_pass: str = "",
    ) -> None:
        self.conn = conn
        self.job = job
        self.system_info = system_info
        self.acq_log = acq_log
        self._has_systemd = system_info.get("init_system") == "systemd"
        self._since = f"{config.DEFAULT_TIME_WINDOW_HOURS} hours ago"
        self._root_pass: str = root_pass
        # Get hostname for log parsing
        self._hostname = system_info.get("hostname", "unknown")
        # Persistent root shell — set by collect_all() when SSH_ROOT_PASS is configured.
        self._root_channel: Optional[_RootChannel] = None
        # Tracks every remote path already downloaded so multiple collection
        # methods never write the same file twice.
        self._seen_log_paths: set[str] = set()

    async def collect_all(self) -> None:
        """Run all collection phases sequentially (Phases 2 → 4).

        If SSH_ROOT_PASS is configured, a persistent 'su root' channel is
        established before any phase runs so that ALL commands execute as
        root without repeated PTY handshakes.
        """
        if self._root_pass:
            self._root_channel = await _RootChannel.create(
                self.conn, self._root_pass, self.acq_log
            )
        try:
            await self._phase2_services()
            await self._phase3_ports_and_processes()
            await self._phase4_logs()
        finally:
            if self._root_channel is not None:
                await self._root_channel.close()
                self._root_channel = None

    # ------------------------------------------------------------------
    # Phase 2 — Services inventory
    # ------------------------------------------------------------------

    async def _phase2_services(self) -> None:
        services = {"raw_systemctl": "", "raw_ps": "", "parsed": []}

        if self._has_systemd:
            # Try with sudo (NOPASSWD) first; fall back to unprivileged.
            # sudo gives a complete picture including root-owned units that
            # an unprivileged user may not see on some distributions.
            out = await self._run(
                "sudo -n systemctl list-units --type=service --state=running --no-pager --plain 2>/dev/null"
                " || systemctl list-units --type=service --state=running --no-pager --plain 2>/dev/null",
                phase=2,
            )
            services["raw_systemctl"] = out
            services["parsed"] = _parse_systemctl_list(out)
        else:
            out = await self._run(
                "sudo -n service --status-all 2>/dev/null || service --status-all 2>/dev/null || ls /etc/init.d/ 2>/dev/null",
                phase=2,
            )
            services["raw_systemctl"] = out

        # Complement with ps
        ps_out = await self._run(
            "ps aux --no-headers 2>/dev/null | head -200",
            phase=2,
            timeout=_TIMEOUT_DEFAULT,
        )
        services["raw_ps"] = ps_out

        self._write_json("services_inventory.json", services, phase=2)

    # ------------------------------------------------------------------
    # Phase 3 — Ports and processes
    # ------------------------------------------------------------------

    async def _phase3_ports_and_processes(self) -> None:
        # Listening ports — the -p flag (show process) requires root on most
        # distros; try sudo first, fall back to unprivileged (no process column).
        ports_out = await self._run(
            "sudo -n ss -lntup 2>/dev/null || ss -lntup 2>/dev/null || sudo -n netstat -lntup 2>/dev/null || netstat -lntup 2>/dev/null",
            phase=3,
            timeout=_TIMEOUT_DEFAULT,
        )
        self._write_text("ports_listening.txt", ports_out, phase=3)

        # /etc/hosts — network context
        hosts_out = await self._run("cat /etc/hosts 2>/dev/null", phase=3, timeout=10)
        self._write_text("etc_hosts.txt", hosts_out, phase=3)

        # Last logins
        last_out = await self._run("last -n 50 2>/dev/null | head -60", phase=3, timeout=10)
        self._write_text("last_logins.txt", last_out, phase=3)

        # Failed login attempts — /var/log/btmp requires root on most distros
        lastb_out = await self._run(
            "sudo -n lastb -n 50 2>/dev/null | head -60 || lastb -n 50 2>/dev/null | head -60",
            phase=3, timeout=10,
        )
        self._write_text("last_failed_logins.txt", lastb_out, phase=3)

        # Active users
        w_out = await self._run("w 2>/dev/null", phase=3, timeout=10)
        self._write_text("active_users.txt", w_out, phase=3)

        # Crontabs
        cron_out = await self._run(
            "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null",
            phase=3, timeout=15,
        )
        self._write_text("crontabs.txt", cron_out, phase=3)

        # Sudoers (read-only, metadata only)
        sudoers_out = await self._run(
            "cat /etc/sudoers 2>/dev/null | head -80",
            phase=3, timeout=10,
        )
        self._write_text("sudoers_partial.txt", sudoers_out, phase=3)

    # ------------------------------------------------------------------
    # Phase 4 — Log export
    # ------------------------------------------------------------------

    async def _phase4_logs(self) -> None:
        if self._has_systemd:
            await self._collect_journalctl_logs()
        # Always attempt plain log files regardless of init system.
        # On systemd hosts this picks up RHEL/CentOS files like /var/log/secure
        # and /var/log/messages which exist alongside journald and are not found
        # by the *.log sweep because they have no .log extension.
        await self._collect_file_logs()

        await self._collect_web_logs()
        await self._collect_service_logs()
        await self._collect_kernel_logs()
        # Rotated copies of the key syslog files (CentOS: secure-YYYYMMDD,
        # Debian: auth.log.1, auth.log.2.gz, etc.)  Required for >72h coverage.
        await self._collect_rotated_logs()
        # Broad sweep — discovers every *.log across all standard log trees
        # (/var/log, /var/opt, /opt, /srv, /var/www) not already collected.
        await self._collect_log_sweep()

    async def _collect_journalctl_logs(self) -> None:
        """Export journalctl logs as JSON (structured, preferred for analysis).

        When a root channel is active all journals are accessible directly.
        Without root, sudo -n (NOPASSWD) is tried first, then the unprivileged
        fallback which returns only the current-boot user journal on most distros.
        """
        sources = [
            # (filename, journalctl args)
            ("journal_system_72h.json", f"--since=\"{self._since}\" -o json --no-pager"),
            ("journal_auth_72h.json", f"-t sshd -t sudo -t su -t pam -t login --since=\"{self._since}\" -o json --no-pager"),
            ("journal_sshd_72h.json", f"-u sshd --since=\"{self._since}\" -o json --no-pager"),
            ("journal_sudo_72h.json", f"-u sudo --since=\"{self._since}\" -o json --no-pager"),
            ("journal_cron_72h.json", f"-u cron -u crond --since=\"{self._since}\" -o json --no-pager"),
            ("journal_kernel_72h.json", f"-k --since=\"{self._since}\" -o json --no-pager"),
        ]

        for filename, args in sources:
            if self._root_channel is not None:
                # Root channel active: run journalctl directly as root.
                cmd = f"journalctl {args} 2>/dev/null | head -n {_MAX_COMMAND_OUTPUT}"
            else:
                # No root: try sudo -n (NOPASSWD) then unprivileged.
                cmd = (
                    f"sudo -n journalctl {args} 2>/dev/null | head -n {_MAX_COMMAND_OUTPUT}"
                    f" || journalctl {args} 2>/dev/null | head -n {_MAX_COMMAND_OUTPUT}"
                )
            out = await self._run(cmd, phase=4, timeout=_TIMEOUT_LARGE)
            if out.strip():
                self._write_log(filename, out, phase=4)

    async def _collect_file_logs(self) -> None:
        """Download syslog-style plain-text files (auth, secure, messages, etc.).

        Called on ALL systems — even systemd hosts keep plain-text copies of
        critical logs like /var/log/secure alongside the journal.  Delegates
        to _download_varlog_file so that deduplication via _seen_log_paths and
        permission-error logging are applied consistently.
        """
        for remote_path in _FALLBACK_LOG_FILES:
            await self._download_varlog_file(remote_path, phase=4)

    async def _collect_web_logs(self) -> None:
        """Collect web server access and error logs."""
        for remote_path in _WEB_LOG_PATHS:
            await self._download_varlog_file(remote_path, phase=4)

    async def _collect_service_logs(self) -> None:
        """Collect logs for each detected service from /var/log/ using _SERVICE_LOG_MAP."""
        services = self._load_detected_services()

        for svc in services:
            svc_key = svc.lower().strip()
            log_paths = _SERVICE_LOG_MAP.get(svc_key, [])
            if not log_paths:
                continue

            for log_path in log_paths:
                if "*" in log_path:
                    # Resolve glob on remote host — never inject svc name into the command
                    glob_out = await self._run(
                        f"ls {log_path} 2>/dev/null | head -10",
                        phase=4, timeout=10,
                    )
                    candidates = [p.strip() for p in glob_out.splitlines() if p.strip()]
                else:
                    candidates = [log_path]

                for path in candidates:
                    # Dedup is handled inside _download_varlog_file via self._seen_log_paths
                    await self._download_varlog_file(path, phase=4)

    async def _download_varlog_file(self, remote_path: str, phase: int) -> None:
        """Download a /var/log file into the evidence store.

        Uses self._seen_log_paths to skip files already downloaded by any
        other collection method in this session.

        When a root channel is active (_run runs as root) a single tail call
        is sufficient.  Without root, sudo -n (NOPASSWD) is tried before the
        unprivileged fallback.  Only if all attempts return empty output AND
        the file exists is the failure logged as a limitation.
        """
        if remote_path in self._seen_log_paths:
            return
        self._seen_log_paths.add(remote_path)

        # gzip-compressed rotated files must be decompressed before tailing.
        if remote_path.endswith(".gz"):
            base_cmd = f"zcat {remote_path} 2>/dev/null | tail -n {_MAX_COMMAND_OUTPUT}"
        else:
            base_cmd = f"tail -n {_MAX_COMMAND_OUTPUT} {remote_path} 2>/dev/null"

        if self._root_channel is not None:
            # Root channel active: _run already executes as root.
            out = await self._run(base_cmd, phase=phase, timeout=_TIMEOUT_LARGE)
            methods_tried = "root channel (su)"
        else:
            # No root: try sudo -n then unprivileged.
            out = await self._run(
                f"sudo -n {base_cmd}", phase=phase, timeout=_TIMEOUT_LARGE
            )
            if not out.strip():
                out = await self._run(base_cmd, phase=phase, timeout=_TIMEOUT_LARGE)
            ssh_root_note = "" if self._root_pass else " (SSH_ROOT_PASS not set)"
            methods_tried = f"su root{ssh_root_note} failed → sudo -n → unprivileged"

        if out.strip():
            filename = remote_path.lstrip("/").replace("/", "_")
            self._write_log(filename, out, phase=phase, convert_to_json=True)
        else:
            # Only log as a limitation when the file exists AND has content
            # (test -s = exists with size > 0).  Empty files (0 bytes) are
            # silently skipped — there is nothing to collect from them.
            has_content = await self._run(
                f"test -s {remote_path} && echo yes 2>/dev/null",
                phase=phase, timeout=10,
            )
            if has_content.strip() == "yes":
                self.acq_log["errors"].append({
                    "phase": phase,
                    "cmd": f"read {remote_path}",
                    "error": (
                        f"permission denied — file has content but could not be read "
                        f"(tried: {methods_tried})"
                    ),
                })

    def _load_detected_services(self) -> list[str]:
        """Read service names written by Phase 2 (services_inventory.json)."""
        services_path = self.job.raw("services_inventory.json")
        if not services_path.exists():
            return []
        try:
            with open(services_path, encoding="utf-8") as fh:
                data = json.load(fh)
            names: list[str] = []
            for item in data.get("parsed", []):
                unit = item.get("unit", "")
                if unit.endswith(".service"):
                    names.append(unit[:-8])
            return names
        except Exception:
            return []

    async def _collect_rotated_logs(self) -> None:
        """Collect rotated copies of the key syslog files for extended time coverage.

        Linux log rotation produces versioned copies alongside the active file:
          CentOS/RHEL  — /var/log/secure-20260407, secure-20260407.gz
          Debian/Ubuntu — /var/log/auth.log.1, auth.log.2.gz, auth.log.3.gz

        For each base path in _FALLBACK_LOG_FILES, we list date-suffixed and
        numbered variants on the remote host, validate each path, then delegate
        to _download_varlog_file (which handles deduplication and .gz via zcat).
        """
        for base_path in _FALLBACK_LOG_FILES:
            # One ls command tries both rotation conventions in a single round-trip.
            # head -60 caps at 60 rotated files per base log (≈ 2 months weekly).
            list_cmd = (
                f"ls -t {base_path}-* {base_path}.[0-9]* {base_path}.[0-9]*.gz"
                f" 2>/dev/null | head -60"
            )
            if self._root_channel is not None:
                raw = await self._run(list_cmd, phase=4, timeout=15)
            else:
                raw = await self._run(
                    f"sudo -n {list_cmd} || {list_cmd}",
                    phase=4, timeout=15,
                )
            for line in raw.splitlines():
                path = line.strip()
                if path and _is_safe_log_path(path):
                    await self._download_varlog_file(path, phase=4)

    async def _collect_log_sweep(self) -> None:
        """Discover and download every *.log file across all standard log directories.

        Searches the following directory trees (not just /var/log/):
          /var/log      — system and most service logs
          /var/opt      — Remi PHP-FPM, other vendor packages
          /opt          — third-party application logs
          /srv          — service-data logs
          /var/www      — web application logs alongside document roots

        Runs *after* all targeted collectors so files already downloaded are
        skipped via self._seen_log_paths.  Paths returned by find(1) are
        validated against a strict allowlist before use to prevent any
        command-injection vector.

        When MAX_LOG_FILES=0 (default) all found files are collected.
        Set MAX_LOG_FILES=N in .env to cap at N files.
        """
        search_dirs = "/var/log /var/opt /opt /srv /var/www"
        # -size +0c skips empty files (0 bytes) — nothing to collect from them.
        # Patterns:
        #   *.log          — standard log files
        #   *.log.[0-9]*   — Debian numbered rotation (auth.log.1, auth.log.2.gz)
        #   *.log.gz       — compressed rotation without number
        find_cmd = (
            f"find {search_dirs} -type f -size +0c \\( "
            f"-name '*.log' -o -name '*.log.[0-9]*' -o -name '*.log.gz' "
            f"\\) 2>/dev/null"
        )

        if self._root_channel is not None:
            raw = await self._run(find_cmd, phase=4, timeout=120)
        else:
            raw = await self._run(
                f"sudo -n {find_cmd} || {find_cmd}",
                phase=4, timeout=120,
            )
        if not raw.strip():
            return

        candidates = []
        for line in raw.splitlines():
            path = line.strip()
            if _is_safe_log_path(path):
                candidates.append(path)
            # silently skip any path that doesn't pass validation

        cap = config.MAX_LOG_FILES_SWEEP
        target = candidates if cap == 0 else candidates[:cap]
        for path in target:
            await self._download_varlog_file(path, phase=4)

    async def _collect_kernel_logs(self) -> None:
        """dmesg — kernel ring buffer (recent, no time filter)."""
        out = await self._run("dmesg --since=\"72 hours ago\" 2>/dev/null || dmesg 2>/dev/null | tail -n 1000", phase=4, timeout=30)
        if out.strip():
            self._write_log("dmesg.txt", out, phase=4, convert_to_json=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_as_root(self, cmd: str, phase: int, timeout: int = _TIMEOUT_DEFAULT) -> str:
        """Execute *cmd* as root via 'su root', using a PTY so that PAM can
        present the password prompt without requiring an interactive terminal.

        Only called when SSH_ROOT_PASS is configured.  Falls back silently to
        an empty string on any failure so callers can try unprivileged methods.

        Output is cleaned of PTY line-ending artefacts (\\r characters).
        Authentication failures from su itself are detected and suppressed.
        """
        if not self._root_pass:
            return ""

        # Escape backslashes and double-quotes so the command can be safely
        # embedded inside the double-quoted su -c "..." argument.
        escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
        su_cmd = f'su -c "{escaped}" root'

        try:
            async with self.conn.create_process(
                su_cmd,
                request_pty=True,
                term_type="dumb",
            ) as proc:
                # Wait for su's "Password:" prompt then send the root password.
                buf = ""
                try:
                    while "assword" not in buf:
                        chunk = await asyncio.wait_for(proc.stdout.read(256), timeout=8)
                        if not chunk:
                            break
                        buf += chunk
                except asyncio.TimeoutError:
                    pass  # some systems skip the prompt when stdin is a PTY

                proc.stdin.write(self._root_pass + "\n")

                # Collect command output until the process exits (EOF).
                parts: list[str] = []
                try:
                    while True:
                        chunk = await asyncio.wait_for(
                            proc.stdout.read(65536), timeout=timeout
                        )
                        if not chunk:
                            break
                        parts.append(chunk)
                except asyncio.TimeoutError:
                    self.acq_log["errors"].append(
                        {"phase": phase, "cmd": cmd[:80],
                         "error": f"su root timeout after {timeout}s"}
                    )

            out = "".join(parts)
            # Clean PTY line endings.
            out = out.replace("\r\n", "\n").replace("\r", "")

            # Detect su authentication failure — these strings appear in the
            # PTY output when su rejects the password.
            lower = out.lower()
            if any(s in lower for s in ("authentication failure", "incorrect password",
                                         "su: auth", "sorry")):
                return ""

            return out

        except Exception as exc:
            self.acq_log["errors"].append(
                {"phase": phase, "cmd": cmd[:80],
                 "error": f"su root error: {str(exc)[:200]}"}
            )
            return ""

    async def _run(self, cmd: str, phase: int, timeout: int = _TIMEOUT_DEFAULT) -> str:
        """Execute *cmd* remotely.

        When a persistent root channel is active (SSH_ROOT_PASS configured and
        su succeeded), the command runs as root via the channel.  Otherwise it
        executes as the SSH login user.  Never raises.
        """
        if self._root_channel is not None:
            out = await self._root_channel.run(cmd, timeout=timeout)
            if out is not None:
                return out
            # Root channel died unexpectedly — fall through to normal execution.

        try:
            result = await asyncio.wait_for(
                self.conn.run(cmd, check=False),
                timeout=timeout,
            )
            return result.stdout or ""
        except asyncio.TimeoutError:
            self.acq_log["errors"].append(
                {"phase": phase, "cmd": cmd[:80], "error": f"timeout after {timeout}s"}
            )
            return ""
        except Exception as exc:
            self.acq_log["errors"].append(
                {"phase": phase, "cmd": cmd[:80], "error": str(exc)[:256]}
            )
            return ""

    def _write_json(self, filename: str, data: dict, phase: int) -> None:
        path = self.job.raw(filename)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        self._register(filename, phase)

    def _write_text(self, filename: str, content: str, phase: int) -> None:
        if not content.strip():
            return
        path = self.job.raw(filename)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        self._register(filename, phase)

    def _write_log(self, filename: str, content: str, phase: int, convert_to_json: bool = False) -> None:
        if not content.strip():
            return

        # Convert to JSON if requested and content looks like text logs
        if convert_to_json and not filename.endswith('.json.gz'):
            # Check if this looks like a log file (has multiple lines or timestamps)
            lines = content.splitlines()
            if len(lines) > 1 or re.search(r'\d{4}-\d{2}-\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', content):
                source_file = str(self.job.log_file(filename))
                content = _convert_text_logs_to_json(content, source_file, self._hostname)
                # Change extension to indicate JSON format
                if filename.endswith('.gz'):
                    filename = filename.replace('.gz', '.jsonl.gz')
                else:
                    new_name = filename.replace('.log', '.jsonl').replace('.txt', '.jsonl')
                    # For extensionless files (e.g. var_log_secure, var_log_cron)
                    # the replacements above are no-ops — append .jsonl explicitly.
                    filename = new_name if new_name != filename else filename + '.jsonl'

        path = self.job.log_file(filename)
        if config.COMPRESS_LOGS and not filename.endswith(".gz"):
            path = self.job.log_file(filename + ".gz")
            with gzip.open(path, "wt", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
        else:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
        self._register(str(path.relative_to(self.job.raw_dir)), phase)

    def _register(self, filename: str, phase: int) -> None:
        self.acq_log["artifacts"].append(
            {
                "phase": phase,
                "file": filename,
                "acquired_at": datetime.now(timezone.utc).isoformat(),
            }
        )


# ------------------------------------------------------------------
# Path validation
# ------------------------------------------------------------------

# Allowlist for paths returned by find(1) on the remote server.
# Covers all directory trees searched by _collect_log_sweep.
# Only ASCII alphanumeric characters plus the small set of punctuation
# that legitimately appears in log paths are accepted.  This prevents
# any command-injection vector through find output before the path is
# embedded in a shell command inside _download_varlog_file.
_SAFE_LOG_RE = re.compile(
    r"^(?:/var/log|/var/opt|/opt|/srv|/var/www)"
    r"/[a-zA-Z0-9_./@+\-]+$"
)


def _is_safe_log_path(path: str) -> bool:
    """Return True only if *path* is safe to embed in a remote shell command.

    Rules:
    - Must start with one of the allowed directory trees
    - Must not contain '..' (directory traversal)
    - Must match the strict character allowlist
    - Maximum length 512 characters
    """
    if len(path) > 512:
        return False
    if ".." in path:
        return False
    return bool(_SAFE_LOG_RE.match(path))


# Keep old name as alias so any external callers are not broken.
_is_safe_varlog_path = _is_safe_log_path
_SAFE_VARLOG_RE = _SAFE_LOG_RE


# ------------------------------------------------------------------
# Parsers (no eval, pure string processing)
# ------------------------------------------------------------------

def _parse_systemctl_list(raw: str) -> list[dict]:
    """Parse 'systemctl list-units --plain' output into structured list.

    systemctl appends a footer block separated by a blank line:
        LOAD   = Reflects whether the unit definition was properly loaded.
        ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
        SUB    = The low-level unit activation state, values depend on unit type.

        24 loaded units listed.  Pass --all to see ...
        To show all installed unit files use 'systemctl list-unit-files'.

    We stop as soon as we hit a blank line *after* having parsed at least one
    service, which is the blank line that precedes that footer.  We also
    require the first token to contain a '.' so that stray header/footer words
    (LOAD, ACTIVE, SUB, …) are never treated as unit names.
    """
    services = []
    for line in raw.splitlines():
        stripped = line.strip()
        # A blank line after the service list marks the start of the footer.
        if not stripped:
            if services:
                break
            continue
        # Skip the column header row and any "Legend" line.
        if stripped.startswith("UNIT") or stripped.startswith("Legend"):
            continue
        parts = stripped.split(None, 4)
        if len(parts) < 3:
            continue
        unit = parts[0]
        # Unit names always contain a '.' (e.g. sshd.service, dbus.socket).
        # Reject bare words that are footer artefacts.
        if "." not in unit:
            continue
        services.append(
            {
                "unit": unit[:128],
                "load": parts[1] if len(parts) > 1 else "",
                "active": parts[2] if len(parts) > 2 else "",
                "sub": parts[3] if len(parts) > 3 else "",
                "description": parts[4][:256] if len(parts) > 4 else "",
            }
        )
    return services
