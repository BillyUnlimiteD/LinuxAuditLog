"""
SystemDetector — Phase 1 of Stage A.

Runs minimal read-only commands on the remote host to identify:
  - OS distribution
  - Kernel + architecture
  - Init system (systemd / openrc / sysvinit / unknown)
  - Host datetime (UTC) and timezone
  - Hostname

All remote command output is treated as untrusted data.
No command is constructed from remote output.
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncssh

import config
from core.job import JobContext


# Maximum bytes read from any single remote command to prevent memory exhaustion.
_MAX_OUTPUT_BYTES = 64 * 1024  # 64 KB


class SystemDetector:
    def __init__(self, conn: "asyncssh.SSHClientConnection", job: JobContext, acq_log: dict) -> None:
        self.conn = conn
        self.job = job
        self.acq_log = acq_log

    async def detect(self) -> dict:
        info: dict = {
            "hostname": "unknown",
            "distro_id": "unknown",
            "distro_name": "unknown",
            "version_id": "unknown",
            "kernel": "unknown",
            "architecture": "unknown",
            "init_system": "unknown",
            "host_datetime_utc": "unknown",
            "timezone": "unknown",
            "raw_uname": "unknown",
        }

        # --- hostname ---
        out = await self._run("hostname", timeout=10)
        if out:
            info["hostname"] = out.strip().splitlines()[0][:128]

        # --- OS release ---
        for path in ["/etc/os-release", "/usr/lib/os-release"]:
            out = await self._run(f"cat {path} 2>/dev/null", timeout=10)
            if out:
                parsed = _parse_os_release(out)
                info.update(parsed)
                break

        # --- kernel + arch ---
        uname = await self._run("uname -r 2>/dev/null", timeout=10)
        if uname:
            info["kernel"] = uname.strip()
        arch = await self._run("uname -m 2>/dev/null", timeout=10)
        if arch:
            info["architecture"] = arch.strip()
        uname_a = await self._run("uname -a 2>/dev/null", timeout=10)
        if uname_a:
            info["raw_uname"] = uname_a.strip()

        # --- init system detection ---
        info["init_system"] = await self._detect_init()

        # --- host datetime ---
        dt_out = await self._run("date -u +\"%Y-%m-%dT%H:%M:%SZ\" 2>/dev/null", timeout=10)
        if dt_out:
            info["host_datetime_utc"] = dt_out.strip()

        # --- timezone ---
        tz_out = await self._run("cat /etc/timezone 2>/dev/null || timedatectl show --property=Timezone --value 2>/dev/null", timeout=10)
        if tz_out:
            info["timezone"] = tz_out.strip().splitlines()[0][:64]

        # Persist to disk
        out_path = self.job.raw("system_info.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(info, fh, indent=2, ensure_ascii=False)

        self.acq_log["commands"].append(
            {"phase": 1, "artifact": "system_info.json", "status": "ok"}
        )
        return info

    # ------------------------------------------------------------------
    # Init system detection
    # ------------------------------------------------------------------

    async def _detect_init(self) -> str:
        # systemd
        out = await self._run("systemctl --version 2>/dev/null | head -1", timeout=10)
        if out and "systemd" in out.lower():
            return "systemd"

        # OpenRC
        out = await self._run("rc-status --version 2>/dev/null", timeout=10)
        if out and "openrc" in out.lower():
            return "openrc"

        # Check PID 1
        out = await self._run("cat /proc/1/comm 2>/dev/null", timeout=10)
        if out:
            comm = out.strip().lower()
            if "systemd" in comm:
                return "systemd"
            if "openrc" in comm:
                return "openrc"
            if "runit" in comm:
                return "runit"
            if "s6" in comm:
                return "s6"
            if "init" in comm or "sysvinit" in comm:
                return "sysvinit"

        # Last resort: check for upstart
        out = await self._run("initctl --version 2>/dev/null | head -1", timeout=10)
        if out and "upstart" in out.lower():
            return "upstart"

        return "sysvinit"  # safe fallback

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run(self, cmd: str, timeout: int = 30) -> str:
        """Execute *cmd* on the remote host. Returns stdout or empty string on failure.
        Never raises; errors are recorded in acq_log.
        """
        import asyncio

        try:
            result = await asyncio.wait_for(
                self.conn.run(cmd, check=False),
                timeout=timeout,
            )
            stdout = result.stdout or ""
            # Limit output size
            if len(stdout) > _MAX_OUTPUT_BYTES:
                stdout = stdout[:_MAX_OUTPUT_BYTES]
            return stdout
        except Exception as exc:
            self.acq_log["errors"].append(
                {"phase": 1, "cmd": cmd[:80], "error": str(exc)[:256]}
            )
            return ""


# ------------------------------------------------------------------
# OS release parser (no eval, pure string parsing)
# ------------------------------------------------------------------

def _parse_os_release(raw: str) -> dict:
    """Parse /etc/os-release key=value format. Values may be quoted."""
    result: dict = {}
    mapping = {
        "ID": "distro_id",
        "NAME": "distro_name",
        "PRETTY_NAME": "distro_name",
        "VERSION_ID": "version_id",
        "VERSION": "version",
    }
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key in mapping:
            result[mapping[key]] = value[:256]
    return result
