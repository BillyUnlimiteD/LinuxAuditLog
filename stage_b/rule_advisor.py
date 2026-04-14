"""
RuleAdvisor — Stage B, pre-IOC step.

After Stage A closes and services inventory is available, this module:
  1. Parses the detected service list from services_inventory.json
  2. Maps each detected service to known rule files in rules/
  3. Reports coverage gaps (services with no rules)
  4. Creates a placeholder rule stub for unknown services so the
     operator can add patterns later via the update_rules.py workflow

This ensures that every detected service is at minimum acknowledged
in the analysis, even if rules must be added manually afterward.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

import config
from core.job import JobContext


# ------------------------------------------------------------------
# Known service → rule file mappings
# Paths are relative to config.RULES_DIR
# ------------------------------------------------------------------

_SERVICE_RULES: dict[str, list[str]] = {
    # SSH
    "sshd": [
        "linux/auth/ssh_brute_force.yaml",
        "linux/auth/ssh_success_from_new_ip.yaml",
        "linux/auth/failed_logins_spike.yaml",
    ],
    # Privilege / auth
    "sudo": ["linux/auth/sudo_abuse.yaml"],
    "su": ["linux/auth/privilege_escalation.yaml"],
    "cron": ["linux/process/cron_abuse.yaml"],
    "crond": ["linux/process/cron_abuse.yaml"],
    "atd": ["linux/process/cron_abuse.yaml"],
    # Web servers
    "nginx": ["services/nginx.yaml", "web/sqli.yaml", "web/path_traversal.yaml",
               "web/lfi_rfi.yaml", "web/rce.yaml", "web/ssrf.yaml",
               "web/web_scanning.yaml", "web/xss.yaml"],
    "apache2": ["services/apache2.yaml", "web/sqli.yaml", "web/path_traversal.yaml",
                 "web/lfi_rfi.yaml", "web/rce.yaml", "web/ssrf.yaml",
                 "web/web_scanning.yaml", "web/xss.yaml"],
    "httpd": ["services/httpd.yaml", "web/sqli.yaml", "web/path_traversal.yaml",
               "web/lfi_rfi.yaml", "web/rce.yaml", "web/ssrf.yaml",
               "web/web_scanning.yaml", "web/xss.yaml"],
    "lighttpd": ["web/sqli.yaml", "web/path_traversal.yaml", "web/web_scanning.yaml"],
    "caddy": ["web/sqli.yaml", "web/path_traversal.yaml", "web/web_scanning.yaml"],
    # Databases
    "mysql": ["services/mysql.yaml"],
    "mysqld": ["services/mysql.yaml"],
    "mysqld_safe": ["services/mysql.yaml"],
    "mariadb": ["services/mysql.yaml"],
    "mariadbd": ["services/mysql.yaml"],
    "postgresql": ["services/postgresql.yaml"],
    "postgres": ["services/postgresql.yaml"],
    "mongod": ["services/mongodb.yaml"],
    "redis-server": ["services/redis.yaml"],
    "redis": ["services/redis.yaml"],
    "elasticsearch": ["services/elasticsearch.yaml"],
    "opensearch": ["services/elasticsearch.yaml"],
    # Mail
    "postfix": ["services/postfix.yaml"],
    "master": ["services/postfix.yaml"],  # postfix master process
    "dovecot": ["services/dovecot.yaml"],
    "sendmail": ["services/sendmail.yaml"],
    "sm-client": ["services/sendmail.yaml"],
    "exim": ["services/postfix.yaml"],
    # Containers / orchestration
    "docker": ["services/docker.yaml"],
    "dockerd": ["services/docker.yaml"],
    "containerd": ["services/docker.yaml"],
    "kubelet": ["services/kubernetes.yaml"],
    # File sharing
    "smbd": ["services/samba.yaml"],
    "nmbd": ["services/samba.yaml"],
    "vsftpd": ["services/vsftpd.yaml"],
    "proftpd": ["services/ftp.yaml"],
    "pure-ftpd": ["services/ftp.yaml"],
    # PHP-FPM (versioned names from Remi's repo on CentOS/RHEL)
    "php-fpm": ["services/php-fpm.yaml"],
    "php56-php-fpm": ["services/php-fpm.yaml"],
    "php70-php-fpm": ["services/php-fpm.yaml"],
    "php74-php-fpm": ["services/php-fpm.yaml"],
    "php80-php-fpm": ["services/php-fpm.yaml"],
    "php81-php-fpm": ["services/php-fpm.yaml"],
    "php82-php-fpm": ["services/php-fpm.yaml"],
    # Monitoring / security
    "zabbix-agent": ["services/zabbix.yaml"],
    "zabbix-agent2": ["services/zabbix.yaml"],
    "clamd": ["services/clamav.yaml"],
    "clamav-daemon": ["services/clamav.yaml"],
    "freshclam": ["services/clamav.yaml"],
    "clamav-freshclam": ["services/clamav.yaml"],
    # Package management (not a daemon but log is security-relevant)
    "yum": ["services/yum.yaml"],
    "dnf": ["services/yum.yaml"],
    # Other
    "memcached": ["services/memcached.yaml"],
    "rabbitmq": ["services/rabbitmq.yaml"],
    "haproxy": ["services/haproxy.yaml"],
    "varnish": ["services/varnish.yaml"],
    "fail2ban": [],  # monitoring — no rules needed
    "ufw": [],       # firewall — no rules needed
    "firewalld": [], # firewall — no rules needed
    "systemd": [],   # init — no rules needed
    "dbus": ["services/dbus.yaml"],
    "rsyslog": ["services/rsyslog.yaml"],
    "syslog-ng": [],
    "auditd": [],
    # System services with security-relevant rules
    "networkmanager": ["services/networkmanager.yaml"],
    "chronyd": ["services/chronyd.yaml"],
    "irqbalance": ["services/irqbalance.yaml"],
    "polkit": ["services/polkit.yaml"],
    "tuned": ["services/tuned.yaml"],
    "getty@tty1": ["services/getty@tty1.yaml"],
    "glassfish": ["services/glassfish.yaml"],
    "netdata": ["services/netdata.yaml"],
    "timedatex": ["services/timedatex.yaml"],
    "user@1000": ["services/user@1000.yaml"],
    "user@1001": ["services/user@1001.yaml"],
    "abrtd": ["services/abrtd.yaml"],
    "qpidd": ["services/qpidd.yaml"],
    "fcoemon": ["services/fcoemon.yaml"],
    "avahi-daemon": ["services/avahi-daemon.yaml"],
    "hald": ["services/hald.yaml"],
    "abrt-oops": ["services/abrt-oops.yaml"],
    "gssproxy": ["services/gssproxy.yaml"],
    "libvirtd": ["services/libvirtd.yaml"],
    "rpcbind": ["services/rpcbind.yaml"],
    # Infrastructure — no security rules applicable
    "lvm2-lvmetad": [],
    "sm-client": ["services/sendmail.yaml"],
    "smb": ["services/samba.yaml"],
}

# Services that are infrastructure (no security rules make sense)
_INFRASTRUCTURE_SERVICES = {
    "systemd", "dbus-daemon", "udev", "rsyslogd", "syslog-ng",
    "networkd", "resolved", "journald", "logind", "timesync",
    "kworker", "ksoftirqd", "irq/", "rcu_", "migration/",
    "auditd", "fail2ban", "ufw", "firewalld",
}


class RuleAdvisor:
    def __init__(self, job: JobContext) -> None:
        self.job = job
        self.rules_dir = config.RULES_DIR
        self._coverage_report: dict = {
            "detected_services": [],
            "services_with_rules": [],
            "services_without_rules": [],
            "placeholder_rules_created": [],
            "total_applicable_rules": 0,
        }

    def advise(self) -> dict:
        """Analyze services inventory and ensure rule coverage. Returns coverage report."""
        services = self._load_services()
        if not services:
            return self._coverage_report

        self._coverage_report["detected_services"] = services

        for service in services:
            # Normalize service name
            svc_name = self._normalize_service_name(service)

            if self._is_infrastructure(svc_name):
                continue

            known_rules = self._find_known_rules(svc_name)
            existing_rules = [r for r in known_rules if (self.rules_dir / r).exists()]

            if existing_rules:
                self._coverage_report["services_with_rules"].append({
                    "service": svc_name,
                    "rules": existing_rules,
                })
                self._coverage_report["total_applicable_rules"] += len(existing_rules)
            else:
                self._coverage_report["services_without_rules"].append(svc_name)
                # Create a placeholder stub so operator knows to add rules
                stub_path = self._create_stub_rule(svc_name)
                if stub_path:
                    self._coverage_report["placeholder_rules_created"].append({
                        "service": svc_name,
                        "stub_path": str(stub_path.relative_to(self.rules_dir)),
                    })

        # Save coverage report
        out_path = self.job.analysis("rule_coverage.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(self._coverage_report, fh, indent=2, ensure_ascii=False)

        return self._coverage_report

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    # Commands/process names from ps that are never services
    _PS_IGNORE = {
        "bash", "sh", "-bash", "zsh", "fish", "dash",
        "ps", "head", "tail", "grep", "awk", "sed", "cat", "ls", "find",
        "python", "python2", "python3", "perl", "ruby", "node",
        "systemd", "init", "kthreadd",
    }

    def _load_services(self) -> list[str]:
        """Extract service names from services_inventory.json."""
        services_path = self.job.raw("services_inventory.json")
        if not services_path.exists():
            return []

        try:
            with open(services_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []

        service_names = []

        # Primary source: systemctl parsed list (authoritative, no noise)
        for item in data.get("parsed", []):
            unit = item.get("unit", "")
            if unit.endswith(".service"):
                service_names.append(unit[:-8])

        # Supplement with ps ONLY when systemctl returned nothing (non-systemd hosts)
        if not service_names:
            raw_ps = data.get("raw_ps", "")
            for line in (raw_ps or "").splitlines():
                parts = line.split()
                if len(parts) < 11:
                    continue
                raw_cmd = parts[10]
                if raw_cmd.startswith("["):
                    continue                          # kernel thread: [kworker/0:0H]
                cmd = raw_cmd.lstrip("/").split("/")[-1].rstrip(":")
                if not cmd or len(cmd) < 2:
                    continue
                if cmd.startswith("-") or "]" in cmd:
                    continue                          # -bash, residues like 0:0H]
                if cmd.lower() in self._PS_IGNORE:
                    continue
                service_names.append(cmd)

        # Deduplicate preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for s in service_names:
            key = s.lower().strip()
            if key and key not in seen:
                seen.add(key)
                unique.append(s)

        return unique

    def _normalize_service_name(self, name: str) -> str:
        """Normalize service name for rule lookup."""
        name = name.lower().strip()
        # Strip version numbers and common suffixes
        for suffix in ("-server", "-daemon", "d", "server"):
            if name.endswith(suffix) and len(name) > len(suffix) + 2:
                base = name[: -len(suffix)]
                if base in _SERVICE_RULES:
                    return base
        return name

    def _is_infrastructure(self, name: str) -> bool:
        for infra in _INFRASTRUCTURE_SERVICES:
            if infra in name:
                return True
        return False

    def _find_known_rules(self, service: str) -> list[str]:
        """Return list of known rule paths for a service."""
        # Direct match
        if service in _SERVICE_RULES:
            return _SERVICE_RULES[service]

        # Partial match (e.g., "postgres" matches "postgresql")
        for known, rules in _SERVICE_RULES.items():
            if known in service or service in known:
                return rules

        # Fallback: if a service-specific rule file exists, use it.
        candidate = self.rules_dir / "services" / f"{service.lower()}.yaml"
        if candidate.exists():
            return [f"services/{service.lower()}.yaml"]

        return []

    def _create_stub_rule(self, service: str) -> Optional[Path]:
        """Create a disabled placeholder rule YAML for an unknown service."""
        stub_id = f"SVC-{service.upper()[:20].replace('-', '_')}-001"
        stub_path = self.rules_dir / "services" / f"{service.lower()[:32]}.yaml"

        # Don't overwrite existing rules
        if stub_path.exists():
            return None

        stub = {
            "id": stub_id,
            "title": f"{service} Security Monitoring (Auto-generated stub)",
            "category": "service",
            "subcategory": service.lower(),
            "mitre_technique": "T1190",
            "mitre_tactic": "initial_access",
            "severity": "medium",
            "confidence": "low",
            "enabled": False,
            "description": (
                f"Auto-generated stub rule for '{service}' service detected on the target host. "
                f"This rule was created because no existing rules cover this service. "
                f"Add detection patterns based on your knowledge of the application's log format. "
                f"Run 'python scripts/update_rules.py' to check for community Sigma rules."
            ),
            "service": service,
            "detection": {
                "type": "pattern",
                "patterns": [
                    {
                        "regex": "PLACEHOLDER_PATTERN",
                        "_note": (
                            f"Replace with actual regex patterns for {service} log anomalies. "
                            f"Check SigmaHQ for community rules: https://github.com/SigmaHQ/sigma/search?q={service}"
                        ),
                    }
                ],
            },
            "false_positives": ["Review before enabling"],
            "recommendation": (
                f"1. Review {service} log format and common attack patterns.\n"
                f"2. Add appropriate regex patterns to the 'detection.patterns' section.\n"
                f"3. Set 'enabled: true' once patterns are validated.\n"
                f"4. Run 'python scripts/update_rules.py' for community rule updates."
            ),
            "references": [
                f"https://github.com/SigmaHQ/sigma/search?q={service}",
            ],
            "tags": [f"service:{service}", "stub", "needs_review"],
            "_auto_generated": True,
            "_generated_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            stub_path.parent.mkdir(parents=True, exist_ok=True)
            with open(stub_path, "w", encoding="utf-8") as fh:
                yaml.dump(stub, fh, allow_unicode=True, sort_keys=False, default_flow_style=False)
            return stub_path
        except Exception:
            return None

    @property
    def coverage_report(self) -> dict:
        return self._coverage_report
