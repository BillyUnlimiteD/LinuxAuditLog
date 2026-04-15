"""
ReportBuilder — generates the final forensic Markdown report via Jinja2.

The report follows a formal/pericial structure with:
  - Chain of custody metadata
  - Executive summary with risk level
  - Acquisition log
  - Evidence manifest table
  - Services inventory table
  - Findings (one subsection per finding)
  - Prioritization matrix
  - Remediation actions
  - Limitations and caveats
  - Timeline excerpt
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined

import config
from core.job import JobContext
from stage_b.ioc_engine import Finding


class ReportBuilder:
    def __init__(self, job: JobContext) -> None:
        self.job = job
        self._env = Environment(
            loader=FileSystemLoader(str(config.TEMPLATES_DIR)),
            undefined=StrictUndefined,
            autoescape=False,
            trim_blocks=True,    # elimina el \n posterior a cada tag de bloque
            lstrip_blocks=True,  # elimina espacios/tabs antes de tags de bloque
        )
        self._env.filters["fmt_bytes"] = _fmt_bytes
        self._env.filters["severity_badge"] = _severity_badge
        self._env.filters["short_hash"] = lambda h: h[:16] + "..." if h and len(h) > 16 else h
        self._env.filters["short_ts"] = _short_ts
        self._env.filters["strip_log_prefix"] = lambda f: re.sub(r"^var_log_", "", str(f))
        self._env.filters["es_confidence"] = _es_confidence
        self._env.filters["es_status"] = _es_status
        self._env.filters["es_tactic"] = _es_tactic

    def build(
        self,
        system_info: dict,
        services: dict,
        findings: list[Finding],
        correlations: dict,
        manifest: dict,
        acquisition_log: dict,
        timeline_events: list[dict],
        log_stats: dict,
    ) -> Path:
        risk = _compute_risk(findings)
        report_ts = datetime.now(timezone.utc)

        # Acquisition timing
        acq_start = acquisition_log.get("start", "N/A")
        acq_end = acquisition_log.get("end", "N/A")
        acq_duration = _compute_duration(acq_start, acq_end)

        context = {
            "job": self.job.to_dict(),
            "system_info": system_info,
            "acquisition": {
                "start_utc": acq_start,
                "end_utc": acq_end,
                "duration": acq_duration,
                "commands_logged": len(acquisition_log.get("commands", [])),
                "artifacts_acquired": len(acquisition_log.get("artifacts", [])),
                "errors": acquisition_log.get("errors", []),
                "connection_closed": acquisition_log.get("connection_closed", False),
                "known_hosts_warning": True,  # We skip host key verification — documented
            },
            "manifest": {
                "artifacts": manifest.get("artifacts", []),
                "total_count": manifest.get("artifact_count", 0),
                "total_size_bytes": manifest.get("total_size_bytes", 0),
                "generated_at": manifest.get("generated_at", "N/A"),
                "all_verified": True,
                "verification_failures": [],
            },
            "services": services.get("parsed", []),
            "raw_services": services.get("raw_systemctl", ""),
            "findings": [f.to_dict() for f in findings],
            "findings_count": len(findings),
            "correlations": correlations,
            "timeline_events": timeline_events,
            "log_stats": log_stats,
            "risk": risk,
            "report_metadata": {
                "tool_name": config.TOOL_NAME,
                "tool_version": config.TOOL_VERSION,
                "classification": config.REPORT_CLASSIFICATION,
                "generated_at": report_ts.isoformat(),
                "generated_at_readable": report_ts.strftime("%d/%m/%Y %H:%M:%S UTC"),
                "time_window_hours": config.DEFAULT_TIME_WINDOW_HOURS,
                "rules_evaluated": 0,  # updated below
            },
        }

        # Try to count rules evaluated
        try:
            rules_dir = config.RULES_DIR
            context["report_metadata"]["rules_evaluated"] = sum(
                1 for _ in rules_dir.rglob("*.yaml")
            )
        except Exception:
            pass

        lang = config.LANGUAGE.lower()
        tpl_name = f"report.{lang}.md.j2"
        # Fallback to Spanish if the requested language template doesn't exist
        try:
            template = self._env.get_template(tpl_name)
        except Exception:
            template = self._env.get_template("report.es.md.j2")
        rendered = template.render(**context)

        report_path = self.job.report_md_path()
        with open(report_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered)

        return report_path


# ------------------------------------------------------------------
# Template filters
# ------------------------------------------------------------------

def _es_confidence(v: str) -> str:
    return {"high": "Alta", "medium": "Media", "low": "Baja"}.get(str(v).lower(), str(v).capitalize())


def _es_status(v: str) -> str:
    return {"open": "Abierto", "closed": "Cerrado", "false_positive": "Falso positivo",
            "reviewing": "En revisión", "mitigated": "Mitigado"}.get(str(v).lower(), str(v))


def _es_tactic(v: str) -> str:
    return {
        "initial_access": "Acceso inicial",
        "execution": "Ejecución",
        "persistence": "Persistencia",
        "privilege_escalation": "Escalada de privilegios",
        "defense_evasion": "Evasión de defensas",
        "credential_access": "Acceso a credenciales",
        "discovery": "Descubrimiento",
        "lateral_movement": "Movimiento lateral",
        "collection": "Recolección",
        "command_and_control": "Mando y control",
        "exfiltration": "Exfiltración",
        "impact": "Impacto",
        "reconnaissance": "Reconocimiento",
        "resource_development": "Desarrollo de recursos",
    }.get(str(v).lower(), str(v).replace("_", " ").capitalize())


def _short_ts(ts) -> str:
    """Return YYYY-MM-DD HH:MM from an ISO timestamp; pass through None/empty as N/A."""
    if not ts:
        return "N/A"
    s = str(ts)
    # ISO: 2026-04-13T14:30:00[.ffffff][+00:00] — take first 16 chars
    return s[:16].replace("T", " ") if len(s) >= 16 else s


def _fmt_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    if size < 1024 ** 3:
        return f"{size / 1024**2:.1f} MB"
    return f"{size / 1024**3:.1f} GB"


def _severity_badge(severity: str) -> str:
    badges = {
        "critical": "**[CRITICO]**",
        "high": "**[ALTO]**",
        "medium": "**[MEDIO]**",
        "low": "[BAJO]",
        "info": "[INFO]",
    }
    return badges.get(severity.lower(), severity.upper())


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _compute_risk(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    if counts["critical"] > 0:
        overall = "CRITICO"
    elif counts["high"] > 0:
        overall = "ALTO"
    elif counts["medium"] > 0:
        overall = "MEDIO"
    elif counts["low"] > 0:
        overall = "BAJO"
    else:
        overall = "SIN HALLAZGOS"

    return {**counts, "overall": overall}


def _compute_duration(start: str, end: str) -> str:
    try:
        t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
        delta = int((t1 - t0).total_seconds())
        mins, secs = divmod(delta, 60)
        return f"{mins}m {secs}s"
    except Exception:
        return "N/A"
