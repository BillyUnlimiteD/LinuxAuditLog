"""
PromptReportBuilder — generates the AI-assist prompts report.

For each finding in the forensic report, produces a ready-to-paste
prompt that includes full system context, detected events and a
structured help request for any LLM (Claude, ChatGPT, Gemini, etc.).

Output: ai_prompts_<job_id>.md  (and its PDF via PDFScriptGenerator)
"""
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

import config
from core.job import JobContext
from stage_b.ioc_engine import Finding


class PromptReportBuilder:
    def __init__(self, job: JobContext) -> None:
        self.job = job
        self._env = Environment(
            loader=FileSystemLoader(str(config.TEMPLATES_DIR)),
            undefined=StrictUndefined,
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.filters["fmt_bytes"] = lambda n: f"{n} B"
        self._env.filters["severity_badge"] = lambda s: s.upper()
        self._env.filters["short_hash"] = lambda h: (h[:16] + "...") if h and len(h) > 16 else h
        self._env.filters["short_ts"] = lambda ts: (str(ts)[:16].replace("T", " ") if ts and len(str(ts)) >= 16 else (ts or "N/A"))
        self._env.filters["strip_log_prefix"] = lambda f: re.sub(r"^var_log_", "", str(f))
        _conf = {"high": "Alta", "medium": "Media", "low": "Baja"}
        _stat = {"open": "Abierto", "closed": "Cerrado", "false_positive": "Falso positivo"}
        _tact = {
            "initial_access": "Acceso inicial", "execution": "Ejecución",
            "persistence": "Persistencia", "privilege_escalation": "Escalada de privilegios",
            "defense_evasion": "Evasión de defensas", "credential_access": "Acceso a credenciales",
            "discovery": "Descubrimiento", "lateral_movement": "Movimiento lateral",
            "collection": "Recolección", "command_and_control": "Mando y control",
            "exfiltration": "Exfiltración", "impact": "Impacto",
            "reconnaissance": "Reconocimiento",
        }
        self._env.filters["es_confidence"] = lambda v: _conf.get(str(v).lower(), str(v).capitalize())
        self._env.filters["es_status"] = lambda v: _stat.get(str(v).lower(), str(v))
        self._env.filters["es_tactic"] = lambda v: _tact.get(str(v).lower(), str(v).replace("_", " ").capitalize())

    def build(
        self,
        system_info: dict,
        findings: list[Finding],
        report_metadata: dict,
    ) -> Path:
        context = {
            "job": self.job.to_dict(),
            "system_info": system_info,
            "findings": [f.to_dict() for f in findings],
            "report_metadata": report_metadata,
        }

        lang = config.LANGUAGE.lower()
        tpl_name = f"prompts.{lang}.md.j2"
        try:
            template = self._env.get_template(tpl_name)
        except Exception:
            template = self._env.get_template("prompts.es.md.j2")
        rendered = template.render(**context)

        out_path = self.job.report(f"ai_prompts_{self.job.job_id}.md")
        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered)

        return out_path
