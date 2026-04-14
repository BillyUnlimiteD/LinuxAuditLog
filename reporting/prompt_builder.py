"""
PromptReportBuilder — generates the AI-assist prompts report.

For each finding in the forensic report, produces a ready-to-paste
prompt that includes full system context, detected events and a
structured help request for any LLM (Claude, ChatGPT, Gemini, etc.).

Output: ai_prompts_<job_id>.md  (and its PDF via PDFScriptGenerator)
"""
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
        )
        self._env.filters["fmt_bytes"] = lambda n: f"{n} B"
        self._env.filters["severity_badge"] = lambda s: s.upper()
        self._env.filters["short_hash"] = lambda h: (h[:16] + "...") if h and len(h) > 16 else h
        self._env.filters["short_ts"] = lambda ts: (str(ts)[:16].replace("T", " ") if ts and len(str(ts)) >= 16 else (ts or "N/A"))

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

        template = self._env.get_template("prompts.md.j2")
        rendered = template.render(**context)

        out_path = self.job.report(f"ai_prompts_{self.job.job_id}.md")
        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered)

        return out_path
