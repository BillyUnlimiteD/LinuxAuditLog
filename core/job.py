"""
JobContext — creates and owns the directory structure for a single acquisition job.

Layout:
    jobs/<YYYYMMDD_HHMMSS_host>/
        01_evidence/
            raw/
                logs/
            MANIFEST.json
            MANIFEST.sig.json
        02_analysis/
            normalized/
        03_report/
            report_<job_id>.md
            convert_to_pdf.sh
            convert_to_pdf.bat
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import config


@dataclass
class JobContext:
    host: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Set in __post_init__
    job_id: str = field(init=False)
    job_dir: Path = field(init=False)
    evidence_dir: Path = field(init=False)
    raw_dir: Path = field(init=False)
    logs_dir: Path = field(init=False)
    analysis_dir: Path = field(init=False)
    normalized_dir: Path = field(init=False)
    report_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        ts = self.started_at.strftime("%Y%m%d_%H%M%S")
        safe_host = self.host.replace(".", "_").replace(":", "_").replace("/", "_")
        self.job_id = f"{ts}_{safe_host}"

        self.job_dir = config.JOBS_DIR / self.job_id
        self.evidence_dir = self.job_dir / "01_evidence"
        self.raw_dir = self.evidence_dir / "raw"
        self.logs_dir = self.raw_dir / "logs"
        self.analysis_dir = self.job_dir / "02_analysis"
        self.normalized_dir = self.analysis_dir / "normalized"
        self.report_dir = self.job_dir / "03_report"

        for d in [self.logs_dir, self.normalized_dir, self.report_dir]:
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Convenience path helpers
    # ------------------------------------------------------------------

    def raw(self, filename: str) -> Path:
        return self.raw_dir / filename

    def log_file(self, filename: str) -> Path:
        return self.logs_dir / filename

    def analysis(self, filename: str) -> Path:
        return self.analysis_dir / filename

    def report(self, filename: str) -> Path:
        return self.report_dir / filename

    def report_md_path(self) -> Path:
        return self.report_dir / f"report_{self.job_id}.md"

    def manifest_path(self) -> Path:
        return self.evidence_dir / "MANIFEST.json"

    def manifest_sig_path(self) -> Path:
        return self.evidence_dir / "MANIFEST.sig.json"

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "host": self.host,
            "started_at": self.started_at.isoformat(),
            "job_dir": str(self.job_dir),
        }
