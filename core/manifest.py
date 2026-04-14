"""
ManifestBuilder — hashes all artifacts in the evidence directory and produces:
    01_evidence/MANIFEST.json      — full artifact inventory
    01_evidence/MANIFEST.sig.json  — hash of the manifest itself (chain of custody)
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.job import JobContext
import config


class ManifestBuilder:
    def __init__(self, job: JobContext) -> None:
        self.job = job
        self.artifacts: list[dict] = []
        self._manifest_hash: Optional[str] = None

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build_from_directory(self, directory: Path) -> "ManifestBuilder":
        """Walk *directory* recursively and register every file."""
        self.artifacts = []
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            sha256 = self._hash_file(path)
            rel = path.relative_to(self.job.job_dir)
            self.artifacts.append(
                {
                    "filename": path.name,
                    "relative_path": str(rel).replace("\\", "/"),
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256,
                    "acquired_at": datetime.now(timezone.utc).isoformat(),
                    "origin": "remote_acquisition",
                    "verified_locally": True,
                }
            )
        return self

    def save(self) -> Path:
        """Write MANIFEST.json and MANIFEST.sig.json. Returns manifest path."""
        manifest = {
            "job_id": self.job.job_id,
            "host": self.job.host,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": f"{config.TOOL_NAME} v{config.TOOL_VERSION}",
            "artifact_count": len(self.artifacts),
            "total_size_bytes": sum(a["size_bytes"] for a in self.artifacts),
            "artifacts": self.artifacts,
        }

        manifest_path = self.job.manifest_path()
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False)

        # Sign the manifest file itself
        self._manifest_hash = self._hash_file(manifest_path)
        signature = {
            "manifest_file": manifest_path.name,
            "manifest_sha256": self._manifest_hash,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "tool": f"{config.TOOL_NAME} v{config.TOOL_VERSION}",
        }
        with open(self.job.manifest_sig_path(), "w", encoding="utf-8") as fh:
            json.dump(signature, fh, indent=2, ensure_ascii=False)

        return manifest_path

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> dict:
        """Re-hash all registered artifacts and compare. Returns verification report."""
        results = {"passed": [], "failed": [], "missing": []}
        for artifact in self.artifacts:
            path = self.job.job_dir / artifact["relative_path"].replace("/", "\\")
            if not path.exists():
                results["missing"].append(artifact["filename"])
                continue
            current_hash = self._hash_file(path)
            if current_hash == artifact["sha256"]:
                results["passed"].append(artifact["filename"])
            else:
                results["failed"].append(
                    {
                        "filename": artifact["filename"],
                        "expected": artifact["sha256"],
                        "actual": current_hash,
                    }
                )
        return results

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def manifest_hash(self) -> Optional[str]:
        return self._manifest_hash

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
