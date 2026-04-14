"""
TimelineBuilder — Stage B, step 4.

Produces a unified chronological timeline CSV from all log entries.
This is the primary artifact for manual forensic review.
"""
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from core.job import JobContext

_SEVERITY_ORDER = {"emerg": 0, "alert": 1, "crit": 2, "error": 3, "warn": 4,
                   "notice": 5, "info": 6, "debug": 7}


class TimelineBuilder:
    def __init__(self, job: JobContext) -> None:
        self.job = job
        self._top_events: list[dict] = []

    def build(self, entries: list[dict]) -> None:
        """Sort entries and write timeline CSV to analysis dir."""
        sorted_entries = sorted(entries, key=lambda e: e.get("ts_epoch", 0))

        csv_path = self.job.analysis("timeline_unified.csv")
        fields = ["timestamp", "ts_epoch", "hostname", "service", "pid", "level",
                  "src_ip", "user", "uri", "http_status", "message", "source_file"]

        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for entry in sorted_entries:
                extracted = entry.get("extracted", {})
                row = {
                    "timestamp": entry.get("timestamp", ""),
                    "ts_epoch": entry.get("ts_epoch", 0),
                    "hostname": entry.get("hostname", ""),
                    "service": entry.get("service", ""),
                    "pid": entry.get("pid", ""),
                    "level": entry.get("level", ""),
                    "src_ip": extracted.get("src_ip", ""),
                    "user": extracted.get("user", ""),
                    "uri": extracted.get("uri", "")[:256] if extracted.get("uri") else "",
                    "http_status": extracted.get("http_status", ""),
                    "message": entry.get("message", "")[:512],
                    "source_file": Path(entry.get("source_file", "")).name,
                }
                writer.writerow(row)

        # Keep top events (errors/warnings) for report summary
        self._top_events = [
            e for e in sorted_entries
            if _SEVERITY_ORDER.get(e.get("level", "info"), 99) <= 4  # warn and above
        ][:100]

    def get_top_events(self, limit: int = 50) -> list[dict]:
        """Return top severity events for report embedding."""
        result = []
        for e in self._top_events[:limit]:
            extracted = e.get("extracted", {})
            result.append({
                "timestamp": e.get("timestamp", "N/A"),
                "service": e.get("service", ""),
                "level": e.get("level", ""),
                "message": e.get("message", "")[:256],
                "src_ip": extracted.get("src_ip", ""),
                "user": extracted.get("user", ""),
            })
        return result
