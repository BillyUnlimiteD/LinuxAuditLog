"""
LogCorrelator — Stage B, step 3.

Uses DuckDB to run SQL queries over normalized log entries (JSONL file).
Produces correlation data grouped by IP, user, service, and time.
No remote connection is used here; all data is local.
"""
import json
from pathlib import Path
from typing import Any

try:
    import duckdb
    HAS_DUCKDB = True
except ImportError:
    HAS_DUCKDB = False

from core.job import JobContext


class LogCorrelator:
    def __init__(self, job: JobContext, entries: list[dict]) -> None:
        self.job = job
        self.entries = entries
        self._jsonl_path = job.analysis("all_entries.jsonl")
        self._conn = None

    def correlate(self) -> dict:
        """Run all correlation queries. Returns consolidated correlation dict."""
        if not HAS_DUCKDB:
            return self._correlate_pure_python()

        correlations: dict = {}

        try:
            self._conn = duckdb.connect()
            self._load_table()

            correlations["top_ips_by_activity"] = self._top_ips()
            correlations["top_users_by_events"] = self._top_users()
            correlations["events_by_service"] = self._by_service()
            correlations["events_by_level"] = self._by_level()
            correlations["errors_over_time"] = self._errors_over_time()
            correlations["auth_failures_by_ip"] = self._auth_failures_by_ip()
            correlations["suspicious_uris"] = self._suspicious_uris()
            correlations["http_status_distribution"] = self._http_status_dist()

        except Exception as exc:
            correlations["error"] = str(exc)
        finally:
            if self._conn:
                self._conn.close()

        # Persist
        out_path = self.job.analysis("correlations.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(correlations, fh, indent=2, ensure_ascii=False, default=str)

        return correlations

    # ------------------------------------------------------------------
    # DuckDB queries
    # ------------------------------------------------------------------

    def _load_table(self) -> None:
        if not self._jsonl_path.exists() or self._jsonl_path.stat().st_size == 0:
            # Create empty table from entries in memory
            self._conn.execute("CREATE TABLE logs AS SELECT * FROM (VALUES (NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) t(timestamp, ts_epoch, hostname, service, pid, level, message, source_file, raw, extracted) WHERE false")
            return
        self._conn.execute(f"CREATE TABLE logs AS SELECT * FROM read_json_auto('{str(self._jsonl_path).replace(chr(92), '/')}', ignore_errors=true)")

    def _query(self, sql: str) -> list[dict]:
        try:
            rel = self._conn.execute(sql)
            cols = [d[0] for d in rel.description]
            return [dict(zip(cols, row)) for row in rel.fetchall()]
        except Exception:
            return []

    def _top_ips(self) -> list[dict]:
        return self._query("""
            SELECT
                json_extract_string(extracted, '$.src_ip') AS src_ip,
                COUNT(*) AS event_count,
                COUNT(DISTINCT service) AS services_touched,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM logs
            WHERE json_extract_string(extracted, '$.src_ip') IS NOT NULL
              AND json_extract_string(extracted, '$.src_ip') != ''
            GROUP BY src_ip
            ORDER BY event_count DESC
            LIMIT 25
        """)

    def _top_users(self) -> list[dict]:
        return self._query("""
            SELECT
                json_extract_string(extracted, '$.user') AS username,
                COUNT(*) AS event_count,
                COUNT(DISTINCT service) AS services_touched,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM logs
            WHERE json_extract_string(extracted, '$.user') IS NOT NULL
              AND json_extract_string(extracted, '$.user') NOT IN ('', '-', 'root')
            GROUP BY username
            ORDER BY event_count DESC
            LIMIT 20
        """)

    def _by_service(self) -> list[dict]:
        return self._query("""
            SELECT service, COUNT(*) AS total, COUNT(DISTINCT hostname) AS hosts
            FROM logs
            GROUP BY service
            ORDER BY total DESC
        """)

    def _by_level(self) -> list[dict]:
        return self._query("""
            SELECT level, COUNT(*) AS total
            FROM logs
            GROUP BY level
            ORDER BY total DESC
        """)

    def _errors_over_time(self) -> list[dict]:
        return self._query("""
            SELECT
                strftime(CAST(to_timestamp(ts_epoch) AS TIMESTAMP), '%Y-%m-%d %H:00') AS hour_bucket,
                COUNT(*) AS error_count
            FROM logs
            WHERE level IN ('error', 'crit', 'alert', 'emerg', 'warn')
              AND ts_epoch > 0
            GROUP BY hour_bucket
            ORDER BY hour_bucket
            LIMIT 72
        """)

    def _auth_failures_by_ip(self) -> list[dict]:
        return self._query("""
            SELECT
                json_extract_string(extracted, '$.src_ip') AS src_ip,
                COUNT(*) AS failure_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM logs
            WHERE (
                message ILIKE '%failed password%'
                OR message ILIKE '%invalid user%'
                OR message ILIKE '%authentication failure%'
                OR message ILIKE '%failed login%'
            )
            AND json_extract_string(extracted, '$.src_ip') IS NOT NULL
            GROUP BY src_ip
            HAVING failure_count >= 3
            ORDER BY failure_count DESC
            LIMIT 30
        """)

    def _suspicious_uris(self) -> list[dict]:
        return self._query("""
            SELECT
                json_extract_string(extracted, '$.uri') AS uri,
                COUNT(*) AS hit_count,
                json_extract_string(extracted, '$.http_status') AS last_status
            FROM logs
            WHERE (
                json_extract_string(extracted, '$.uri') ILIKE '%../%'
                OR json_extract_string(extracted, '$.uri') ILIKE '%/etc/%'
                OR json_extract_string(extracted, '$.uri') ILIKE '%/proc/%'
                OR json_extract_string(extracted, '$.uri') ILIKE '%union%select%'
                OR json_extract_string(extracted, '$.uri') ILIKE '%<script%'
                OR json_extract_string(extracted, '$.uri') ILIKE '%cmd=%'
                OR json_extract_string(extracted, '$.uri') ILIKE '%exec(%'
            )
            AND json_extract_string(extracted, '$.uri') IS NOT NULL
            GROUP BY uri, last_status
            ORDER BY hit_count DESC
            LIMIT 30
        """)

    def _http_status_dist(self) -> list[dict]:
        return self._query("""
            SELECT
                json_extract_string(extracted, '$.http_status') AS status_code,
                COUNT(*) AS count
            FROM logs
            WHERE json_extract_string(extracted, '$.http_status') IS NOT NULL
            GROUP BY status_code
            ORDER BY count DESC
        """)

    # ------------------------------------------------------------------
    # Pure Python fallback (no DuckDB)
    # ------------------------------------------------------------------

    def _correlate_pure_python(self) -> dict:
        from collections import Counter, defaultdict

        ip_counts: Counter = Counter()
        user_counts: Counter = Counter()
        service_counts: Counter = Counter()
        level_counts: Counter = Counter()
        auth_fail_ips: Counter = Counter()

        auth_fail_keywords = ("failed password", "invalid user", "authentication failure", "failed login")

        for entry in self.entries:
            svc = entry.get("service", "unknown")
            lvl = entry.get("level", "info")
            msg = entry.get("message", "").lower()
            extracted = entry.get("extracted", {})

            service_counts[svc] += 1
            level_counts[lvl] += 1

            ip = extracted.get("src_ip")
            if ip:
                ip_counts[ip] += 1
                if any(kw in msg for kw in auth_fail_keywords):
                    auth_fail_ips[ip] += 1

            user = extracted.get("user")
            if user and user not in ("", "-", "root"):
                user_counts[user] += 1

        return {
            "top_ips_by_activity": [{"src_ip": k, "event_count": v} for k, v in ip_counts.most_common(25)],
            "top_users_by_events": [{"username": k, "event_count": v} for k, v in user_counts.most_common(20)],
            "events_by_service": [{"service": k, "total": v} for k, v in service_counts.most_common()],
            "events_by_level": [{"level": k, "total": v} for k, v in level_counts.most_common()],
            "auth_failures_by_ip": [
                {"src_ip": k, "failure_count": v}
                for k, v in auth_fail_ips.most_common(30)
                if v >= 3
            ],
            "note": "DuckDB not available — limited correlation (install duckdb for full SQL analysis)",
        }
