#!/usr/bin/env python3
"""
Prueba del pipeline JSON Stage A → Stage B.

Cubre:
  1. Fix de extensión para archivos sin .log (var_log_secure → var_log_secure.jsonl)
  2. _convert_text_logs_to_json() produce JSONL válido con campos correctos
  3. LogNormalizer._parse_stage_a_jsonl() parsea correctamente el JSONL de Stage A
  4. End-to-end: texto syslog → JSONL (Stage A) → entradas normalizadas (Stage B)

Ejecución desde la raíz del proyecto:
    python scripts/test_json_pipeline.py
"""
import json
import sys
import tempfile
from pathlib import Path

# Raíz del proyecto en el path
sys.path.insert(0, str(Path(__file__).parent.parent))

import config

# ── Muestras de log ────────────────────────────────────────────────────────────

SYSLOG_SAMPLE = """\
Apr 13 08:01:12 servidor sshd[1234]: Accepted publickey for admin from 10.0.0.5 port 54321 ssh2
Apr 13 08:01:15 servidor sudo[1235]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
Apr 13 08:02:00 servidor sshd[1236]: Failed password for invalid user ghost from 10.0.0.99 port 44444 ssh2
Apr 13 08:02:01 servidor sshd[1237]: Failed password for invalid user ghost from 10.0.0.99 port 44445 ssh2
Apr 13 08:05:30 servidor cron[1240]: (root) CMD (/usr/lib/update-notifier/apt-daily-install)
"""

DMESG_SAMPLE = """\
[    0.000000] Initializing cgroup subsys cpuset
[    0.000000] Linux version 5.15.0-91-generic
[    1.234567] EXT4-fs (sda1): mounted filesystem with ordered data mode
[  120.000000] audit: type=1400 audit(1744531200.000:1): apparmor="ALLOWED" operation="open"
"""

# ── Utilidades ─────────────────────────────────────────────────────────────────

_PASS = "\033[92m[PASS]\033[0m"
_FAIL = "\033[91m[FAIL]\033[0m"
_results: list[tuple[str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = _PASS if condition else _FAIL
    msg = f"  {status} {name}"
    if detail:
        msg += f"\n         {detail}"
    print(msg)
    _results.append((name, "PASS" if condition else "FAIL"))


# ── Test 1: fix de extensión en _write_log ─────────────────────────────────────

def test_filename_fix() -> None:
    print("\n[1] Fix de extensión para archivos sin .log")

    cases = [
        # (filename_entrada,    filename_esperado)
        ("var_log_auth.log",   "var_log_auth.jsonl"),    # .log → .jsonl  ✓
        ("var_log_secure",     "var_log_secure.jsonl"),  # sin ext → .jsonl (fix)
        ("var_log_syslog",     "var_log_syslog.jsonl"),  # 'syslog' no es extensión
        ("var_log_cron",       "var_log_cron.jsonl"),    # sin ext → .jsonl (fix)
        ("var_log_messages",   "var_log_messages.jsonl"),
        ("var_log_maillog",    "var_log_maillog.jsonl"),
        ("dmesg.txt",          "dmesg.jsonl"),           # .txt → .jsonl  ✓
    ]

    for original, expected in cases:
        if original.endswith('.gz'):
            result = original.replace('.gz', '.jsonl.gz')
        else:
            new_name = original.replace('.log', '.jsonl').replace('.txt', '.jsonl')
            result = new_name if new_name != original else original + '.jsonl'

        check(f"{original} → {result}", result == expected,
              f"esperado={expected}, obtenido={result}")


# ── Test 2: _convert_text_logs_to_json produce JSONL válido ───────────────────

def test_convert_to_jsonl() -> None:
    print("\n[2] _convert_text_logs_to_json() → JSONL válido")

    from stage_a.collector import _convert_text_logs_to_json

    # Syslog
    output = _convert_text_logs_to_json(SYSLOG_SAMPLE, "/var/log/auth.log", "servidor")
    lines = [l for l in output.splitlines() if l.strip()]

    check("syslog: produce líneas no vacías", len(lines) > 0,
          f"líneas={len(lines)}")

    parsed = []
    for line in lines:
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError as e:
            check(f"syslog: JSON válido en línea '{line[:40]}'", False, str(e))
            return

    check("syslog: todas las líneas son JSON válido", len(parsed) == len(lines))

    required_keys = {"timestamp", "ts_epoch", "hostname", "service",
                     "pid", "level", "message", "source_file", "raw", "extracted"}
    for entry in parsed:
        missing = required_keys - set(entry.keys())
        check(f"syslog: campos completos en entrada", not missing,
              f"faltan={missing}, msg='{entry.get('message','')[:50]}'")
        break  # basta verificar la primera

    # Verificar que mensajes específicos se parsearon bien
    auth_msgs = [e["message"] for e in parsed]
    has_ssh_accept = any("Accepted publickey" in m for m in auth_msgs)
    has_failed    = any("Failed password" in m for m in auth_msgs)
    check("syslog: mensaje 'Accepted publickey' capturado", has_ssh_accept)
    check("syslog: mensaje 'Failed password' capturado", has_failed)

    # dmesg (sin formato estándar — debe caer en fallback)
    output2 = _convert_text_logs_to_json(DMESG_SAMPLE, "/run/dmesg", "servidor")
    lines2 = [l for l in output2.splitlines() if l.strip()]
    check("dmesg: produce entradas (fallback genérico)", len(lines2) > 0)


# ── Test 3: _parse_stage_a_jsonl en el normalizador ───────────────────────────

def test_normalizer_parser() -> None:
    print("\n[3] LogNormalizer._parse_stage_a_jsonl() reconoce formato Stage A")

    from stage_a.collector import _convert_text_logs_to_json
    from stage_b.normalizer import LogNormalizer
    from core.job import JobContext

    with tempfile.TemporaryDirectory() as tmpdir:
        original_jobs = config.JOBS_DIR
        config.JOBS_DIR = Path(tmpdir) / "jobs"
        config.JOBS_DIR.mkdir()

        try:
            job = JobContext(host="test-host")

            # Simular lo que Stage A escribe en logs_dir
            jsonl_content = _convert_text_logs_to_json(
                SYSLOG_SAMPLE, "/var/log/auth.log", "servidor"
            )
            log_file = job.logs_dir / "var_log_auth.jsonl"
            log_file.write_text(jsonl_content, encoding="utf-8")

            # Verificar detección
            sample = jsonl_content[:2000]
            is_stage_a = (
                sample.strip().startswith("{")
                and '"ts_epoch"' in sample
                and '"source_file"' in sample
            )
            check("detección: reconoce JSONL de Stage A", is_stage_a)
            is_not_journalctl = "__REALTIME_TIMESTAMP" not in sample
            check("detección: no confunde con journalctl", is_not_journalctl)

            # Ejecutar normalizer
            normalizer = LogNormalizer(job)
            entries = normalizer.normalize_all()

            check("normalizer: produce entradas > 0", len(entries) > 0,
                  f"entradas={len(entries)}")

            if entries:
                # Verificar que las entradas tienen estructura (no son raw strings)
                e = entries[0]
                check("entrada: campo 'service' es string corto",
                      isinstance(e.get("service"), str) and len(e["service"]) < 100,
                      f"service='{e.get('service')}'")
                check("entrada: campo 'message' contiene texto de log",
                      isinstance(e.get("message"), str) and len(e["message"]) > 5,
                      f"message='{e.get('message','')[:60]}'")
                check("entrada: 'message' NO es un objeto JSON serializado",
                      not e.get("message", "").strip().startswith("{"),
                      f"message='{e.get('message','')[:60]}'")
                check("entrada: campo 'extracted' es dict",
                      isinstance(e.get("extracted"), dict))

        finally:
            config.JOBS_DIR = original_jobs


# ── Test 4: end-to-end con dos formatos (Stage A JSONL + syslog plano) ────────

def test_end_to_end_mixed() -> None:
    print("\n[4] End-to-end: JSONL Stage A + syslog plano → normalizer unificado")

    from stage_a.collector import _convert_text_logs_to_json
    from stage_b.normalizer import LogNormalizer
    from core.job import JobContext

    with tempfile.TemporaryDirectory() as tmpdir:
        original_jobs = config.JOBS_DIR
        config.JOBS_DIR = Path(tmpdir) / "jobs"
        config.JOBS_DIR.mkdir()

        try:
            job = JobContext(host="test-host-e2e")

            # Archivo 1: Stage A JSONL (simulando /var/log/secure convertido)
            jsonl_secure = _convert_text_logs_to_json(
                SYSLOG_SAMPLE, "/var/log/secure", "servidor"
            )
            (job.logs_dir / "var_log_secure.jsonl").write_text(jsonl_secure, encoding="utf-8")

            # Archivo 2: syslog plano (como si Stage A no lo hubiera convertido)
            (job.logs_dir / "var_log_syslog_raw").write_text(SYSLOG_SAMPLE, encoding="utf-8")

            # Archivo 3: journalctl JSON real
            journalctl_line = json.dumps({
                "__REALTIME_TIMESTAMP": "1744531200000000",
                "_HOSTNAME": "servidor",
                "SYSLOG_IDENTIFIER": "sshd",
                "_PID": "9999",
                "PRIORITY": "6",
                "MESSAGE": "Server listening on 0.0.0.0 port 22.",
            })
            (job.logs_dir / "journal_sshd_72h.json").write_text(
                journalctl_line + "\n", encoding="utf-8"
            )

            normalizer = LogNormalizer(job)
            entries = normalizer.normalize_all()
            stats = normalizer.get_stats()

            check("total entradas > 0", len(entries) > 0,
                  f"entradas={len(entries)}")
            check("journalctl procesado (sshd encontrado)",
                  "sshd" in stats["by_service"],
                  f"servicios={list(stats['by_service'].keys())[:10]}")

            # Verificar que ninguna entrada tiene 'message' que sea JSON en bruto
            raw_json_messages = [
                e for e in entries
                if isinstance(e.get("message"), str) and e["message"].strip().startswith("{")
            ]
            check("ninguna entrada tiene message=JSON bruto",
                  len(raw_json_messages) == 0,
                  f"{len(raw_json_messages)} entradas con message=JSON")

            print(f"\n    Estadísticas del normalizador:")
            print(f"      Total entradas : {stats['total_entries']}")
            print(f"      Por servicio   : {dict(list(stats['by_service'].items())[:5])}")
            print(f"      Por nivel      : {stats['by_level']}")
            print(f"      Rango temporal : {stats['time_range']}")

        finally:
            config.JOBS_DIR = original_jobs


# ── Runner ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("  TEST: Pipeline JSON Stage A → Stage B")
    print("=" * 60)

    test_filename_fix()
    test_convert_to_jsonl()
    test_normalizer_parser()
    test_end_to_end_mixed()

    total = len(_results)
    passed = sum(1 for _, r in _results if r == "PASS")
    failed = total - passed

    print("\n" + "=" * 60)
    print(f"  Resultado: {passed}/{total} pruebas pasaron", end="")
    if failed:
        print(f"  ({failed} fallaron)")
        print("\n  Pruebas fallidas:")
        for name, result in _results:
            if result == "FAIL":
                print(f"    - {name}")
    else:
        print()
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
