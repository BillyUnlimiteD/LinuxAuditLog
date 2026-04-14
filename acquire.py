#!/usr/bin/env python3
"""
LinuxAuditLog — Remote Forensic Acquisition Agent
===================================================
Entry point. Reads connection parameters from environment variables.
Credentials are never written to disk.

Usage:
    export SSH_HOST=192.168.1.100
    export SSH_USER=admin
    export SSH_PASS=yourpassword
    export SSH_PORT=22          # optional, default 22
    python acquire.py

Output:
    jobs/<YYYYMMDD_HHMMSS_host>/
        01_evidence/   — raw artifacts + MANIFEST
        02_analysis/   — normalized logs, timeline, correlations
        03_report/     — report.md + PDF conversion scripts
"""
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Verify Python version
if sys.version_info < (3, 11):
    sys.exit("[ERROR] Python 3.11 or higher is required.")

# Load .env file if present (does NOT overwrite variables already set in the environment)
_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    with open(_ENV_FILE, encoding="utf-8") as _fh:
        for _line in _fh:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                _k = _k.strip()
                if _k and _k not in os.environ:
                    os.environ[_k] = _v.strip()

# Verify dependencies early
_MISSING = []
for _pkg in ("asyncssh", "yaml", "jinja2"):
    try:
        __import__(_pkg)
    except ImportError:
        _MISSING.append(_pkg)
if _MISSING:
    print("[ERROR] Missing dependencies. Run: pip install -r requirements.txt")
    print(f"  Missing: {', '.join(_MISSING)}")
    sys.exit(1)

import asyncssh

from core.job import JobContext
from core.manifest import ManifestBuilder
from core.session import EphemeralSession
from stage_a.collector import RemoteCollector
from stage_a.detector import SystemDetector
from stage_b.correlator import LogCorrelator
from stage_b.ioc_engine import IOCEngine
from stage_b.normalizer import LogNormalizer
from stage_b.rule_advisor import RuleAdvisor
from stage_b.timeline import TimelineBuilder
from reporting.markdown_builder import ReportBuilder
from reporting.pdf_scripts import PDFScriptGenerator
from reporting.prompt_builder import PromptReportBuilder
import config


# ------------------------------------------------------------------
# Banner
# ------------------------------------------------------------------

def _banner() -> None:
    print()
    print("=" * 62)
    print(f"  {config.TOOL_NAME} v{config.TOOL_VERSION}")
    print("  Remote Forensic Acquisition + Local Analysis")
    print("=" * 62)
    print()


def _section(title: str) -> None:
    print(f"\n[{'='*3}] {title}")
    print("-" * 50)


def _ok(msg: str) -> None:
    print(f"  [+] {msg}")


def _warn(msg: str) -> None:
    print(f"  [!] {msg}")


def _err(msg: str) -> None:
    print(f"  [X] {msg}")


# ------------------------------------------------------------------
# Stage A — Remote Acquisition
# ------------------------------------------------------------------

async def run_stage_a(session: EphemeralSession, job: JobContext) -> tuple[dict, dict]:
    """Connect, collect, hash, disconnect. Returns (system_info, acq_log)."""

    acq_log: dict = {
        "start": datetime.now(timezone.utc).isoformat(),
        "end": None,
        "host": session.host,
        "username": session.username,
        "commands": [],
        "artifacts": [],
        "errors": [],
        "connection_closed": False,
    }

    system_info: dict = {}

    _section("ETAPA A — ADQUISICION REMOTA")
    _ok(f"Conectando a {session.host}:{session.port} ...")

    try:
        conn_opts = session.to_asyncssh_options()

        async with asyncssh.connect(**conn_opts) as conn:
            _ok(f"Conexion SSH establecida")

            # Phase 1 — System identification
            _ok("Fase 1: Identificacion del sistema...")
            detector = SystemDetector(conn, job, acq_log)
            system_info = await detector.detect()
            _ok(f"  SO: {system_info.get('distro_name', 'unknown')}")
            _ok(f"  Init: {system_info.get('init_system', 'unknown')}")
            _ok(f"  Kernel: {system_info.get('kernel', 'unknown')}")

            # Phase 2-4 — Services, ports, logs
            _ok("Fases 2-4: Recoleccion de servicios, puertos y logs...")
            collector = RemoteCollector(conn, job, system_info, acq_log,
                                        root_pass=session.root_pass)
            await collector.collect_all()
            artifact_count = len(acq_log.get("artifacts", []))
            _ok(f"  Artefactos recolectados: {artifact_count}")

            if acq_log.get("errors"):
                _warn(f"  {len(acq_log['errors'])} comando(s) fallaron — documentados como limitaciones")

            # Phase 5 — Hashing + manifest
            _ok("Fase 5: Generando hashes SHA-256 y manifiesto...")
            manifest_builder = ManifestBuilder(job)
            manifest_builder.build_from_directory(job.raw_dir)
            manifest_builder.save()
            _ok(f"  Manifiesto: {manifest_builder.artifact_count} artefactos hasheados")

            # Connection closes here (context manager __aexit__)

        # Phase 6 — Session closed (outside context manager)
        acq_log["end"] = datetime.now(timezone.utc).isoformat()
        acq_log["connection_closed"] = True
        _ok("Fase 6: Conexion SSH cerrada explicitamente")

    except asyncssh.PermissionDenied:
        _err("Autenticacion fallida — verificar SSH_USER y SSH_PASS")
        _save_acq_log(acq_log, job)
        sys.exit(1)
    except asyncssh.HostKeyNotVerifiable as e:
        _err(f"Host key no verificable: {e}")
        _save_acq_log(acq_log, job)
        sys.exit(1)
    except (asyncssh.ConnectionLost, ConnectionResetError) as e:
        _err(f"Conexion perdida: {e}")
        _save_acq_log(acq_log, job)
        sys.exit(1)
    except OSError as e:
        _err(f"No se pudo conectar a {session.host}:{session.port} — {e}")
        _save_acq_log(acq_log, job)
        sys.exit(1)
    finally:
        # Zero credentials regardless of outcome
        session.zero_credentials()
        _ok("Credenciales destruidas de memoria")

    _save_acq_log(acq_log, job)
    return system_info, acq_log


def _save_acq_log(acq_log: dict, job: JobContext) -> None:
    try:
        with open(job.raw("acquisition_log.json"), "w", encoding="utf-8") as fh:
            json.dump(acq_log, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ------------------------------------------------------------------
# Stage B — Local Analysis
# ------------------------------------------------------------------

def run_stage_b(job: JobContext, system_info: dict, acq_log: dict) -> None:
    """Perform all analysis on local copies. No remote connection."""

    _section("ETAPA B — ANALISIS LOCAL")
    _ok("Normalizando logs exportados...")

    # Step 1 — Normalize
    normalizer = LogNormalizer(job)
    entries = normalizer.normalize_all()
    stats = normalizer.get_stats()
    _ok(f"  {stats['total_entries']} entradas normalizadas")
    _ok(f"  Rango: {stats['time_range'].get('earliest', 'N/A')} → {stats['time_range'].get('latest', 'N/A')}")

    # Step 2 — Rule advisor: map detected services to rules, create stubs for unknowns
    _ok("Analizando cobertura de reglas por servicio detectado...")
    advisor = RuleAdvisor(job)
    coverage = advisor.advise()
    _ok(f"  Servicios detectados: {len(coverage['detected_services'])}")
    _ok(f"  Con cobertura de reglas: {len(coverage['services_with_rules'])}")
    if coverage["services_without_rules"]:
        _warn(f"  Sin reglas ({len(coverage['services_without_rules'])}): {', '.join(coverage['services_without_rules'][:8])}")
    if coverage["placeholder_rules_created"]:
        _ok(f"  Stubs creados para nuevos servicios: {len(coverage['placeholder_rules_created'])}")
        for stub in coverage["placeholder_rules_created"]:
            _warn(f"    rules/{stub['stub_path']} — completar patrones manualmente")

    # Step 3 — Timeline
    _ok("Construyendo timeline unificado...")
    timeline = TimelineBuilder(job)
    timeline.build(entries)
    top_events = timeline.get_top_events(50)

    # Step 4 — IOC detection (includes any newly created stub rules, disabled by default)
    _ok(f"Evaluando reglas de deteccion ({_count_rules()} reglas)...")
    ioc_engine = IOCEngine(config.RULES_DIR)
    findings = ioc_engine.evaluate(entries)
    _ok(f"  {len(findings)} hallazgo(s) identificados")
    for f in findings:
        severity_mark = {"critical": "[!!]", "high": "[! ]", "medium": "[ *]"}.get(f.severity, "[  ]")
        _ok(f"  {severity_mark} [{f.rule_id}] {f.title} ({f.match_count} eventos)")

    # Step 5 — Correlation
    _ok("Correlacionando entidades (IP, usuario, servicio)...")
    correlator = LogCorrelator(job, entries)
    correlations = correlator.correlate()

    # Step 6 — Load manifest for report
    manifest = _load_json(job.manifest_path(), {"artifacts": [], "artifact_count": 0, "total_size_bytes": 0, "generated_at": "N/A"})
    services = _load_json(job.raw("services_inventory.json"), {"parsed": [], "raw_systemctl": ""})

    # Step 7 — Report
    _ok("Generando informe forense...")
    report_builder = ReportBuilder(job)
    report_path = report_builder.build(
        system_info=system_info,
        services=services,
        findings=findings,
        correlations=correlations,
        manifest=manifest,
        acquisition_log=acq_log,
        timeline_events=top_events,
        log_stats=stats,
    )
    _ok(f"  Informe: {report_path}")

    # Step 7b — PDF conversion (immediate) + fallback scripts
    pdf_gen = PDFScriptGenerator(job, python_executable=sys.executable)
    pdf_gen.generate(report_path)

    _ok("Convirtiendo informe a PDF...")
    pdf_path = pdf_gen.convert_now(report_path)
    if pdf_path:
        _ok(f"  PDF: {pdf_path}")
    else:
        _warn("  PDF no generado — pandoc/weasyprint no disponibles.")
        _warn("  Usar manualmente: convert_to_pdf.sh / .bat / .py")

    # Step 8 — AI prompts report
    _ok("Generando reporte de prompts IA...")
    _now = datetime.now(timezone.utc)
    report_metadata = {
        "tool_name": config.TOOL_NAME,
        "tool_version": config.TOOL_VERSION,
        "generated_at": _now.isoformat(),
        "generated_at_readable": _now.strftime("%d/%m/%Y %H:%M:%S UTC"),
    }
    prompt_builder = PromptReportBuilder(job)
    prompts_path = prompt_builder.build(
        system_info=system_info,
        findings=findings,
        report_metadata=report_metadata,
    )
    _ok(f"  Prompts MD: {prompts_path}")

    _ok("Convirtiendo prompts a PDF...")
    prompts_pdf = pdf_gen.convert_now(prompts_path)
    if prompts_pdf:
        _ok(f"  Prompts PDF: {prompts_pdf}")
    else:
        _warn("  PDF de prompts no generado.")


def _count_rules() -> int:
    try:
        return sum(1 for _ in config.RULES_DIR.rglob("*.yaml"))
    except Exception:
        return 0


def _load_json(path: Path, default: dict) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

async def main() -> None:
    _banner()

    # Load session from environment (no credentials on disk)
    try:
        session = EphemeralSession.from_env()
    except EnvironmentError as e:
        _err(str(e))
        sys.exit(1)

    _ok(f"Host: {session.host}:{session.port}")
    _ok(f"Usuario: {session.username}")
    _ok(f"Ventana temporal: ultimas {config.DEFAULT_TIME_WINDOW_HOURS}h")

    # Create job context (creates output directories)
    job = JobContext(host=session.host)
    _ok(f"Job ID: {job.job_id}")
    _ok(f"Directorio de trabajo: {job.job_dir}")

    t_start = time.monotonic()

    # STAGE A
    system_info, acq_log = await run_stage_a(session, job)

    # STAGE B (runs only with local data — session already closed)
    run_stage_b(job, system_info, acq_log)

    elapsed = time.monotonic() - t_start

    # Final summary
    print()
    print("=" * 62)
    print("  ADQUISICION Y ANALISIS COMPLETADOS")
    print("=" * 62)
    print(f"  Tiempo total:   {elapsed:.0f}s")
    print(f"  Directorio:     {job.job_dir}")
    print()
    print("  Estructura de salida:")
    print(f"    01_evidence/  — artefactos crudos + MANIFEST.json")
    print(f"    02_analysis/  — timeline, correlaciones, entradas normalizadas")
    print(f"    03_report/    — report_{job.job_id}.md + .pdf")
    print(f"                  — ai_prompts_{job.job_id}.md + .pdf")
    print()


if __name__ == "__main__":
    asyncio.run(main())
