#!/usr/bin/env python3
"""
readme_to_pdf.py — Convierte README.md a README.pdf

Intenta los metodos en orden:
  1. pandoc + xelatex  (mejor calidad)
  2. pandoc + wkhtmltopdf
  3. pandoc (motor por defecto)
  4. xhtml2pdf (Python puro, sin dependencias de sistema)
  5. weasyprint (Python puro, requiere GTK en Windows)

Uso:
    python scripts/readme_to_pdf.py
    python scripts/readme_to_pdf.py --output docs/manual.pdf
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
README = BASE_DIR / "README.md"


def _run(cmd: list[str]) -> bool:
    """Run command, return True if successful."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True
        print(f"    stderr: {result.stderr.strip()[:200]}")
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _pandoc_xelatex(readme: Path, output: Path) -> bool:
    if not shutil.which("pandoc"):
        return False
    print("  Intentando pandoc + xelatex...")
    return _run([
        "pandoc", str(readme),
        "--pdf-engine=xelatex",
        "-V", "geometry:margin=2.5cm",
        "-V", "lang=es",
        "-V", "colorlinks=true",
        "-V", "linkcolor=blue",
        "--toc",
        "--toc-depth=2",
        "-o", str(output),
    ])


def _pandoc_wkhtmltopdf(readme: Path, output: Path) -> bool:
    if not shutil.which("pandoc") or not shutil.which("wkhtmltopdf"):
        return False
    print("  Intentando pandoc + wkhtmltopdf...")
    return _run([
        "pandoc", str(readme),
        "--pdf-engine=wkhtmltopdf",
        "-V", "lang=es",
        "--toc",
        "-o", str(output),
    ])


def _pandoc_default(readme: Path, output: Path) -> bool:
    if not shutil.which("pandoc"):
        return False
    print("  Intentando pandoc (motor por defecto)...")
    return _run([
        "pandoc", str(readme),
        "--toc",
        "-o", str(output),
    ])


def _xhtml2pdf(readme: Path, output: Path) -> bool:
    try:
        import markdown  # type: ignore
        from xhtml2pdf import pisa  # type: ignore
    except ImportError:
        return False

    print("  Intentando xhtml2pdf (Python puro)...")
    try:
        md_text = readme.read_text(encoding="utf-8")
        html_body = markdown.markdown(
            md_text,
            extensions=["tables", "fenced_code", "toc"],
        )
        css = """
            @page { margin: 2.5cm; }
            body { font-family: Helvetica, Arial, sans-serif; font-size: 10pt; line-height: 1.5; color: #222; }
            h1 { font-size: 20pt; color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 4px; }
            h2 { font-size: 14pt; color: #16213e; border-bottom: 1px solid #ccc; padding-bottom: 2px; margin-top: 18px; }
            h3 { font-size: 11pt; color: #0f3460; margin-top: 12px; }
            code { background: #f4f4f4; padding: 1px 4px; font-family: Courier, monospace; font-size: 9pt; }
            pre { background: #f4f4f4; padding: 8px; border-left: 3px solid #1a1a2e; font-size: 8pt; font-family: Courier, monospace; }
            table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 9pt; }
            th { background: #1a1a2e; color: white; padding: 5px 8px; text-align: left; }
            td { border: 1px solid #ccc; padding: 4px 8px; }
            tr:nth-child(even) td { background: #f9f9f9; }
            blockquote { border-left: 3px solid #e74c3c; padding-left: 10px; color: #555; margin: 8px 0; }
            a { color: #0f3460; }
            hr { border: none; border-top: 1px solid #ddd; margin: 12px 0; }
        """
        html = (
            "<!DOCTYPE html><html><head>"
            "<meta charset='utf-8'>"
            f"<style>{css}</style>"
            f"</head><body>{html_body}</body></html>"
        )
        with open(output, "wb") as fh:
            result = pisa.CreatePDF(html.encode("utf-8"), dest=fh, encoding="utf-8")
        if result.err:
            print(f"    xhtml2pdf errors: {result.err}")
            return False
        return True
    except Exception as e:
        print(f"    Error xhtml2pdf: {e}")
        return False


def _weasyprint(readme: Path, output: Path) -> bool:
    try:
        import markdown  # type: ignore
        from weasyprint import HTML, CSS  # type: ignore
    except ImportError:
        return False

    print("  Intentando weasyprint (Python puro)...")
    try:
        md_text = readme.read_text(encoding="utf-8")
        html_body = markdown.markdown(
            md_text,
            extensions=["tables", "fenced_code", "toc"],
        )
        css = CSS(string="""
            @page { margin: 2.5cm; }
            body { font-family: Arial, sans-serif; font-size: 10pt; line-height: 1.5; }
            h1 { font-size: 18pt; color: #1a1a2e; border-bottom: 2px solid #1a1a2e; }
            h2 { font-size: 14pt; color: #16213e; border-bottom: 1px solid #ccc; }
            h3 { font-size: 12pt; color: #0f3460; }
            code { background: #f4f4f4; padding: 2px 4px; font-family: monospace; font-size: 9pt; }
            pre { background: #f4f4f4; padding: 10px; border-left: 3px solid #1a1a2e; overflow-x: auto; }
            table { border-collapse: collapse; width: 100%; margin: 1em 0; }
            th, td { border: 1px solid #ccc; padding: 6px 10px; }
            th { background: #1a1a2e; color: white; }
            blockquote { border-left: 3px solid #e74c3c; padding-left: 10px; color: #555; }
        """)
        html = f"<!DOCTYPE html><html><head><meta charset='utf-8'></head><body>{html_body}</body></html>"
        HTML(string=html).write_pdf(str(output), stylesheets=[css])
        return True
    except Exception as e:
        print(f"    Error weasyprint: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Convierte README.md a PDF")
    parser.add_argument(
        "--output", "-o",
        default=str(BASE_DIR / "README.pdf"),
        help="Ruta del PDF de salida (por defecto: README.pdf en raíz del proyecto)",
    )
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    if not README.exists():
        print(f"[X] No se encontró README.md en: {README}")
        sys.exit(1)

    print(f"[*] Convirtiendo {README.name} -> {output.name}")
    print()

    methods = [
        _pandoc_xelatex,
        _pandoc_wkhtmltopdf,
        _pandoc_default,
        _xhtml2pdf,
        _weasyprint,
    ]

    for method in methods:
        if method(README, output):
            print()
            print(f"[+] PDF generado: {output}")
            sys.exit(0)

    print()
    print("[X] No se pudo generar el PDF. Instale una de estas opciones:")
    print("    - pandoc + texlive-xetex  (recomendado)")
    print("    - pandoc + wkhtmltopdf")
    print("    - pip install xhtml2pdf markdown")
    print("    - pip install weasyprint markdown  (+ GTK en Windows)")
    sys.exit(1)


if __name__ == "__main__":
    main()
