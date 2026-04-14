"""
PDFScriptGenerator — creates convert_to_pdf.sh/.bat/.py alongside the
Markdown report AND runs the conversion immediately.

Priority order for PDF conversion:
  1. pandoc + xelatex  (best quality, pericial grade)
  2. pandoc + wkhtmltopdf
  3. pandoc (default engine)
  4. weasyprint (pure Python fallback — requires: pip install weasyprint)
"""
import subprocess
import sys
from pathlib import Path

from core.job import JobContext


class PDFScriptGenerator:
    def __init__(self, job: JobContext, python_executable: str = "") -> None:
        self.job = job
        # Use the provided executable (sys.executable from acquire.py).
        # Fallback to "python3" on Linux/macOS or "python" on Windows if not supplied.
        import sys
        if python_executable:
            self.python_exe = python_executable
        else:
            self.python_exe = sys.executable or ("python" if sys.platform == "win32" else "python3")

    def generate(self, report_md_path: Path) -> None:
        report_name = report_md_path.stem
        pdf_name = report_name + ".pdf"

        self._write_sh(report_md_path, pdf_name)
        self._write_bat(report_md_path, pdf_name)
        self._write_python_fallback(report_md_path, pdf_name)

    def convert_now(self, report_md_path: Path) -> Path | None:
        """Convert the Markdown report to PDF immediately.

        Tries the same priority chain used by the generated scripts:
          1. pandoc + xelatex
          2. pandoc + wkhtmltopdf
          3. pandoc (default engine)
          4. weasyprint (pure Python)

        Returns the Path to the generated PDF on success, or None if every
        method fails.
        """
        pdf_path = report_md_path.with_suffix(".pdf")
        md = str(report_md_path)
        out = str(pdf_path)

        # -- pandoc attempts --------------------------------------------------
        if self._which("pandoc"):
            common = [
                "--table-of-contents", "--toc-depth=2",
                "-V", "geometry:margin=2.5cm",
                "-V", "fontsize=11pt",
                "--highlight-style=tango",
            ]

            engines = []
            if self._which("xelatex"):
                engines.append(["--pdf-engine=xelatex", "-V", "mainfont=DejaVu Sans"])
            if self._which("wkhtmltopdf"):
                engines.append(["--pdf-engine=wkhtmltopdf"])
            engines.append([])  # pandoc default engine

            for engine_args in engines:
                cmd = ["pandoc", md, "-o", out] + engine_args + common
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        timeout=120,
                    )
                    if result.returncode == 0 and pdf_path.exists():
                        return pdf_path
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue

        # -- xhtml2pdf fallback (pure Python, cross-platform) -----------------
        try:
            import markdown as md_lib   # type: ignore
            from xhtml2pdf import pisa  # type: ignore

            with open(report_md_path, encoding="utf-8") as fh:
                md_text = fh.read()

            html_body = md_lib.markdown(
                md_text,
                extensions=["tables", "fenced_code", "nl2br"],
            )
            css = """
@page {
    margin: 2.2cm 2cm 2.2cm 2cm;
    @frame footer {
        -pdf-frame-content: footer_content;
        bottom: 0.8cm; margin-left: 1cm; margin-right: 1cm; height: 0.8cm;
    }
}
body {
    font-family: Arial, Helvetica, sans-serif;
    font-size: 10.5pt;
    line-height: 1.45;
    color: #111;
}
h1 {
    font-size: 16pt;
    color: #1a1a2e;
    border-bottom: 2px solid #1a1a2e;
    padding-bottom: 4px;
    margin-top: 0.8em;
}
h2 {
    font-size: 13pt;
    color: #16213e;
    border-bottom: 1px solid #aaa;
    padding-bottom: 3px;
    margin-top: 0.4em;
    page-break-before: always;
}
h3 {
    font-size: 11pt;
    color: #0f3460;
    margin-top: 0.6em;
    page-break-after: avoid;
}
p { margin: 0.4em 0; }
table {
    border-collapse: collapse;
    width: 100%;
    margin: 0.6em 0;
    font-size: 8.5pt;
    table-layout: fixed;
}
th, td {
    border: 1px solid #bbb;
    padding: 4px 6px;
    text-align: left;
    vertical-align: top;
    word-break: break-all;
    overflow-wrap: break-word;
}
th {
    background-color: #1a1a2e;
    color: #ffffff;
    font-weight: bold;
}
code {
    font-family: Courier, monospace;
    font-size: 8pt;
    background: #f0f0f0;
    padding: 1px 3px;
}
pre {
    font-family: Courier, monospace;
    font-size: 7.5pt;
    background: #f0f0f0;
    border-left: 3px solid #1a1a2e;
    padding: 6px 8px;
    margin: 0.5em 0;
    white-space: pre-wrap;
    word-break: break-all;
    overflow-wrap: break-word;
}
blockquote {
    border-left: 3px solid #e74c3c;
    margin: 0.6em 0;
    padding: 0.3em 0.8em;
    background: #fff5f5;
}
ul, ol { margin: 0.4em 0; padding-left: 1.4em; }
li { margin: 0.2em 0; }
hr { border: none; border-top: 1px solid #ccc; margin: 0.8em 0; }
#footer_content {
    text-align: center;
    font-size: 8pt;
    color: #666;
}
"""
            html = (
                '<!DOCTYPE html><html lang="es"><head>'
                '<meta charset="utf-8">'
                f"<style>{css}</style>"
                '</head><body>'
                '<div id="footer_content">LinuxAuditLog — Informe Forense</div>'
                f"{html_body}</body></html>"
            )
            with open(pdf_path, "wb") as pdf_fh:
                status = pisa.CreatePDF(html, dest=pdf_fh)
            if not status.err and pdf_path.exists():
                return pdf_path
            pdf_path.unlink(missing_ok=True)
        except Exception:
            pass

        return None

    @staticmethod
    def _which(cmd: str) -> bool:
        """Return True if *cmd* is available on PATH."""
        import shutil
        return shutil.which(cmd) is not None

    # ------------------------------------------------------------------
    # Shell script (Linux / macOS)
    # ------------------------------------------------------------------

    def _write_sh(self, md_path: Path, pdf_name: str) -> None:
        md_file = md_path.name
        content = f"""#!/usr/bin/env bash
# ============================================================
# LinuxAuditLog — Convert forensic report to PDF
# ============================================================
# Usage: bash convert_to_pdf.sh
# Requires: pandoc  (https://pandoc.org/installing.html)
#           Optional: texlive-xetex for best quality
# ============================================================

set -euo pipefail

MD_FILE="{md_file}"
PDF_FILE="{pdf_name}"
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

cd "$SCRIPT_DIR"

if ! command -v pandoc &>/dev/null; then
    echo "[ERROR] pandoc not found."
    echo "  Install: https://pandoc.org/installing.html"
    echo "  Or use: python convert_to_pdf.py"
    exit 1
fi

echo "[*] Converting $MD_FILE -> $PDF_FILE ..."

# Attempt 1: xelatex (highest quality)
if command -v xelatex &>/dev/null; then
    pandoc "$MD_FILE" \\
        -o "$PDF_FILE" \\
        --pdf-engine=xelatex \\
        -V geometry:margin=2.5cm \\
        -V fontsize=11pt \\
        -V mainfont="DejaVu Sans" \\
        --table-of-contents \\
        --toc-depth=2 \\
        --highlight-style=tango \\
        2>/dev/null && \\
    echo "[OK] PDF generated with xelatex: $PDF_FILE" && exit 0
fi

# Attempt 2: wkhtmltopdf
if command -v wkhtmltopdf &>/dev/null; then
    pandoc "$MD_FILE" \\
        -o "$PDF_FILE" \\
        --pdf-engine=wkhtmltopdf \\
        2>/dev/null && \\
    echo "[OK] PDF generated with wkhtmltopdf: $PDF_FILE" && exit 0
fi

# Attempt 3: pandoc default engine
pandoc "$MD_FILE" \\
    -o "$PDF_FILE" \\
    -V geometry:margin=2.5cm \\
    2>/dev/null && \\
echo "[OK] PDF generated: $PDF_FILE" && exit 0

echo "[WARN] pandoc PDF failed. Trying Python fallback..."
"{self.python_exe}" convert_to_pdf.py 2>/dev/null || \\
echo "[ERROR] All PDF conversion methods failed. Install texlive or weasyprint."
"""
        path = self.job.report("convert_to_pdf.sh")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)

    # ------------------------------------------------------------------
    # Batch script (Windows)
    # ------------------------------------------------------------------

    def _write_bat(self, md_path: Path, pdf_name: str) -> None:
        md_file = md_path.name
        content = f"""@echo off
REM ============================================================
REM LinuxAuditLog - Convert forensic report to PDF (Windows)
REM ============================================================
REM Usage: convert_to_pdf.bat
REM Requires: pandoc  (https://pandoc.org/installing.html)
REM           Optional: MiKTeX or TeX Live for xelatex engine
REM ============================================================

setlocal
set MD_FILE={md_file}
set PDF_FILE={pdf_name}
cd /d "%~dp0"

where pandoc >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pandoc not found.
    echo   Install: https://pandoc.org/installing.html
    echo   Or run:  python convert_to_pdf.py
    exit /b 1
)

echo [*] Converting %MD_FILE% -^> %PDF_FILE% ...

REM Attempt 1: xelatex
where xelatex >nul 2>&1
if %errorlevel% equ 0 (
    pandoc "%MD_FILE%" -o "%PDF_FILE%" --pdf-engine=xelatex -V geometry:margin=2.5cm -V fontsize=11pt --table-of-contents --toc-depth=2 2>nul
    if %errorlevel% equ 0 (
        echo [OK] PDF generated with xelatex: %PDF_FILE%
        exit /b 0
    )
)

REM Attempt 2: wkhtmltopdf
where wkhtmltopdf >nul 2>&1
if %errorlevel% equ 0 (
    pandoc "%MD_FILE%" -o "%PDF_FILE%" --pdf-engine=wkhtmltopdf 2>nul
    if %errorlevel% equ 0 (
        echo [OK] PDF generated with wkhtmltopdf: %PDF_FILE%
        exit /b 0
    )
)

REM Attempt 3: pandoc default
pandoc "%MD_FILE%" -o "%PDF_FILE%" -V geometry:margin=2.5cm 2>nul
if %errorlevel% equ 0 (
    echo [OK] PDF generated: %PDF_FILE%
    exit /b 0
)

echo [WARN] pandoc PDF failed. Trying Python fallback...
"{self.python_exe}" convert_to_pdf.py 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] All PDF conversion methods failed.
    echo   Install MiKTeX: https://miktex.org
    echo   Or weasyprint: pip install weasyprint
)
endlocal
"""
        path = self.job.report("convert_to_pdf.bat")
        with open(path, "w", encoding="utf-8", newline="\r\n") as fh:
            fh.write(content)

    # ------------------------------------------------------------------
    # Python fallback (xhtml2pdf — pure Python, cross-platform)
    # ------------------------------------------------------------------

    def _write_python_fallback(self, md_path: Path, pdf_name: str) -> None:
        md_file = md_path.name
        content = f"""#!/usr/bin/env python3
\"\"\"
Pure Python PDF conversion fallback using xhtml2pdf.
Requires: pip install xhtml2pdf markdown
\"\"\"
import sys
from pathlib import Path

script_dir = Path(__file__).parent
md_path = script_dir / "{md_file}"
pdf_path = script_dir / "{pdf_name}"

try:
    import markdown
    from xhtml2pdf import pisa
except ImportError as e:
    print(f"[ERROR] Missing dependency: {{e}}")
    print("  pip install xhtml2pdf markdown")
    sys.exit(1)

print(f"[*] Converting {{md_path.name}} -> {{pdf_path.name}} ...")

with open(md_path, "r", encoding="utf-8") as fh:
    md_content = fh.read()

html_body = markdown.markdown(
    md_content,
    extensions=["tables", "fenced_code", "nl2br"]
)

html = f\"\"\"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<style>
@page {{
    margin: 2.2cm 2cm 2.2cm 2cm;
    @frame footer {{
        -pdf-frame-content: footer_content;
        bottom: 0.8cm; margin-left: 1cm; margin-right: 1cm; height: 0.8cm;
    }}
}}
body {{
    font-family: Arial, Helvetica, sans-serif;
    font-size: 10.5pt;
    line-height: 1.45;
    color: #111;
}}
h1 {{
    font-size: 16pt;
    color: #1a1a2e;
    border-bottom: 2px solid #1a1a2e;
    padding-bottom: 4px;
    margin-top: 0.8em;
}}
h2 {{
    font-size: 13pt;
    color: #16213e;
    border-bottom: 1px solid #aaa;
    padding-bottom: 3px;
    margin-top: 0.4em;
    page-break-before: always;
}}
h3 {{ font-size: 11pt; color: #0f3460; margin-top: 0.6em; page-break-after: avoid; }}
p {{ margin: 0.4em 0; }}
table {{
    border-collapse: collapse;
    width: 100%;
    margin: 0.6em 0;
    font-size: 8.5pt;
    table-layout: fixed;
}}
th, td {{
    border: 1px solid #bbb;
    padding: 4px 6px;
    text-align: left;
    vertical-align: top;
    word-break: break-all;
    overflow-wrap: break-word;
}}
th {{
    background-color: #1a1a2e;
    color: #ffffff;
    font-weight: bold;
}}
code {{
    font-family: Courier, monospace;
    font-size: 8pt;
    background: #f0f0f0;
    padding: 1px 3px;
}}
pre {{
    font-family: Courier, monospace;
    font-size: 7.5pt;
    background: #f0f0f0;
    border-left: 3px solid #1a1a2e;
    padding: 6px 8px;
    margin: 0.5em 0;
    white-space: pre-wrap;
    word-break: break-all;
    overflow-wrap: break-word;
}}
blockquote {{
    border-left: 3px solid #e74c3c;
    margin: 0.6em 0;
    padding: 0.3em 0.8em;
    background: #fff5f5;
}}
ul, ol {{ margin: 0.4em 0; padding-left: 1.4em; }}
li {{ margin: 0.2em 0; }}
hr {{ border: none; border-top: 1px solid #ccc; margin: 0.8em 0; }}
#footer_content {{
    text-align: center;
    font-size: 8pt;
    color: #666;
}}
</style>
</head>
<body>
<div id="footer_content">LinuxAuditLog — Informe Forense</div>
{{html_body}}
</body>
</html>\"\"\"

try:
    with open(pdf_path, "wb") as pdf_fh:
        status = pisa.CreatePDF(html, dest=pdf_fh)
    if status.err:
        print(f"[ERROR] xhtml2pdf reported errors: {{status.err}}")
        sys.exit(1)
    print(f"[OK] PDF generated: {{pdf_path}}")
except Exception as e:
    print(f"[ERROR] xhtml2pdf failed: {{e}}")
    sys.exit(1)
"""
        path = self.job.report("convert_to_pdf.py")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
