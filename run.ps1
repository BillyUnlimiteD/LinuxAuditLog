# LinuxAuditLog -- Lanzador completo (PowerShell)
# Uso: .\run.ps1
#
# Primera ejecucion: descarga uv, instala Python localmente en .tools\,
# crea el venv y guarda las rutas absolutas en .env.
# Ejecuciones siguientes: usa directamente las rutas del .env, sin internet.
#
# Si la politica de ejecucion bloquea el script:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile   = Join-Path $ScriptDir ".env"
$ReqFile   = Join-Path $ScriptDir "requirements.txt"

function ok   { param($m) Write-Host "  [OK]  $m" -ForegroundColor Green }
function warn { param($m) Write-Host "  [--]  $m" -ForegroundColor Yellow }
function err  { param($m) Write-Host "  [XX]  $m" -ForegroundColor Red }
function info { param($m) Write-Host "  [..]  $m" -ForegroundColor Cyan }

# Actualiza o agrega KEY=VALUE en el .env (descomenta si estaba comentado)
function Update-EnvFile {
    param($File, $Key, $Value)
    $lines = if (Test-Path $File) { Get-Content $File } else { @() }
    $found = $false
    $result = @(foreach ($line in $lines) {
        if ($line -match "^#?\s*${Key}\s*=") { $found = $true; "${Key}=${Value}" }
        else { $line }
    })
    if (-not $found) { $result += "${Key}=${Value}" }
    $result | Set-Content -Path $File -Encoding UTF8
}

# -- Ctrl+C: salida limpia ----------------------------------------------------
$cancelHandler = [System.ConsoleCancelEventHandler]{
    param($src, $e)
    $e.Cancel = $true
    Write-Host ""
    Write-Host "  [--]  Interrumpido (Ctrl+C)." -ForegroundColor Yellow
    [System.Environment]::Exit(130)
}
[Console]::add_CancelKeyPress($cancelHandler)

Write-Host ""
Write-Host "======================================================" -ForegroundColor White
Write-Host "  LinuxAuditLog v1.6.0 -- Forensic Acquisition Agent"   -ForegroundColor White
Write-Host "======================================================" -ForegroundColor White

# -- Leer rutas desde .env ----------------------------------------------------
$ToolsDir      = Join-Path $ScriptDir ".tools"
$VenvDir       = ""
$PythonPath    = ""
$PythonVersion = "3.11"

if (Test-Path $EnvFile) {
    $envLines = Get-Content $EnvFile
    $m = $envLines | Select-String "^TOOLS_DIR=(.+)$"
    if ($m) { $ToolsDir = $m.Matches[0].Groups[1].Value.Trim() }
    $m = $envLines | Select-String "^VENV_PATH=(.+)$"
    if ($m) { $VenvDir = $m.Matches[0].Groups[1].Value.Trim() }
    $m = $envLines | Select-String "^PYTHON_PATH=(.+)$"
    if ($m) { $PythonPath = $m.Matches[0].Groups[1].Value.Trim() }
    $m = $envLines | Select-String "^PYTHON_VERSION=(.+)$"
    if ($m) { $PythonVersion = $m.Matches[0].Groups[1].Value.Trim() }
}

$UV = Join-Path $ToolsDir "uv.exe"

# -- 1. Python ----------------------------------------------------------------
# Si PYTHON_PATH esta en .env y funciona, se usa directamente.
# Si no, se descarga uv, instala Python local y guarda la ruta en .env.

$pythonOk = $false
if ($PythonPath -and (Test-Path $PythonPath)) {
    & $PythonPath -c "import sys" 2>$null | Out-Null
    $pythonOk = ($LASTEXITCODE -eq 0)
}

if (-not $pythonOk) {
    info "Python no encontrado en .env -- iniciando instalacion local..."
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
    $env:UV_PYTHON_INSTALL_DIR = Join-Path $ToolsDir "python"
    $env:UV_CACHE_DIR           = Join-Path $ToolsDir "cache"

    if (-not (Test-Path $UV)) {
        info "Descargando uv (~4 MB)..."
        $arch = "x86_64"
        try {
            if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq `
                [System.Runtime.InteropServices.Architecture]::Arm64) { $arch = "aarch64" }
        } catch { }
        $uvUrl  = "https://github.com/astral-sh/uv/releases/latest/download/uv-${arch}-pc-windows-msvc.zip"
        $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) "uv_dl.zip"
        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "uv_ex"
        try {
            Invoke-WebRequest -Uri $uvUrl -OutFile $tmpZip -UseBasicParsing
            Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force
            $uvExe = Get-ChildItem -Path $tmpDir -Filter "uv.exe" -Recurse | Select-Object -First 1
            Move-Item $uvExe.FullName $UV -Force
            ok "uv descargado -> .tools\uv.exe"
        } catch {
            err "Error descargando uv: $_"; exit 1
        } finally {
            Remove-Item $tmpZip -ErrorAction SilentlyContinue
            Remove-Item $tmpDir -Recurse -ErrorAction SilentlyContinue
        }
    } else {
        ok "uv listo"
    }

    info "Instalando Python ${PythonVersion} en .tools\python\ ..."
    & $UV python install $PythonVersion
    if ($LASTEXITCODE -ne 0) { err "No se pudo instalar Python ${PythonVersion}."; exit 1 }

    $PythonPath = (& $UV python find $PythonVersion 2>$null).Trim()
    if (-not $PythonPath -or -not (Test-Path $PythonPath)) {
        err "No se encontro el ejecutable de Python. Revisa .tools\python\."; exit 1
    }

    Update-EnvFile $EnvFile "PYTHON_PATH" $PythonPath
    ok "Python ${PythonVersion} instalado -> $PythonPath"
    ok "Ruta guardada en .env  (PYTHON_PATH)"
} else {
    ok "Python listo -> $PythonPath"
}

# -- 2. Entorno virtual -------------------------------------------------------
# Si VENV_PATH no esta en .env, se define como <proyecto>\.venv (absoluto).
# Si el venv no funciona se recrea usando PYTHON_PATH.

if (-not $VenvDir) {
    $VenvDir = Join-Path $ScriptDir ".venv"
    Update-EnvFile $EnvFile "VENV_PATH" $VenvDir
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

$venvOk = (Test-Path $VenvPython)
if ($venvOk) {
    & $VenvPython -c "import sys" 2>$null | Out-Null
    $venvOk = ($LASTEXITCODE -eq 0)
}

if (-not $venvOk) {
    if (Test-Path $VenvDir) {
        info "Venv no funciona - recreando..."
        Remove-Item $VenvDir -Recurse -Force
    }
    info "Creando entorno virtual..."
    & $PythonPath -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { err "No se pudo crear el entorno virtual."; exit 1 }

    $absVenv = (Resolve-Path $VenvDir).Path
    Update-EnvFile $EnvFile "VENV_PATH" $absVenv
    $VenvDir    = $absVenv
    $VenvPython = Join-Path $VenvDir "Scripts\python.exe"
    ok "Entorno virtual creado -> $VenvDir"
    ok "Ruta guardada en .env  (VENV_PATH)"
} else {
    ok "Entorno virtual listo -> $VenvDir"
}

& (Join-Path $VenvDir "Scripts\Activate.ps1")
ok "Entorno virtual activado"

# -- 3. Dependencias ----------------------------------------------------------
if (Test-Path $ReqFile) {
    info "Verificando dependencias..."
    if (Test-Path $UV) {
        & $UV pip install --quiet -r $ReqFile --python $VenvDir
    } else {
        & $VenvPython -m pip install --quiet -r $ReqFile
    }
    if ($LASTEXITCODE -ne 0) { err "pip install fallo."; exit 1 }
    ok "Dependencias instaladas"
} else {
    warn "requirements.txt no encontrado"
}

# -- 4. Variables de entorno --------------------------------------------------
if (-not (Test-Path $EnvFile)) {
    err ".env no encontrado. Copia .env.example y edita tus credenciales SSH."
    exit 1
}

Get-Content $EnvFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line -match "^([^=]+)=(.*)$") {
        $key   = $Matches[1].Trim()
        $value = $Matches[2].Trim()
        [System.Environment]::SetEnvironmentVariable($key, $value, "Process")
        Set-Item -Path "Env:\$key" -Value $value
    }
}

Write-Host ""
ok "Variables SSH listas"
Write-Host "       SSH_HOST = $env:SSH_HOST"
Write-Host "       SSH_USER = $env:SSH_USER"
Write-Host "       SSH_PORT = $env:SSH_PORT"
Write-Host "       SSH_PASS = ***"
Write-Host ""

# -- 5. Ejecutar --------------------------------------------------------------
Write-Host "  Iniciando adquisicion..." -ForegroundColor White
Write-Host ""
& $VenvPython (Join-Path $ScriptDir "acquire.py")
