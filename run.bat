@echo off
REM LinuxAuditLog -- Lanzador completo (Windows CMD)
REM Uso: run.bat
REM
REM Primera ejecucion: descarga uv, instala Python local en .tools\,
REM crea el venv y guarda las rutas absolutas en .env.
REM Ejecuciones siguientes: usa directamente las rutas del .env, sin internet.

SETLOCAL ENABLEDELAYEDEXPANSION
BREAK OFF

SET "SCRIPT_DIR=%~dp0"
SET "ENV_FILE=%SCRIPT_DIR%.env"
SET "REQ_FILE=%SCRIPT_DIR%requirements.txt"

REM -- Valores por defecto (se sobreescriben desde .env) ---------------------
SET "TOOLS_DIR=%SCRIPT_DIR%.tools"
SET "VENV_DIR="
SET "PYTHON_PATH="
SET "PYTHON_VERSION=3.11"

REM -- Leer rutas desde .env -------------------------------------------------
IF EXIST "%ENV_FILE%" (
    FOR /F "usebackq tokens=1,* delims==" %%A IN ("%ENV_FILE%") DO (
        SET "_K=%%A"
        IF NOT "%%A"=="" IF NOT "!_K:~0,1!"=="#" (
            IF "%%A"=="TOOLS_DIR"      SET "TOOLS_DIR=%%B"
            IF "%%A"=="VENV_PATH"      SET "VENV_DIR=%%B"
            IF "%%A"=="PYTHON_PATH"    SET "PYTHON_PATH=%%B"
            IF "%%A"=="PYTHON_VERSION" SET "PYTHON_VERSION=%%B"
        )
    )
)

SET "UV=%TOOLS_DIR%\uv.exe"

echo.
echo ======================================================
echo   LinuxAuditLog v1.6.0 -- Forensic Acquisition Agent
echo ======================================================

REM -- 1. Python ---------------------------------------------------------------
REM Si PYTHON_PATH esta en .env y funciona, se usa directamente.
REM Si no, se descarga uv, instala Python local y guarda la ruta en .env.

SET "_PYTHON_OK=0"
IF NOT "!PYTHON_PATH!"=="" (
    IF EXIST "!PYTHON_PATH!" (
        "!PYTHON_PATH!" -c "import sys" >nul 2>&1
        IF !ERRORLEVEL! EQU 0 SET "_PYTHON_OK=1"
    )
)

IF "!_PYTHON_OK!"=="0" (
    echo   [..]  Python no encontrado en .env -- iniciando instalacion local...
    IF NOT EXIST "%TOOLS_DIR%" MKDIR "%TOOLS_DIR%"
    SET "UV_PYTHON_INSTALL_DIR=%TOOLS_DIR%\python"
    SET "UV_CACHE_DIR=%TOOLS_DIR%\cache"

    IF NOT EXIST "%UV%" (
        echo   [..]  Descargando uv ^(~4 MB^)...
        powershell -NoProfile -ExecutionPolicy Bypass -Command ^
            "$zip=[IO.Path]::Combine([IO.Path]::GetTempPath(),'uv_dl.zip');" ^
            "$dir=[IO.Path]::Combine([IO.Path]::GetTempPath(),'uv_ex');" ^
            "Invoke-WebRequest 'https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip' -OutFile $zip -UseBasicParsing;" ^
            "Expand-Archive $zip $dir -Force;" ^
            "$f=(Get-ChildItem $dir -Filter uv.exe -Recurse|Select -First 1);" ^
            "Move-Item $f.FullName '%UV%' -Force;" ^
            "Remove-Item $zip,$dir -Recurse -ErrorAction SilentlyContinue"
        IF !ERRORLEVEL! NEQ 0 ( echo   [XX]  No se pudo descargar uv. & EXIT /B 1 )
        echo   [OK]  uv descargado -^> .tools\uv.exe
    ) ELSE (
        echo   [OK]  uv listo
    )

    echo   [..]  Instalando Python %PYTHON_VERSION% en .tools\python\ ...
    "%UV%" python install %PYTHON_VERSION%
    IF !ERRORLEVEL! NEQ 0 ( echo   [XX]  No se pudo instalar Python. & EXIT /B 1 )

    FOR /F "delims=" %%P IN ('"%UV%" python find %PYTHON_VERSION% 2^>nul') DO SET "PYTHON_PATH=%%P"
    IF "!PYTHON_PATH!"=="" ( echo   [XX]  No se encontro el ejecutable Python. & EXIT /B 1 )

    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "$f='%ENV_FILE%'; $k='PYTHON_PATH'; $v='!PYTHON_PATH!';" ^
        "$lines=Get-Content $f; $found=$false;" ^
        "$new=@(foreach($l in $lines){if($l -match '^#?\s*'+$k+'\s*='){$found=$true;$k+'='+$v}else{$l}});" ^
        "if(-not $found){$new+=$k+'='+$v}; $new|Set-Content $f -Encoding UTF8"
    echo   [OK]  Python %PYTHON_VERSION% instalado -^> !PYTHON_PATH!
    echo   [OK]  Ruta guardada en .env  ^(PYTHON_PATH^)
) ELSE (
    echo   [OK]  Python listo -^> !PYTHON_PATH!
)

REM -- 2. Entorno virtual ------------------------------------------------------
REM Si VENV_PATH no esta en .env, se define como <proyecto>\.venv (absoluto).
REM Si el venv no funciona se recrea usando PYTHON_PATH.

IF "!VENV_DIR!"=="" (
    SET "VENV_DIR=%SCRIPT_DIR%.venv"
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "$f='%ENV_FILE%'; $k='VENV_PATH'; $v='!VENV_DIR!';" ^
        "$lines=Get-Content $f; $found=$false;" ^
        "$new=@(foreach($l in $lines){if($l -match '^#?\s*'+$k+'\s*='){$found=$true;$k+'='+$v}else{$l}});" ^
        "if(-not $found){$new+=$k+'='+$v}; $new|Set-Content $f -Encoding UTF8"
)

SET "_VENV_OK=0"
IF EXIST "!VENV_DIR!\Scripts\python.exe" (
    "!VENV_DIR!\Scripts\python.exe" -c "import sys" >nul 2>&1
    IF !ERRORLEVEL! EQU 0 SET "_VENV_OK=1"
)

IF "!_VENV_OK!"=="0" (
    IF EXIST "!VENV_DIR!" (
        echo   [..]  Venv no funciona - recreando...
        RMDIR /S /Q "!VENV_DIR!"
    )
    echo   [..]  Creando entorno virtual...
    "!PYTHON_PATH!" -m venv "!VENV_DIR!"
    IF !ERRORLEVEL! NEQ 0 ( echo   [XX]  No se pudo crear el entorno virtual. & EXIT /B 1 )
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "$f='%ENV_FILE%'; $k='VENV_PATH'; $v='!VENV_DIR!';" ^
        "$lines=Get-Content $f; $found=$false;" ^
        "$new=@(foreach($l in $lines){if($l -match '^#?\s*'+$k+'\s*='){$found=$true;$k+'='+$v}else{$l}});" ^
        "if(-not $found){$new+=$k+'='+$v}; $new|Set-Content $f -Encoding UTF8"
    echo   [OK]  Entorno virtual creado -^> !VENV_DIR!
    echo   [OK]  Ruta guardada en .env  ^(VENV_PATH^)
) ELSE (
    echo   [OK]  Entorno virtual listo -^> !VENV_DIR!
)

CALL "!VENV_DIR!\Scripts\activate.bat"
echo   [OK]  Entorno virtual activado

REM -- 3. Dependencias ---------------------------------------------------------
IF EXIST "%REQ_FILE%" (
    echo   [..]  Verificando dependencias...
    IF EXIST "%UV%" (
        "%UV%" pip install --quiet -r "%REQ_FILE%" --python "!VENV_DIR!"
    ) ELSE (
        "!VENV_DIR!\Scripts\python.exe" -m pip install --quiet -r "%REQ_FILE%"
    )
    IF !ERRORLEVEL! NEQ 0 ( echo   [XX]  pip install fallo. & EXIT /B 1 )
    echo   [OK]  Dependencias instaladas
) ELSE (
    echo   [--]  requirements.txt no encontrado
)

REM -- 4. Variables de entorno -------------------------------------------------
IF NOT EXIST "%ENV_FILE%" (
    echo   [XX]  .env no encontrado.
    echo         Copia .env.example y edita tus credenciales SSH.
    EXIT /B 1
)

FOR /F "usebackq tokens=1,* delims==" %%A IN ("%ENV_FILE%") DO (
    SET "_K=%%A"
    IF NOT "%%A"=="" IF NOT "!_K:~0,1!"=="#" SET "%%A=%%B"
)

echo.
echo   [OK]  Variables SSH listas
echo          SSH_HOST=%SSH_HOST%
echo          SSH_USER=%SSH_USER%
echo          SSH_PORT=%SSH_PORT%
echo          SSH_PASS=***
echo.

REM -- 5. Ejecutar -------------------------------------------------------------
echo   Iniciando adquisicion...
echo.
BREAK ON
"!VENV_DIR!\Scripts\python.exe" "%SCRIPT_DIR%acquire.py"
SET "_EXIT=!ERRORLEVEL!"

IF !_EXIT! EQU 0 GOTO :END
IF !_EXIT! EQU 130 ( echo. & echo   [--]  Interrumpido. & GOTO :END )
echo. & echo   [XX]  acquire.py termino con codigo !_EXIT!.

:END
ENDLOCAL
EXIT /B %_EXIT%
