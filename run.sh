#!/usr/bin/env bash
# LinuxAuditLog -- Lanzador completo (Linux / macOS / WSL)
# Uso: bash run.sh   |   chmod +x run.sh && ./run.sh
#
# Primera ejecucion: descarga uv, instala Python localmente en .tools/,
# crea el venv y guarda las rutas absolutas en .env.
# Ejecuciones siguientes: usa directamente las rutas del .env, sin internet.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
REQ_FILE="$SCRIPT_DIR/requirements.txt"
_ACQUIRE_PID=""

# -- Colores ------------------------------------------------------------------
if [ -t 1 ]; then
    GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; CYAN="\033[96m"
    BOLD="\033[1m"; RESET="\033[0m"
else
    GREEN=""; YELLOW=""; RED=""; CYAN=""; BOLD=""; RESET=""
fi
ok()   { echo -e "  ${GREEN}[OK]${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}[--]${RESET}  $*"; }
err()  { echo -e "  ${RED}[XX]${RESET}  $*"; }
info() { echo -e "  ${CYAN}[..]${RESET}  $*"; }

# Actualiza o agrega KEY=VALUE en el .env (descomenta si estaba comentado)
_set_env_var() {
    local key="$1" value="$2" found=0 tmp
    tmp=$(mktemp)
    while IFS= read -r line || [ -n "$line" ]; do
        if echo "$line" | grep -qE "^#?[[:space:]]*${key}[[:space:]]*="; then
            echo "${key}=${value}"
            found=1
        else
            echo "$line"
        fi
    done < "$ENV_FILE" > "$tmp"
    [ "$found" -eq 0 ] && echo "${key}=${value}" >> "$tmp"
    mv "$tmp" "$ENV_FILE"
}

# -- Ctrl+C: salida limpia ----------------------------------------------------
_cleanup() {
    echo ""
    echo -e "  ${YELLOW}[--]${RESET}  Interrupcion (Ctrl+C) -- saliendo."
    [ -n "$_ACQUIRE_PID" ] && kill "$_ACQUIRE_PID" 2>/dev/null || true
    exit 130
}
trap '_cleanup' INT TERM

echo ""
echo -e "${BOLD}======================================================${RESET}"
echo -e "${BOLD}  LinuxAuditLog v1.5.0 -- Forensic Acquisition Agent${RESET}"
echo -e "${BOLD}======================================================${RESET}"

# -- Leer rutas desde .env ----------------------------------------------------
TOOLS_DIR="$SCRIPT_DIR/.tools"
VENV_DIR=""
PYTHON_PATH=""
PYTHON_VERSION="3.11"

if [ -f "$ENV_FILE" ]; then
    _td=$(grep -E '^TOOLS_DIR=(.+)$'      "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
    _vd=$(grep -E '^VENV_PATH=(.+)$'      "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
    _pp=$(grep -E '^PYTHON_PATH=(.+)$'    "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
    _pv=$(grep -E '^PYTHON_VERSION=(.+)$' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
    [ -n "$_td" ] && TOOLS_DIR="$_td"
    [ -n "$_vd" ] && VENV_DIR="$_vd"
    [ -n "$_pp" ] && PYTHON_PATH="$_pp"
    [ -n "$_pv" ] && PYTHON_VERSION="$_pv"
    unset _td _vd _pp _pv
fi

UV="$TOOLS_DIR/uv"

# -- 1. Python ----------------------------------------------------------------
# Si PYTHON_PATH esta en .env y funciona, se usa directamente.
# Si no, se descarga uv, instala Python local y guarda la ruta en .env.

_python_ok=0
if [ -n "$PYTHON_PATH" ] && [ -x "$PYTHON_PATH" ]; then
    "$PYTHON_PATH" -c "import sys" 2>/dev/null && _python_ok=1
fi

if [ "$_python_ok" -eq 0 ]; then
    info "Python no encontrado en .env -- iniciando instalacion local..."
    mkdir -p "$TOOLS_DIR"
    export UV_PYTHON_INSTALL_DIR="$TOOLS_DIR/python"
    export UV_CACHE_DIR="$TOOLS_DIR/cache"

    if [ ! -f "$UV" ]; then
        info "Descargando uv (~4 MB)..."
        ARCH=$(uname -m)
        case "$(uname -s)" in
            Linux*)
                case "$ARCH" in
                    x86_64)  PLATFORM="x86_64-unknown-linux-musl" ;;
                    aarch64) PLATFORM="aarch64-unknown-linux-musl" ;;
                    armv7l)  PLATFORM="armv7-unknown-linux-musleabihf" ;;
                    *) err "Arquitectura no soportada: $ARCH"; exit 1 ;;
                esac ;;
            Darwin*)
                case "$ARCH" in
                    x86_64) PLATFORM="x86_64-apple-darwin" ;;
                    arm64)  PLATFORM="aarch64-apple-darwin" ;;
                    *) err "Arquitectura no soportada: $ARCH"; exit 1 ;;
                esac ;;
            *) err "SO no soportado: $(uname -s)"; exit 1 ;;
        esac
        URL="https://github.com/astral-sh/uv/releases/latest/download/uv-${PLATFORM}.tar.gz"
        TMP=$(mktemp -d)
        if command -v curl &>/dev/null; then
            curl -fsSL "$URL" | tar xz -C "$TMP"
        elif command -v wget &>/dev/null; then
            wget -qO- "$URL" | tar xz -C "$TMP"
        else
            rm -rf "$TMP"; err "Se requiere curl o wget."; exit 1
        fi
        if ! mv "$TMP"/*/uv "$UV" 2>/dev/null; then
            rm -rf "$TMP"; err "Fallo al descargar uv."; exit 1
        fi
        rm -rf "$TMP"
        chmod +x "$UV"
        ok "uv descargado -> .tools/uv"
    else
        ok "uv listo"
    fi

    info "Instalando Python ${PYTHON_VERSION} en .tools/python/ ..."
    "$UV" python install "$PYTHON_VERSION"
    if [ $? -ne 0 ]; then err "No se pudo instalar Python ${PYTHON_VERSION}."; exit 1; fi

    PYTHON_PATH=$("$UV" python find "$PYTHON_VERSION" 2>/dev/null | tr -d '[:space:]')
    if [ -z "$PYTHON_PATH" ] || [ ! -x "$PYTHON_PATH" ]; then
        err "No se encontro el ejecutable de Python. Revisa .tools/python/"; exit 1
    fi

    _set_env_var "PYTHON_PATH" "$PYTHON_PATH"
    ok "Python ${PYTHON_VERSION} instalado -> $PYTHON_PATH"
    ok "Ruta guardada en .env  (PYTHON_PATH)"
else
    ok "Python listo -> $PYTHON_PATH"
fi

# -- 2. Entorno virtual -------------------------------------------------------
# Si VENV_PATH no esta en .env, se define como <proyecto>/.venv (absoluto).
# Si el venv no funciona se recrea usando PYTHON_PATH.

if [ -z "$VENV_DIR" ]; then
    VENV_DIR="$SCRIPT_DIR/.venv"
    _set_env_var "VENV_PATH" "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"

_venv_ok=0
if [ -f "$VENV_PYTHON" ]; then
    "$VENV_PYTHON" -c "import sys" 2>/dev/null && _venv_ok=1
fi

if [ "$_venv_ok" -eq 0 ]; then
    [ -d "$VENV_DIR" ] && { info "Venv no funciona - recreando..."; rm -rf "$VENV_DIR"; }
    info "Creando entorno virtual..."
    "$PYTHON_PATH" -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then err "No se pudo crear el entorno virtual."; exit 1; fi
    _set_env_var "VENV_PATH" "$VENV_DIR"
    ok "Entorno virtual creado -> $VENV_DIR"
    ok "Ruta guardada en .env  (VENV_PATH)"
else
    ok "Entorno virtual listo -> $VENV_DIR"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
ok "Entorno virtual activado"

# -- 3. Dependencias ----------------------------------------------------------
if [ -f "$REQ_FILE" ]; then
    info "Verificando dependencias..."
    if [ -f "$UV" ]; then
        "$UV" pip install --quiet -r "$REQ_FILE" --python "$VENV_DIR"
    else
        "$VENV_PYTHON" -m pip install --quiet -r "$REQ_FILE"
    fi
    if [ $? -ne 0 ]; then err "pip install fallo."; exit 1; fi
    ok "Dependencias instaladas"
else
    warn "requirements.txt no encontrado"
fi

# -- 4. Variables de entorno --------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
    err ".env no encontrado. Copia .env.example y edita tus credenciales SSH:"
    err "  cp .env.example .env && nano .env"
    exit 1
fi

while IFS='=' read -r key value; do
    key="${key#"${key%%[![:space:]]*}"}"
    [ -z "$key" ] || [[ "$key" == \#* ]] && continue
    export "$key"="$value"
done < "$ENV_FILE"

echo ""
ok "Variables SSH listas"
echo "       SSH_HOST = ${SSH_HOST:-<no definido>}"
echo "       SSH_USER = ${SSH_USER:-<no definido>}"
echo "       SSH_PORT = ${SSH_PORT:-22}"
echo "       SSH_PASS = ***"
echo ""

# -- 5. Ejecutar --------------------------------------------------------------
echo -e "${BOLD}  Iniciando adquisicion...${RESET}"
echo ""
"$VENV_PYTHON" "$SCRIPT_DIR/acquire.py" &
_ACQUIRE_PID=$!
wait $_ACQUIRE_PID
_EXIT=$?
_ACQUIRE_PID=""
exit $_EXIT
