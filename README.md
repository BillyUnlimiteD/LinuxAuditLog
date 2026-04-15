# LinuxAuditLog v1.6.0

**Agente forense de adquisición remota y análisis de seguridad Linux**

Herramienta de adquisición forense remota sobre SSH con análisis local determinístico, generación de informe pericial en español o inglés, exportación PDF automática y generación de prompts listos para consultar a una IA por cada hallazgo. Sin credenciales en disco. Sin dependencias de servicios en la nube.

---

## Índice

1. [Requisitos](#1-requisitos)
2. [Instalación](#2-instalación)
3. [Uso rápido](#3-uso-rápido)
4. [Arquitectura en dos etapas](#4-arquitectura-en-dos-etapas)
5. [Estructura de salida](#5-estructura-de-salida)
6. [Generación automática de PDF](#6-generación-automática-de-pdf)
7. [Reporte de prompts IA](#7-reporte-de-prompts-ia)
8. [Actualizar el diccionario de reglas](#8-actualizar-el-diccionario-de-reglas)
9. [Formato de reglas YAML](#9-formato-de-reglas-yaml)
10. [Añadir reglas personalizadas](#10-añadir-reglas-personalizadas)
11. [Motor IOC — Rendimiento](#11-motor-ioc--rendimiento)
12. [Consideraciones de seguridad](#12-consideraciones-de-seguridad)
13. [Referencia de variables de entorno](#13-referencia-de-variables-de-entorno)
14. [Resolución de problemas](#14-resolución-de-problemas)

---

## 1. Requisitos

| Componente | Versión mínima | Obligatorio | Notas |
|---|---|---|---|
| Python | 3.11 | Si | Requerido para todo |
| pandoc | 2.x | No | Mejor calidad de PDF |
| TeX Live / MiKTeX | cualquiera | No | PDF con pandoc + XeLaTeX |
| wkhtmltopdf | 0.12.x | No | Alternativa a XeLaTeX |

> Las dependencias Python (incluyendo `xhtml2pdf` para PDF sin pandoc) se instalan automáticamente con `setup_env.py`.

> **Acceso remoto:** el usuario SSH debe poder ejecutar `journalctl`, `systemctl`, `ss`/`netstat` y `ps`, y leer `/var/log/`. No requiere `root` (ver variable `SSH_ROOT_PASS` para acceso elevado).

---

## 2. Instalación

No se requiere instalacion previa. Los scripts `run` se encargan de todo en la primera ejecucion: descargan `uv`, instalan Python 3.11 localmente en `.tools/`, crean el entorno virtual e instalan las dependencias. En ejecuciones posteriores usan las rutas guardadas en `.env` sin acceso a internet.

**Paquetes instalados automaticamente:**
`asyncssh`, `duckdb`, `jinja2`, `pyyaml`, `requests`, `markdown`, `xhtml2pdf`

---

## 3. Uso rápido

### Paso 1 — Configurar credenciales

Crea el archivo `.env` en la raíz del proyecto con los datos del host a analizar:

```bash
cp .env.example .env      # Linux / macOS
copy .env.example .env    # Windows
```

Edita `.env` con las credenciales reales:

```ini
SSH_HOST=192.168.1.100
SSH_USER=admin
SSH_PASS=tu_contrasena
SSH_PORT=22
# Opcional: contraseña de root para acceder a logs protegidos (ver sección 11)
# SSH_ROOT_PASS=contrasena_root
```

> `.env` está en `.gitignore` y **nunca se sube al repositorio**. Las credenciales se cargan en memoria al inicio y se destruyen al cerrar la conexión SSH.

### Paso 2 — Ejecutar

Lanza el script correspondiente a tu plataforma. En la primera ejecucion instala todo automaticamente:

```powershell
# Windows PowerShell (recomendado en Windows)
.\run.ps1
```

```cmd
REM Windows CMD
run.bat
```

```bash
# Linux / macOS / WSL
bash run.sh
```

> Si PowerShell bloquea la ejecucion de scripts: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

Al finalizar, el directorio de trabajo se encuentra en `jobs/<YYYYMMDD_HHMMSS_host>/`. El informe Markdown **y su PDF** se generan automáticamente — no se requiere ningún paso adicional.

> Las variables de entorno del sistema tienen **prioridad** sobre el `.env`. Si una variable ya está definida en el entorno, el valor del `.env` se ignora.

---

## 4. Arquitectura en dos etapas

```
┌─────────────────────────────────────────────────────────┐
│  ETAPA A — ADQUISICION REMOTA (SSH)                     │
│                                                         │
│  1. Conexion SSH efimera (asyncssh)                     │
│  2. Deteccion de SO, kernel e init system               │
│     (systemd / OpenRC / runit / s6 / SysV)              │
│  3. Inventario de servicios activos y puertos           │
│  4. Exportacion de logs (journalctl + archivos)         │
│     - Canal raiz persistente: su root al conectar       │
│       (SSH_ROOT_PASS), todos los comandos como root     │
│     - Barrido recursivo: /var/log /var/opt /opt         │
│       /srv /var/www — sin limite de archivos            │
│     - Recoleccion de logs rotados (secure-YYYYMMDD.gz,  │
│       auth.log.2.gz, etc.) para cobertura extendida     │
│     - Conversion a JSONL estructurado en origen         │
│     - Fallback: sudo -n → sin privilegios               │
│     - Limite: 50.000 lineas por fuente                  │
│  5. Hash SHA-256 de todos los artefactos (MANIFEST)     │
│  6. Cierre explicito de la conexion SSH                 │
│  7. Destruccion de credenciales de memoria              │
└─────────────────────────────────────────────────────────┘
                          │  (sin red desde aqui)
                          ▼
┌─────────────────────────────────────────────────────────┐
│  ETAPA B — ANALISIS LOCAL (sin conexion)                │
│                                                         │
│  1. Normalizacion de logs → JSONL unificado             │
│     - Parser JSONL de Stage A (formato estructurado)    │
│     - Parser de audit log Linux (type=SYSCALL, AVC...)  │
│     - cache JSONL en re-ejecuciones sin cambios         │
│  2. Rule Advisor: cobertura de reglas por servicio      │
│     (crea stubs para servicios desconocidos)            │
│  3. Timeline unificado → CSV ordenado por tiempo        │
│  4. Motor IOC: evalua 48 reglas YAML (pattern/          │
│     threshold/sequence) con mapeo MITRE ATT&CK          │
│     (indice de servicio case-insensitive: ~83x)         │
│  5. Correlacion por IP, usuario y servicio (DuckDB)     │
│  6. Generacion del informe forense en Markdown          │
│  7. Generacion automatica del PDF del informe           │
│  8. Generacion del reporte de prompts IA (.md + .pdf)   │
│     (un prompt por hallazgo, listo para copiar/pegar)   │
└─────────────────────────────────────────────────────────┘
```

**Principio de mínimo impacto:** la Etapa A solo ejecuta comandos de lectura. No escribe archivos en el host remoto, no instala agentes ni modifica configuraciones.

---

## 5. Estructura de salida

Cada ejecucion genera un directorio de trabajo independiente:

```
jobs/
└── 20240115_143022_192-168-1-100/
    ├── 01_evidence/
    │   ├── raw/
    │   │   ├── logs/
    │   │   │   ├── journalctl_system.gz
    │   │   │   ├── auth.log.gz
    │   │   │   ├── nginx_access.gz
    │   │   │   └── ...
    │   │   ├── system_info.json
    │   │   ├── services_inventory.json
    │   │   ├── ports_inventory.json
    │   │   └── acquisition_log.json
    │   ├── MANIFEST.json          <- hashes SHA-256 de todos los artefactos
    │   └── MANIFEST.sig.json      <- firma del manifiesto
    │
    ├── 02_analysis/
    │   ├── all_entries.jsonl      <- entradas de log unificadas (cache)
    │   ├── timeline.csv           <- eventos ordenados cronologicamente
    │   ├── correlations.json      <- correlaciones IP/usuario/servicio
    │   └── rule_coverage.json     <- cobertura de reglas por servicio
    │
    └── 03_report/
        ├── report_20240115_143022_192-168-1-100.md        <- informe pericial
        ├── report_20240115_143022_192-168-1-100.pdf       <- PDF del informe
        ├── ai_prompts_20240115_143022_192-168-1-100.md    <- prompts IA
        ├── ai_prompts_20240115_143022_192-168-1-100.pdf   <- PDF de prompts
        ├── convert_to_pdf.sh      <- conversion Linux/macOS (manual)
        ├── convert_to_pdf.bat     <- conversion Windows (manual)
        └── convert_to_pdf.py      <- conversion Python (manual)
```

### Descripcion de archivos clave

| Archivo | Descripcion |
|---|---|
| `MANIFEST.json` | Lista de artefactos con hash SHA-256, tamaño y ruta relativa |
| `acquisition_log.json` | Registro de la adquisicion: comandos ejecutados, errores, timestamps |
| `all_entries.jsonl` | Todas las entradas de log normalizadas en formato JSONL (cache) |
| `timeline.csv` | Timeline unificado: timestamp, hostname, service, src_ip, user, message |
| `correlations.json` | Resumen estadistico: IPs mas activas, usuarios, errores por servicio |
| `rule_coverage.json` | Que reglas se aplicaron a que servicios detectados |
| `report_<job_id>.md` | Informe forense completo en español (Markdown) |
| `report_<job_id>.pdf` | PDF del informe, generado automaticamente al terminar el analisis |
| `ai_prompts_<job_id>.md` | Prompts listos para IA, uno por hallazgo (Markdown) |
| `ai_prompts_<job_id>.pdf` | PDF del reporte de prompts IA |

---

## 6. Generación automática de PDF

El PDF del informe forense se genera **automáticamente** al finalizar la Etapa B. No es necesario ejecutar ningún script adicional.

### Motor de conversión PDF

El sistema prueba los motores disponibles en este orden de preferencia:

1. `pandoc + XeLaTeX` — mayor calidad tipográfica, soporte Unicode completo
2. `pandoc + wkhtmltopdf` — buena calidad, sin dependencias TeX
3. `pandoc (html)` — salida HTML básica via pandoc
4. **`xhtml2pdf`** — **motor por defecto**, Python puro, sin dependencias de sistema

`xhtml2pdf` está incluido en `requirements.txt` y siempre disponible. En la mayoría de instalaciones será el motor activo.

### Regenerar el PDF manualmente

Si necesitas regenerar el PDF de un informe existente, desde el directorio `03_report/` del job:

```powershell
# Windows PowerShell / CMD
convert_to_pdf.bat
```

```bash
# Linux / macOS / WSL
bash convert_to_pdf.sh
```

### PDF del README / manual

Para generar un PDF de esta documentacion (requiere venv creado):

```powershell
# Windows PowerShell
.venv\Scripts\python.exe scripts/readme_to_pdf.py
```

```bash
# Linux / macOS / WSL
.venv/bin/python scripts/readme_to_pdf.py
```

### Instalar pandoc (mejor calidad tipográfica)

```bash
# Ubuntu / Debian
sudo apt install pandoc texlive-xetex texlive-lang-spanish

# macOS
brew install pandoc && brew install --cask mactex

# Windows — descargar instaladores:
# pandoc:  https://pandoc.org/installing.html
# MiKTeX:  https://miktex.org/download
```

> Sin pandoc, `xhtml2pdf` genera el PDF directamente desde Python sin dependencias adicionales.

---

## 7. Reporte de prompts IA

Al finalizar cada análisis, el sistema genera automáticamente un segundo reporte (`ai_prompts_<job_id>.md` y su PDF) con un prompt estructurado por cada hallazgo de seguridad detectado. El prompt está diseñado para copiarse y pegarse directamente en cualquier IA (Claude, ChatGPT, Gemini, etc.) y obtener ayuda experta de inmediato.

### Contenido de cada prompt

Cada prompt incluye cinco bloques de contexto seguidos de una solicitud de ayuda estructurada:

| Bloque | Descripcion |
|---|---|
| **Contexto del sistema** | OS, hostname, kernel, arquitectura, init system, host analizado |
| **Alerta de seguridad** | Rule ID, titulo, severidad, confianza, tecnica MITRE, fechas |
| **Descripcion de la alerta** | Descripcion completa de lo que detecta la regla |
| **Entidades afectadas** | Usuarios, IPs y servicios implicados con conteo de eventos |
| **Eventos detectados** | Hasta 5 lineas de log reales del sistema con campos extraidos |
| **Recomendacion inicial** | Lo que sugiere la regla como primer paso de remediacion |
| **Posibles falsos positivos** | Contexto para que la IA no sobre-reaccione |

### Solicitud de ayuda incluida en cada prompt

Los prompts solicitan a la IA responder cinco preguntas concretas:

1. **Evaluacion** — ¿Es un indicador real de compromiso o un falso positivo?
2. **Investigacion forense** — Comandos concretos para confirmar o descartar el hallazgo
3. **Impacto** — Escenario de ataque mas probable si el hallazgo es real
4. **Remediacion inmediata** — Acciones priorizadas por urgencia
5. **Prevencion** — Configuraciones o controles para evitar que se repita

### Uso

El archivo PDF se genera en `03_report/` junto al informe forense. Abrirlo, localizar el hallazgo de interes, copiar el bloque de texto del prompt y pegarlo directamente en la IA:

```
03_report/
├── report_<job_id>.pdf          <- informe forense
└── ai_prompts_<job_id>.pdf      <- prompts IA (este archivo)
```

---

## 8. Actualizar el diccionario de reglas

El proyecto incluye un script para descargar reglas de la comunidad **SigmaHQ** y convertirlas al formato local. Requiere que el venv este creado (se crea la primera vez que ejecutas `run.ps1` / `run.sh` / `run.bat`):

```powershell
# Windows PowerShell
.venv\Scripts\python.exe scripts/update_rules.py --dry-run   # ver sin modificar
.venv\Scripts\python.exe scripts/update_rules.py              # actualizar
.venv\Scripts\python.exe scripts/update_rules.py --force      # sobreescribir
.venv\Scripts\python.exe scripts/update_rules.py --token ghp_xxxxxxxxxxxx
```

```bash
# Linux / macOS / WSL
.venv/bin/python scripts/update_rules.py --dry-run
.venv/bin/python scripts/update_rules.py
.venv/bin/python scripts/update_rules.py --force
.venv/bin/python scripts/update_rules.py --token ghp_xxxxxxxxxxxx
```

Las reglas se guardan en el directorio `rules/` con la misma estructura de categorias.

---

## 9. Formato de reglas YAML

Todas las reglas residen en `rules/` y siguen este esquema:

```yaml
id: LIN-AUTH-001                    # Identificador unico
title: SSH Brute Force Detection    # Titulo descriptivo
category: auth                      # Categoria principal
subcategory: brute_force            # Subcategoria
mitre_technique: T1110.001          # Tecnica MITRE ATT&CK
mitre_tactic: credential_access     # Tactica MITRE ATT&CK
severity: high                      # critical / high / medium / low
confidence: high                    # high / medium / low
enabled: true                       # true = activa, false = desactivada

description: >
  Descripcion detallada de lo que detecta esta regla.

service: sshd                       # Servicio al que aplica (* = todos)

detection:
  type: pattern                     # Ver tipos mas abajo

false_positives:
  - Administracion legitima

recommendation: >
  Pasos de remediacion recomendados.

references:
  - "https://attack.mitre.org/techniques/T1110/"

tags:
  - ssh
  - brute_force
```

### Tipos de deteccion

#### `pattern` — Coincidencia regex

```yaml
detection:
  type: pattern
  patterns:
    - regex: "Failed password for (?P<user>\\S+) from (?P<src_ip>[\\d.]+)"
    - regex: "Invalid user (?P<user>\\S+) from (?P<src_ip>[\\d.]+)"
```

Cada patron puede usar grupos nombrados (`?P<nombre>`) que se extraen como entidades afectadas.

#### `threshold` — Umbral de frecuencia

```yaml
detection:
  type: threshold
  patterns:
    - regex: "Failed password for (?P<user>\\S+) from (?P<src_ip>[\\d.]+)"
  aggregation:
    field: src_ip        # Agrupar por este campo extraido
    count: 10            # Numero de ocurrencias para activar
    window_sec: 300      # Ventana de tiempo en segundos
```

Se activa cuando el campo `field` supera `count` coincidencias en `window_sec` segundos.

#### `sequence` — Par de eventos ordenados

```yaml
detection:
  type: sequence
  patterns:
    - regex: "Failed password.*from (?P<src_ip>[\\d.]+)"   # Evento 1
    - regex: "Accepted.*from (?P<src_ip>[\\d.]+)"           # Evento 2
  aggregation:
    window_sec: 3600    # El evento 2 debe ocurrir dentro de esta ventana
```

Se activa cuando el evento 2 ocurre despues del evento 1 dentro de la ventana temporal.

### Directorio de reglas (48 reglas incluidas)

```
rules/
├── linux/
│   ├── auth/       ssh_brute_force, sudo_abuse, privilege_escalation,
│   │               account_manipulation, failed_logins_spike,
│   │               ssh_success_from_new_ip, sudo_password_bruteforce,
│   │               credentials_in_cmdline, sudoers_enumeration
│   ├── process/    suspicious_execution, cron_abuse, reverse_shell,
│   │               docker_abuse, docker_defense_evasion,
│   │               git_abuse, git_data_exposure
│   └── network/    port_scanning, suspicious_connections,
│                   firewall_removal, cifs_remote_mount
├── web/            sqli, path_traversal, lfi_rfi, rce, ssrf,
│                   web_scanning, xss
└── services/       nginx, apache2, httpd, mysql, samba, tuned,
                    php-fpm, zabbix, rsyslog, chronyd, dbus,
                    networkmanager, polkit, sendmail, irqbalance,
                    timedatex, getty@tty1, user@1001,
                    clamav, yum, memcached
                    (+ stubs auto-generados para servicios desconocidos)
```

### Nuevas reglas (v1.1.0)

| ID | Titulo | MITRE | Severidad |
|---|---|---|---|
| LIN-AUTH-007 | Sudo Password Brute-Force | T1110.001 | critical |
| LIN-AUTH-008 | Plaintext Credentials in Command-Line | T1552.003 | high |
| LIN-AUTH-009 | Sudoers File Enumeration | T1069.001 | high |
| LIN-NET-003 | Firewall Software Removal or Replacement | T1562.004 | critical |
| LIN-NET-004 | CIFS/SMB Remote Mount (Interactive) | T1021.002 | medium |
| LIN-PROC-004 | Docker Container Escape / Privileged Abuse | T1611 | critical |
| LIN-PROC-005 | Docker Defense Evasion | T1610 | high |
| LIN-PROC-006 | Git Hook / Credential Helper Abuse | T1195.001 | high |
| LIN-PROC-007 | Git Data Exposure | T1213 | medium |

### Nuevas reglas (v1.3.0)

| ID | Titulo | MITRE | Severidad |
|---|---|---|---|
| SVC-CLAMAV-001 | ClamAV Malware Detection / Antivirus Evasion | T1562.001 | high |
| SVC-YUM-001 | Package Manager Abuse (yum/dnf) | T1072 | high |
| SVC-MEMCACHED-001 | Memcached Unauthorized Access / Exposure | T1046 | high |

### Novedades de motor y pipeline (v1.4.0)

Sin nuevas reglas YAML en esta version. Los cambios son de infraestructura:

| Componente | Mejora |
|---|---|
| Stage A — Recoleccion | Logs rotados por logrotate (CentOS: `secure-YYYYMMDD.gz`, Debian: `auth.log.2.gz`) recolectados automaticamente para cobertura de hasta 60 dias |
| Stage A — Conversion | Todos los archivos de texto plano se convierten a JSONL estructurado durante la adquisicion (timestamp, servicio, pid, mensaje) |
| Stage B — Normalizer | Parser dedicado para formato JSONL de Stage A; parser de audit log Linux (`type=SYSCALL`, `USER_LOGIN`, `AVC`, etc.) con mapeo a servicios |
| Stage B — IOC engine | Filtro de servicio ahora case-insensitive (solucionaba falsos negativos con `NetworkManager`, `CROND`) |
| Reporting — PDF | Tablas corregidas: nombres de artefacto sin prefijo `var_log_`, timestamps en formato `YYYY-MM-DD HH:MM` en lugar de ISO completo |

### Nuevas reglas (v1.5.0)

| ID | Titulo | MITRE | Severidad |
|---|---|---|---|
| WEB-GIT-001 | Git Repository Theft via Web | T1213 | high |
| WEB-CONFIG-001 | Configuration File Disclosure via Web | T1552.001 | high |
| WEB-BACKUP-001 | Backup File Enumeration via Web | T1083 | medium |
| WEB-VCS-001 | VCS Metadata Exposure (SVN/HG/BZR/CVS) | T1213 | high |
| WEB-ETC-001 | /etc/ File Access via Web (LFI/Path Traversal) | T1083 | critical |

### Novedades de plataforma (v1.5.0)

| Componente | Mejora |
|---|---|
| Multi-idioma | Informes en español (`LANGUAGE=ES`) o inglés (`LANGUAGE=EN`) seleccionable desde `.env` |
| Templates | Plantillas separadas por idioma: `report.es.md.j2`, `report.en.md.j2`, `prompts.es.md.j2`, `prompts.en.md.j2` |
| Documentacion | `README.en.md` añadido — documentacion completa en ingles |
| Reglas web | 5 nuevas reglas para deteccion de ataques web: robo de repositorios .git, divulgacion de archivos de configuracion, enumeracion de backups, metadata VCS y acceso a /etc/ via LFI |
| Config | Variable `LANGUAGE` añadida a `config.py` y `.env.example` |

### Nuevas reglas (v1.6.0) — OWASP, Linux y servicios

**Web (9 reglas):**

| ID | Titulo | MITRE | Severidad |
|---|---|---|---|
| WEB-008 | XXE Injection Attempt | T1190 | high |
| WEB-009 | Insecure Deserialization Attack Attempt | T1190 | critical |
| WEB-010 | Log4Shell / Log4j RCE (CVE-2021-44228) | T1190 | critical |
| WEB-011 | Shellshock CGI Attack (CVE-2014-6271) | T1190 | critical |
| WEB-012 | Open Redirect / Unvalidated URL Redirect | T1204 | medium |
| WEB-013 | HTTP Header Injection / CRLF Injection | T1190 | high |
| WEB-014 | WordPress Attack Patterns (xmlrpc, wp-login) | T1110.001 | high |
| WEB-015 | Directory Listing Exposure / Sensitive File Discovery | T1083 | medium |
| WEB-016 | Dangerous HTTP Method Abuse (TRACE/PUT/WebDAV) | T1190 | medium |

**Linux (6 reglas):**

| ID | Titulo | MITRE | Severidad |
|---|---|---|---|
| LIN-AUTH-010 | SSH Authorized Keys Tampering | T1098.004 | high |
| LIN-PROC-008 | Log Tampering / Audit Log Clearing | T1070.002 | critical |
| LIN-PROC-009 | Crypto Mining Activity | T1496 | high |
| LIN-PROC-010 | Kernel Module Loading / Rootkit Indicators | T1547.006 | critical |
| LIN-NET-005 | DNS Tunneling / Data Exfiltration via DNS | T1048.003 | high |
| LIN-NET-006 | Email Relay Abuse / SMTP Spam Sending | T1071.003 | high |

**Servicios (5 reglas):**

| ID | Titulo | MITRE | Severidad |
|---|---|---|---|
| SVC-REDIS-001 | Redis Unauthorized Access / RCE via CONFIG SET | T1190 | critical |
| SVC-POSTGRES-001 | PostgreSQL Auth Failures / COPY PROGRAM RCE | T1190 | high |
| SVC-TOMCAT-001 | Apache Tomcat Manager Brute Force / WAR RCE | T1190 | critical |
| SVC-POSTFIX-001 | Postfix Mail Relay Abuse / SMTP Brute Force | T1071.003 | high |
| SVC-FTP-001 | FTP Brute Force / Anonymous Login Abuse | T1110.001 | high |

### Cobertura OWASP Top 10 (2021) — v1.6.0

| # | Categoria | Reglas principales | Estado |
|---|---|---|---|
| A01 | Broken Access Control | path_traversal, lfi_rfi, web_etc_file_access, open_redirect | ✅ Cubierta |
| A02 | Cryptographic Failures | redis (cleartext), postfix (plaintext SMTP), vsftpd (FTP) | Parcial |
| A03 | Injection | sqli, xss, rce, lfi_rfi, xxe_injection, http_header_injection | ✅ Cubierta |
| A04 | Insecure Design | No detectable en logs de acceso | N/A |
| A05 | Security Misconfiguration | web_scanning, git_exposure, directory_listing, http_method_abuse | ✅ Cubierta |
| A06 | Vulnerable Components | log4shell, shellshock, yum | ✅ Cubierta |
| A07 | Auth Failures | ssh_brute_force, failed_logins, wordpress_attacks, ftp_bruteforce | ✅ Cubierta |
| A08 | Software Integrity / Deserialization | insecure_deserialization | ✅ Cubierta |
| A09 | Logging Failures | log_tampering | ✅ Cubierta |
| A10 | SSRF | ssrf | ✅ Cubierta |

---

## 10. Añadir reglas personalizadas

### Opcion A — Crear manualmente

1. Cree un archivo YAML en el subdirectorio correspondiente de `rules/`.
2. Siga el formato descrito en la seccion anterior.
3. Establezca `enabled: true`.
4. Lance `run.ps1` / `run.sh` / `run.bat` — la nueva regla se cargara automaticamente.

### Opcion B — Completar un stub auto-generado

Cuando se detecta un servicio sin reglas, el sistema crea automaticamente un stub desactivado en `rules/services/<servicio>.yaml`. Para activarlo:

1. Abra el archivo stub.
2. Reemplace `PLACEHOLDER_PATTERN` con un regex valido para los logs del servicio.
3. Cambie `enabled: false` a `enabled: true`.
4. Ajuste `severity`, `confidence` y `recommendation`.

### Opcion C — Descargar de SigmaHQ

Ver sección [7. Actualizar el diccionario de reglas](#7-actualizar-el-diccionario-de-reglas).

---

## 11. Motor IOC — Rendimiento

El motor IOC de la Etapa B evalua cada regla contra el conjunto completo de entradas de log normalizadas. En v1.1.0 se incorporaron dos optimizaciones que redujeron el tiempo de analisis de ~180 segundos a ~2 segundos (**aceleracion de ~83x**) sobre un corpus de 109.000 entradas.

### Optimización 1 — Índice de servicio

Las entradas de log se agrupan previamente por campo `service` en un `defaultdict(list)`. Las reglas con `service: <nombre>` solo iteran las entradas de ese servicio en vez de las 100K+ totales. Las reglas con `service: "*"` siguen evaluando todo el conjunto.

### Optimización 2 — Pre-filtro de anclas (anchor pre-filter)

Antes de invocar el motor de expresiones regulares (costoso), el sistema extrae la subcadena literal más larga de cada patron regex. Esta "ancla" se verifica con `str.__contains__` (velocidad C) sobre el mensaje en minúsculas:

- Si el ancla **no** está presente → la entrada se descarta sin ejecutar ninguna regex.
- Si el ancla **sí** está presente → se evalua el regex completo.

En la práctica el pre-filtro descarta ~99% de las entradas antes de que el regex engine las toque, eliminando el coste de retroceso (backtracking) sobre patrones complejos.

### Caché JSONL del normalizador

En re-ejecuciones (Stage B sin cambios en los logs), el normalizador detecta que `all_entries.jsonl` es más reciente que todos los archivos de log en `logs_dir` y carga el JSONL cacheado directamente, sin descomprimir ni re-parsear los `.gz` originales.

### Referencia de tiempos

| Etapa | v1.0.0 (109K entradas) | v1.1.0 (109K entradas) | v1.4.0+ (375K entradas) |
|---|---|---|---|
| Normalizacion (primera vez) | ~0.8 s | ~0.8 s | ~3 s |
| Normalizacion (cache hit) | ~0.8 s | ~0.7 s | ~0.5 s |
| Motor IOC | ~180 s | ~2.2 s | ~7 s |
| Total (primer analisis) | ~181 s | ~3 s | ~10 s |
| Total (re-analisis con cache) | ~181 s | ~2.9 s | ~7.5 s |

> Los datos de v1.4.0+ corresponden a una adquisicion real de 60 dias (1440h) sobre CentOS 7 con 54 artefactos y 375.928 entradas normalizadas.

---

## 12. Consideraciones de seguridad

### Credenciales

- Las credenciales SSH se leen desde el archivo `.env` o desde variables de entorno del sistema.
- Las variables de entorno del sistema tienen **prioridad** sobre el `.env`.
- Se almacenan en memoria en un objeto `EphemeralSession`.
- Se destruyen (sobrescriben con ceros) inmediatamente al cerrar la conexion SSH, incluso si ocurre un error.
- **Nunca** se escriben en logs ni en el informe generado.
- El archivo `.env` esta en `.gitignore` y nunca debe subirse al repositorio.

### Canal raíz persistente (SSH_ROOT_PASS)

Algunos archivos de log (como `/var/log/audit/audit.log`) solo son legibles por `root`. Si el usuario SSH no tiene permisos suficientes y el login SSH directo como root está deshabilitado en el servidor, puede definirse `SSH_ROOT_PASS` en el `.env`:

```ini
SSH_ROOT_PASS=contrasena_de_root
```

Cuando esta variable está definida, la Etapa A abre **un canal PTY persistente** al inicio de la conexion SSH y ejecuta `su root` una sola vez. Todos los comandos de adquisicion (inventario de servicios, puertos, procesos y descarga de logs) se enrutan por ese canal y se ejecutan como `root` durante toda la sesion. Al finalizar la etapa, el canal se cierra limpiamente. La escalada **no** requiere modificar `sshd_config` ni habilitar `PermitRootLogin`. La contraseña de root se destruye junto con las demás credenciales al cerrar la sesion.

> **Seguridad:** `SSH_ROOT_PASS` solo se usa en la sesion activa y nunca se registra en logs ni en el informe. Si no se necesita acceso a logs de root, omita esta variable.

### Fallback: sudo -n y ejecucion sin privilegios

Si `SSH_ROOT_PASS` no está definida, los comandos se intentan primero con `sudo -n` (modo no-interactivo, requiere entrada `NOPASSWD` en sudoers). Si falla, se reintenta sin privilegios. Con el canal raiz activo este fallback no se usa.

### Barrido de logs ampliado

La Etapa A ejecuta `find` sobre cinco directorios para descubrir archivos de log no estándar:

```
/var/log   /var/opt   /opt   /srv   /var/www
```

Solo se incluyen archivos `*.log` no vacíos (`-size +0c`). Para prevenir inyeccion de rutas, cada ruta devuelta se valida contra un patrón seguro antes de usarla en un comando de lectura. El número máximo de archivos es configurable via `MAX_LOG_FILES` (por defecto: sin límite).

### Conexion SSH

- Por defecto, `asyncssh` verifica la host key contra `~/.ssh/known_hosts`.
- Si el host no esta en `known_hosts`, la conexion fallara con `HostKeyNotVerifiable`.
- Para registrar el host antes de la primera conexion:

```bash
ssh-keyscan -H 192.168.1.100 >> ~/.ssh/known_hosts
```

> **Advertencia:** No deshabilite la verificacion de host key en entornos de produccion. Es vulnerable a ataques MITM.

### Integridad de evidencias

- Todos los artefactos recolectados se hashean con **SHA-256** antes de cerrar la conexion.
- `MANIFEST.json` + `MANIFEST.sig.json` permiten verificar que los artefactos no han sido modificados.

### Impacto minimo en el host remoto

- Solo se ejecutan comandos de **lectura** en el host remoto.
- No se instalan agentes, no se modifican configuraciones, no se escriben archivos.
- Limite de 50.000 lineas por fuente de log para evitar sobrecarga.

---

## 13. Referencia de variables de entorno

Las variables pueden definirse en el archivo `.env` o como variables de entorno del sistema.

| Variable | Obligatoria | Por defecto | Descripcion |
|---|---|---|---|
| `SSH_HOST` | Si | — | IP o hostname del host a analizar |
| `SSH_USER` | Si | — | Usuario SSH |
| `SSH_PASS` | Si | — | Contrasena SSH |
| `SSH_PORT` | No | `22` | Puerto SSH |
| `SSH_ROOT_PASS` | No | — | Contrasena de root para canal raiz persistente (todos los comandos como root) |
| `TIME_WINDOW_HOURS` | No | `72` | Ventana temporal de logs a exportar (horas). Ej: 1440 = 60 dias |
| `LOG_MAX_LINES` | No | `50000` | Maximo de lineas por fuente de log |
| `MAX_LOG_FILES` | No | `0` | Maximo de archivos `*.log` en el barrido (0 = sin limite) |
| `SSH_CONNECT_TIMEOUT` | No | `30` | Timeout de conexion SSH (segundos) |
| `SSH_COMMAND_TIMEOUT` | No | `60` | Timeout de comandos SSH normales (segundos) |
| `SSH_LARGE_TIMEOUT` | No | `120` | Timeout de comandos SSH pesados, ej. exportacion de journal (segundos) |

### Archivo .env

El archivo `.env` en la raiz del proyecto se carga automaticamente por los scripts `run`. Editar con las credenciales reales antes de ejecutar:

```ini
SSH_HOST=192.168.1.100
SSH_USER=admin
SSH_PASS=tu_contrasena
SSH_PORT=22
# SSH_ROOT_PASS=contrasena_root   # Opcional: para leer logs de root
```

Para crear desde la plantilla:

```bash
cp .env.example .env      # Linux / macOS
copy .env.example .env    # Windows
```

---

## 14. Resolución de problemas

### `[X] Missing required environment variable(s): SSH_HOST, SSH_USER, SSH_PASS`

El archivo `.env` no existe o las variables no estan definidas. Crea el `.env` desde la plantilla:

```bash
copy .env.example .env    # Windows
cp .env.example .env      # Linux / macOS
```

Luego edita `.env` con tus credenciales reales.

### `[X] Autenticacion fallida — verificar SSH_USER y SSH_PASS`

Las credenciales en `.env` son incorrectas. Verifica usuario y contrasena.

### `[X] Host key no verificable`

El host no esta en `~/.ssh/known_hosts`. Solucion:

```bash
ssh-keyscan -H <host> >> ~/.ssh/known_hosts
```

### `[X] No se pudo conectar — timeout`

El host no es alcanzable desde esta maquina. Verifica conectividad de red y que el puerto SSH este abierto:

```bash
ssh -p 22 usuario@host    # prueba manual de conectividad
```

### `Missing: asyncssh, yaml, jinja2`

Las dependencias no estan instaladas. Los scripts `run` las instalan automaticamente al inicio — simplemente vuelve a ejecutar:

```powershell
.\run.ps1        # Windows PowerShell
```

```bash
bash run.sh      # Linux / macOS / WSL
```

### Logs de root no recolectados (`/var/log/audit/audit.log`, `/var/log/secure`)

Si el usuario SSH no tiene acceso a logs protegidos y aparecen errores de permisos en `acquisition_log.json`, define `SSH_ROOT_PASS` en el `.env`:

```ini
SSH_ROOT_PASS=contrasena_de_root
```

El sistema abrirá un canal PTY persistente al iniciar la sesion, ejecutará `su root` una vez y todos los comandos subsiguientes (servicios, puertos, procesos, logs) correrán como root. Esto también resuelve problemas con `journalctl` en hosts RHEL/CentOS donde el usuario SSH no pertenece al grupo `systemd-journal`.

### Archivos de log con peso 0 omitidos

Los archivos `*.log` de 0 bytes se detectan antes del intento de descarga y se omiten silenciosamente. No generan errores de permisos. Si un log esperado no aparece en la evidencia, verificar que el archivo no esté vacío en el host remoto.

### El informe esta vacio o sin hallazgos

- Revisa `jobs/<job_id>/01_evidence/raw/acquisition_log.json` para ver que comandos fallaron.
- Si el usuario SSH no tiene permisos para `journalctl`, los logs del sistema no se exportaran.
- Revisa `jobs/<job_id>/02_analysis/rule_coverage.json` para ver que reglas se aplicaron.

### Error en la generacion de PDF

Sin pandoc, el sistema usa `xhtml2pdf` automaticamente. Si el PDF no se genera, vuelve a ejecutar el script `run` correspondiente — reinstalara las dependencias automaticamente. Para mejor calidad de PDF instala pandoc:

```bash
# Ubuntu/Debian
sudo apt install pandoc texlive-xetex texlive-lang-spanish
# macOS
brew install pandoc && brew install --cask mactex
# Windows — descargar desde https://pandoc.org/installing.html
```

### `duckdb` no disponible — correlaciones limitadas

Si DuckDB no esta instalado, el correlador usa un fallback Python puro. Para funcionalidad completa:

```bash
.venv\Scripts\pip install duckdb
```

### Motor IOC lento en re-analisis

Si el tiempo de analisis es alto en re-ejecuciones, verifica que `all_entries.jsonl` existe y es mas reciente que los archivos en `01_evidence/raw/logs/`. Si los archivos de log tienen fecha de modificacion posterior al cache, el normalizador re-parsea todo. Esto es esperado tras una nueva adquisicion.

---

## Licencia

Todas las dependencias son de codigo abierto (MIT, Apache 2.0 o BSD). No se requieren licencias comerciales.

---

*LinuxAuditLog v1.6.0 — Herramienta forense de adquisicion remota Linux*

*Desarrollado por Gonzalo Serrano en colaboracion con [Claude Code](https://claude.ai/code) (Anthropic).*
