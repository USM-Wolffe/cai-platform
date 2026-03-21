# cai-platform

> Plataforma de investigación de ciberseguridad para EGS, potenciada por IA (CAI). Centraliza múltiples casos de uso —análisis de logs WatchGuard, investigación de phishing y más— en un API determinista con aislamiento multi-tenant por cliente.

---

## Tabla de contenidos

1. [¿Qué hace esta plataforma?](#qué-hace-esta-plataforma)
2. [Arquitectura general](#arquitectura-general)
3. [Estructura del repositorio](#estructura-del-repositorio)
4. [Prerequisitos](#prerequisitos)
5. [Instalación rápida](#instalación-rápida)
6. [Variables de entorno](#variables-de-entorno)
7. [Interfaz web (Streamlit UI)](#interfaz-web-streamlit-ui)
   - [Instalación](#instalación-de-la-ui)
   - [Tab 1 — WatchGuard S3 Investigation](#tab-1--watchguard-s3-investigation)
   - [Tab 2 — Phishing Investigation](#tab-2--phishing-investigation)
   - [Tab 3 — Monitor de Email (IMAP)](#tab-3--monitor-de-email-imap)
8. [Cómo usar la plataforma (CLI)](#cómo-usar-la-plataforma)
   - [CLI del orquestador](#cli-del-orquestador)
   - [Terminal CAI interactiva](#terminal-cai-interactiva)
   - [Monitor IMAP de phishing](#monitor-imap-de-phishing)
   - [API HTTP directa](#api-http-directa)
9. [Pipeline WatchGuard S3 (logs a escala)](#pipeline-watchguard-s3-logs-a-escala)
10. [Investigador multi-agente de phishing](#investigador-multi-agente-de-phishing)
11. [Despliegue en producción (AWS)](#despliegue-en-producción-aws)
12. [Desarrollo y tests](#desarrollo-y-tests)
13. [Cómo agregar un nuevo backend](#cómo-agregar-un-nuevo-backend)
14. [Referencia de endpoints](#referencia-de-endpoints)
15. [Recursos AWS](#recursos-aws)

---

## ¿Qué hace esta plataforma?

`cai-platform` es la plataforma v2 de investigación de ciberseguridad de EGS. Su propósito central es:

- **Centralizar casos de uso de ciberseguridad**: análisis de logs de firewall WatchGuard, investigación de phishing, y cualquier backend futuro, bajo un único API determinista.
- **Potenciar a analistas de EGS con IA**: los agentes CAI (basados en Claude vía Amazon Bedrock) corren de forma autónoma y los analistas revisan los resultados.
- **Aislar datos por cliente** (`client_id`): EGS atiende a múltiples clientes y sus datos están estrictamente separados en la misma plataforma.
- **Ser auditable**: cada investigación genera un `Case` con su historial de `Run`, `Artifact` y `ObservationResult` trazable.

**Flujo típico de un analista:**

```
Analista → Streamlit UI  ─────────────────┐
         → CAI Terminal / CLI             │
                                          ↓
                                    Platform API (HTTP)
                                          ↓
                                    Backend (watchguard_logs / phishing_email / ...)
                                          ↓
                                    Resultado determinista + artefactos
                                          ↓
                                    Analista revisa
```

---

## Arquitectura general

### Capas del código (dependencias estrictas de izquierda a derecha)

```
platform-contracts → platform-core → platform-adapters → platform-backends → platform-api
                                                                            ↑
                                                                   cai-orchestrator
```

| Capa | Paquete | Responsabilidad |
|---|---|---|
| **Contracts** | `packages/platform-contracts` | Vocabulario compartido: `Case`, `Run`, `Artifact`, `ObservationRequest`, etc. |
| **Core** | `packages/platform-core` | Lógica de coordinación neutra al vendor. Puertos (`CaseRepository`, `RunRepository`, etc.) |
| **Adapters** | `packages/platform-adapters` | Traducción de fuentes externas (ej. WatchGuard S3 ZIP → referencia normalizada) |
| **Backends** | `packages/platform-backends` | Implementaciones de backends: `watchguard_logs`, `phishing_email` |
| **API** | `apps/platform-api` | API HTTP (FastAPI) que expone la superficie pública. Corre en Docker/ECS |
| **Orchestrator** | `apps/cai-orchestrator` | CLI host-run que conecta CAI con `platform-api` |

### Infraestructura en producción (AWS)

```
Internet
    │
    ▼
ALB (Application Load Balancer)
    │  cai-platform-alb-*.us-east-2.elb.amazonaws.com
    ▼
ECS Fargate (cai-platform-service)
    │  Task: cai-platform-api  ← imagen desde ECR
    │  DATABASE_URL → RDS
    │  DB_CREDENTIALS ← Secrets Manager
    ▼
RDS PostgreSQL (cai-platform-db)
    │  db.t3.micro, caiplatform DB
    ▼
(Backends lean about S3)
S3 (egslatam-cai-dev)
    └── workspaces/{workspace_id}/...
```

---

## Estructura del repositorio

```
cai-platform/
├── apps/
│   ├── platform-api/          # API HTTP (FastAPI + uvicorn)
│   ├── cai-orchestrator/      # CLI + agentes CAI
│   └── platform-ui/           # Interfaz web Streamlit
├── packages/
│   ├── platform-contracts/    # Modelos Pydantic compartidos
│   ├── platform-core/         # Puertos y servicios neutros
│   ├── platform-adapters/     # Adaptadores de fuentes externas
│   └── platform-backends/     # Implementaciones de backends
├── tests/                     # Tests alineados por capa
├── docs/
│   ├── architecture/          # Decisiones de arquitectura
│   ├── backends/              # Documentación de backends
│   └── operations/            # Guía operacional
├── examples/
│   ├── watchguard/            # Payload de ejemplo WatchGuard
│   └── phishing/              # Payload de ejemplo phishing
├── docker-compose.yml
├── Makefile
├── .env                       # Variables de entorno (no commitear)
└── CLAUDE.md                  # Guía para Claude Code
```

---

## Prerequisitos

### Para usar la plataforma (producción / EC2)
- Python 3.12+
- Docker Engine + Docker Compose plugin

### Para el pipeline WatchGuard S3
- AWS CLI configurado con credenciales que tengan acceso a `egslatam-cai-dev`

### Para la terminal CAI
- Instalación opcional de `apps/cai-orchestrator[cai]`
- Credenciales AWS para Amazon Bedrock (Claude vía `bedrock/us.anthropic.claude-*`)

---

## Instalación rápida

```bash
# 1. Clonar el repositorio
git clone <repo-url>
cd cai-platform

# 2. Crear entorno virtual
python3 -m venv .venv
. .venv/bin/activate

# 3. Instalar el orquestador CLI (mínimo necesario para correr investigaciones)
pip install -e apps/cai-orchestrator

# 4. (Opcional) Instalar con soporte CAI para la terminal interactiva
pip install -e 'apps/cai-orchestrator[cai]'

# 5. Copiar y editar variables de entorno
cp .env.example .env
# editar .env con tus credenciales AWS, IMAP, etc.
```

El API corre en Docker (apunta al ALB en producción, o local con `make up`):

```bash
# Producción: ya está corriendo en AWS, ver PLATFORM_API_BASE_URL en .env

# Local (desarrollo):
make up         # levanta platform-api en http://localhost:8000
make health     # verifica que responda
```

---

## Variables de entorno

Copiar `.env.example` → `.env` y completar:

| Variable | Requerida | Descripción |
|---|---|---|
| `PLATFORM_API_BASE_URL` | Sí | URL base del API (ALB en producción, `http://localhost:8000` en local) |
| `CAI_MODEL` | Para CAI | Modelo Bedrock a usar, ej. `bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0` |
| `CAI_AGENT_TYPE` | Para CAI | Tipo de agente: `egs-analist` (default) |
| `AWS_ACCESS_KEY_ID` | Para S3/Bedrock | Credenciales AWS |
| `AWS_SECRET_ACCESS_KEY` | Para S3/Bedrock | Credenciales AWS |
| `AWS_DEFAULT_REGION` | Para S3/Bedrock | Región AWS (default: `us-east-2`) |
| `WATCHGUARD_S3_BUCKET` | Para S3 pipeline | Bucket S3 (default: `egslatam-cai-dev`) |
| `IMAP_HOST` | Para monitor IMAP | Host IMAP, ej. `imap.gmail.com` |
| `IMAP_PORT` | Para monitor IMAP | Puerto IMAP (default: `993`) |
| `IMAP_USERNAME` | Para monitor IMAP | Email de la cuenta de monitoreo |
| `IMAP_PASSWORD` | Para monitor IMAP | App password (Gmail: habilitar 2FA + app password) |
| `DATABASE_URL` | Solo API en producción | DSN PostgreSQL. Si no se define, se usa memoria (dev/test) |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` | Solo API en producción | Datos de conexión RDS |

> **Nota sobre `DATABASE_URL`**: El API selecciona automáticamente PostgreSQL si `DATABASE_URL` está definido, o memoria in-process si no. En producción (ECS), esta variable viene del task definition con las credenciales desde Secrets Manager.

---

## Interfaz web (Streamlit UI)

`platform-ui` es una interfaz web que envuelve el orquestador y elimina la fricción de la CLI. No reemplaza el CLI ni el API — es una capa de presentación pura que llama a los mismos flujos internamente.

### Instalación de la UI

```bash
# Sin soporte CAI (solo pipeline determinista)
make install-ui

# Con soporte CAI (habilita chat de seguimiento y pipeline multi-agente)
make install-ui-cai
```

Luego lanzar:

```bash
make ui
# Abre automáticamente http://localhost:8501
```

La UI lee las mismas variables de entorno que el CLI (`PLATFORM_API_BASE_URL`, `CAI_MODEL`, `AWS_*`, `IMAP_*`). Todos los campos también son editables desde el **panel lateral** sin necesidad de reiniciar.

---

### Tab 1 — WatchGuard S3 Investigation

Permite subir un ZIP de logs WatchGuard (exportado desde SharePoint), staging en S3 y obtener analytics sin tocar la CLI.

**Pasos:**

1. En el panel lateral, completar:
   - **AWS Access Key ID** y **Secret** (o dejar vacíos para usar `~/.aws/credentials`)
   - **S3 Bucket** y **Región** (defaults: `egslatam-cai-dev` / `us-east-2`)
   - **Client ID** (para aislamiento multi-tenant)

2. En el tab **WatchGuard S3 Investigation**:
   - **Subir el ZIP** con el uploader. El Workspace ID se auto-detecta desde el nombre del archivo.
   - Verificar o editar el Workspace ID manualmente si es necesario.
   - Escribir una pregunta de investigación opcional (usada para orientar al agente CAI en el chat).
   - Click en **Investigar**.

3. La UI ejecuta automáticamente:
   ```
   upload ZIP → S3
   create_case → attach_artifact → create_run
   stage_workspace_zip   → CSVs en S3 staging
   duckdb_workspace_analytics → agregaciones
   ```

4. Se muestran tablas con: top IPs origen/destino, distribución de acciones, protocolos, tipos de alarma, rango de fechas y conteo de eventos DENY.

5. Si CAI está instalado, aparece un **chat de seguimiento** debajo de las tablas. El analista puede hacer preguntas en lenguaje natural y el agente `egs-analist` usa las herramientas de la plataforma para responderlas.

**Ejemplo de pregunta de chat:**
```
¿Cuáles son los 5 destinos más frecuentes de la IP 10.0.0.55?
```

---

### Tab 2 — Phishing Investigation

Analiza un email sospechoso individual. Soporta dos modos de entrada:

**Modo A — Subir archivo `.eml`**

Subir el archivo `.eml` exportado desde el cliente de correo. La UI parsea los headers, URLs, adjuntos y cuerpo automáticamente.

**Modo B — Pegar payload JSON**

Para integraciones o pruebas, pegar directamente el JSON con la estructura:

```json
{
  "subject": "Urgent: verify your account",
  "sender": {"email": "attacker@example.com", "display_name": "Security"},
  "reply_to": null,
  "urls": ["http://198.51.100.7/login?verify=1"],
  "text": "Click here immediately to avoid suspension.",
  "attachments": []
}
```

**Flujo de análisis:**

1. Se muestra un preview del payload parseado.
2. Click en **Investigar**.
3. El backend corre las reglas heurísticas y muestra: `risk_level`, `risk_score`, reglas activadas, señales de URLs y adjuntos.
4. Si CAI está instalado y se activa el checkbox **"Correr pipeline multi-agente CAI"**, el agente `phishing_investigator` corre el pipeline completo (triage → especialistas → síntesis) y agrega el veredicto estructurado:

| Campo | Valores posibles |
|---|---|
| `overall_verdict` | `phishing` / `suspicious` / `legitimate` / `uncertain` |
| `risk_level` | `critical` / `high` / `medium` / `low` |
| `confidence` | 0.0 – 1.0 |
| `recommended_action` | `block` / `quarantine` / `no_action` / etc. |
| `evidence_summary` | Resumen en lenguaje natural |

---

### Tab 3 — Monitor de Email (IMAP)

Conecta directamente al buzón de la cuenta de monitoreo y procesa todos los correos no leídos automáticamente. Equivalente a `run-phishing-monitor --once` desde el CLI.

#### Configuración del buzón

Expandir **Configuración IMAP** en el tab y completar:

| Campo | Descripción |
|---|---|
| Host IMAP | `imap.gmail.com` para Gmail, `outlook.office365.com` para Outlook |
| Puerto | `993` (IMAP SSL, default) |
| Usuario | Email completo de la cuenta de monitoreo |
| Contraseña de aplicación | Ver instrucciones abajo |
| Buzón | `INBOX` (default) o la carpeta específica |
| Marcar como leído | Si activado, marca los emails procesados para no repetirlos |

**Generar App Password para Gmail:**
1. Ir a [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Crear una App Password para "Mail" (requiere 2FA activo)
3. Pegar la contraseña de 16 caracteres en el campo

#### Mecanismo de reenvío

El monitor está diseñado para un flujo de **reenvío como adjunto**:

```
Empleado recibe email sospechoso
         ↓
Reenvía el email COMO ADJUNTO (.eml) al buzón de monitoreo
(en Outlook: Inicio → Más → Reenviar como datos adjuntos)
(en Gmail:   Menú ⋮ → Forward as attachment)
         ↓
Monitor de Email detecta el email no leído
         ↓
Extrae el .eml adjunto (el email original sospechoso)
         ↓
Corre el análisis de phishing sobre el email original
```

> **Importante:** el monitor analiza el email **adjunto** (el sospechoso original), no el email del empleado que lo reenvió. Si el email sospechoso se reenvía inline en lugar de como adjunto, se analiza directamente.

#### Resultados

Por cada email procesado se muestra:
- **Remitente real** del email sospechoso (no del empleado que lo reenvió)
- **Risk Level** y **Risk Score** del análisis heurístico
- **Reglas activadas** con detalle de evidencia
- **Señales de URLs** (incluyendo detección de redirect wrappers y shorteners)
- Si CAI está activo: **Veredicto multi-agente** completo con `overall_verdict`, `confidence` y `recommended_action`

#### Estrategia de detección de URLs

El backend detecta automáticamente URLs que ocultan su destino real:

- **Redirect wrappers**: URLs donde el destino está embebido como parámetro (`?url=`, `?redirect=`, `?target=`, etc.). Cubre gateways corporativos de seguridad de email, rastreadores de marketing, y servicios de redirección genéricos.
- **URL shorteners**: más de 35 dominios conocidos (`bit.ly`, `t.ly`, `ow.ly`, `is.gd`, `rb.gy`, etc.)
- **Urgencia multilingüe**: términos en inglés, español y portugués
- **Identidad sospechosa**: display names que simulan ser soporte/admin/seguridad desde dominios no corporativos

---

## Cómo usar la plataforma

### CLI del orquestador

Todos los comandos requieren `--client-id` para identificar al cliente de EGS.

```bash
. .venv/bin/activate
set -a && . .env && set +a
```

**Análisis de logs WatchGuard (normalización y resumen):**
```bash
python3 -m cai_orchestrator run-watchguard \
  --client-id "cliente-abc" \
  --title "Investigación firewall Enero" \
  --summary "Analizar tráfico denegado del mes de enero." \
  --payload-file examples/watchguard/minimal_payload.json
```

**Análisis básico de phishing:**
```bash
python3 -m cai_orchestrator run-phishing-email-basic-assessment \
  --client-id "cliente-abc" \
  --title "Email sospechoso #2024-01" \
  --summary "Verificar si el email adjunto es phishing." \
  --payload-file examples/phishing/minimal_payload.json
```

**Shortcuts de Makefile:**
```bash
make demo-watchguard     # corre run-watchguard con payload de ejemplo
make demo-phishing-email # corre análisis de phishing con payload de ejemplo
```

---

### Terminal CAI interactiva

La terminal CAI lanza un agente conversacional (`egs-analist`) con acceso completo a todas las herramientas de la plataforma. El analista describe la investigación en lenguaje natural.

```bash
python3 -m cai_orchestrator run-cai-terminal \
  --client-id "cliente-abc" \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0" \
  --prompt "Analiza el workspace 8011029C760FA. Busca el ZIP más reciente, crea el caso, estágealo y dime los top IPs con más tráfico denegado."
```

El agente `egs-analist` puede:
- Crear casos y runs (`create_case`, `create_run`)
- Ejecutar cualquier observación disponible en los backends
- Hacer handoff al agente especializado `phishing_investigator_agent`
- Consultar artefactos y resultados previos

**Tipos de agente disponibles** (`CAI_AGENT_TYPE`):
| Agente | Descripción |
|---|---|
| `egs-analist` | Agente general de investigación (default). Puede delegar a phishing. |
| `platform_investigation_agent` | Alias de `egs-analist` |
| `phishing_investigator_agent` | Pipeline multi-agente de phishing directamente |

---

### Monitor IMAP de phishing

Monitorea un buzón de correo en busca de emails reenviados para investigar como phishing. Extrae el `.eml` adjunto y corre el pipeline automáticamente.

```bash
# Procesar un email sin marcarlo como leído (prueba)
python3 -m cai_orchestrator run-phishing-monitor \
  --client-id "cliente-abc" \
  --once --dry-run

# Procesar un email y luego correr el investigador CAI
python3 -m cai_orchestrator run-phishing-monitor \
  --client-id "cliente-abc" \
  --once --cai-investigate \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"

# Loop continuo (intervalo por defecto: 60 segundos)
python3 -m cai_orchestrator run-phishing-monitor --client-id "cliente-abc"
```

Configurar en `.env`: `IMAP_HOST`, `IMAP_PORT`, `IMAP_USERNAME`, `IMAP_PASSWORD`.

Para Gmail: activar verificación en dos pasos y generar una [app password](https://myaccount.google.com/apppasswords).

---

### API HTTP directa

El API está disponible en `PLATFORM_API_BASE_URL`. Todos los endpoints devuelven JSON.

**Ejemplo: crear un caso e investigar phishing paso a paso:**

```bash
BASE=http://cai-platform-alb-472989822.us-east-2.elb.amazonaws.com

# 1. Crear caso
CASE=$(curl -s -X POST $BASE/cases \
  -H 'Content-Type: application/json' \
  -d '{"title":"Email sospechoso","client_id":"cliente-abc","workflow_type":"defensive_analysis"}')
CASE_ID=$(echo $CASE | python3 -c "import sys,json; print(json.load(sys.stdin)['case_id'])")

# 2. Adjuntar artefacto de entrada
ARTIFACT=$(curl -s -X POST $BASE/cases/$CASE_ID/artifacts \
  -H 'Content-Type: application/json' \
  -d @examples/phishing/minimal_payload.json)
ARTIFACT_ID=$(echo $ARTIFACT | python3 -c "import sys,json; print(json.load(sys.stdin)['artifact_id'])")

# 3. Crear run
RUN=$(curl -s -X POST $BASE/cases/$CASE_ID/runs \
  -H 'Content-Type: application/json' \
  -d "{\"backend_id\":\"phishing_email\",\"artifact_ids\":[\"$ARTIFACT_ID\"]}")
RUN_ID=$(echo $RUN | python3 -c "import sys,json; print(json.load(sys.stdin)['run_id'])")

# 4. Ejecutar observación
curl -s -X POST $BASE/runs/$RUN_ID/observations/phishing-basic \
  -H 'Content-Type: application/json' -d '{}'
```

Ver la [tabla completa de endpoints](#referencia-de-endpoints) más abajo.

---

## Pipeline WatchGuard S3 (logs a escala)

Para archivos ZIP de SharePoint con 1.5–10 millones de filas de logs WatchGuard, el pipeline evita el problema de RAM usando S3 + DuckDB httpfs.

### Paso 1 — Subir el ZIP a S3

```bash
make upload-workspace ZIP=8011029C760FA_8011029DE7578.zip WORKSPACE=8011029C760FA_8011029DE7578
```

El archivo queda en: `s3://egslatam-cai-dev/workspaces/{WORKSPACE}/input/uploads/{timestamp}/raw.zip`

### Paso 2 — CAI hace el resto

```bash
python3 -m cai_orchestrator run-cai-terminal \
  --client-id "cliente-abc" \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0" \
  --prompt "Analiza el workspace 8011029C760FA_8011029DE7578. Encuentra el ZIP más reciente, créa el caso, estágealo, corre analytics y muéstrame los top talkers con tráfico denegado."
```

El agente ejecuta automáticamente:
1. `find_latest_workspace_upload(workspace_id)` → s3_uri del ZIP
2. `create_case` + `attach_workspace_s3_zip_reference` + `create_run`
3. `execute_watchguard_stage_workspace_zip` → descomprime TARs → CSVs → staging en S3
4. `execute_watchguard_duckdb_workspace_analytics` → DuckDB lee CSVs desde S3, retorna agregaciones
5. `execute_watchguard_duckdb_workspace_query` → drill-down sobre IPs / tipos de alarma / acciones

### Estructura S3

```
s3://egslatam-cai-dev/
└── workspaces/{workspace_id}/
    ├── input/uploads/{upload_id}/raw.zip      ← sube el usuario
    └── staging/{upload_id}/
        ├── _manifest.json
        ├── traffic/{date}/*.csv
        ├── event/{date}/*.csv
        └── alarm/{date}/*.csv
```

### Observaciones disponibles (`watchguard_logs`)

| Operación | Tipo | Descripción |
|---|---|---|
| `watchguard_logs.normalize_and_summarize` | Predefinida | Normaliza y resume logs básicos |
| `watchguard_logs.filter_denied_events` | Predefinida | Filtra eventos denegados |
| `watchguard_logs.analytics_bundle_basic` | Predefinida | Bundle de analytics básico |
| `watchguard_logs.top_talkers_basic` | Predefinida | Top IPs por tráfico |
| `watchguard_logs.workspace_zip_ingestion` | Predefinida | Ingesta de ZIP local |
| `watchguard_logs.stage_workspace_zip` | Predefinida | Staging ZIP S3 → CSVs en S3 |
| `watchguard_logs.duckdb_workspace_analytics` | Predefinida | Agregaciones DuckDB sobre S3 |
| `watchguard_logs.guarded_filtered_rows` | Guarded (requiere aprobación) | Filas filtradas (requiere approval) |
| `watchguard_logs.duckdb_workspace_query` | Guarded (requiere aprobación) | Query DuckDB libre (máx 500 filas) |

---

## Investigador multi-agente de phishing

El pipeline multi-agente de phishing sigue esta topología:

```
phishing-triage
  ├─ execute_phishing_email_basic_assessment
  ├─ read_artifact_content (lee señales de riesgo)
  └─ handoff a especialista según señales:
       phishing-url-specialist        → phishing-synthesis
       phishing-header-specialist     → phishing-synthesis
       phishing-attachment-specialist → phishing-synthesis
       (sin señales claras)           → phishing-synthesis (directo)

phishing-synthesis (nodo terminal)
  └─ veredicto JSON estructurado
```

**Campos del veredicto final:**
`overall_verdict`, `risk_level`, `confidence`, `triggered_rules`, `authentication_summary`, `url_summary`, `attachment_summary`, `recommended_action`, `evidence_summary`

### Observaciones disponibles (`phishing_email`)

| Operación | Descripción |
|---|---|
| `phishing_email.basic_assessment` | Evaluación de phishing a partir del contenido del email |
| `phishing_email.header_analysis` | Análisis técnico de cabeceras SPF/DKIM/DMARC/Received |

---

## Despliegue en producción (AWS)

El API corre en ECS Fargate detrás de un ALB. La base de datos es RDS PostgreSQL.

### Recursos AWS actuales

| Recurso | Identificador |
|---|---|
| ALB | `cai-platform-alb` — `cai-platform-alb-472989822.us-east-2.elb.amazonaws.com` |
| ECS Cluster | `cai-platform-cluster` |
| ECS Service | `cai-platform-service` |
| ECR Repository | `cai-platform-api` |
| RDS (PostgreSQL) | `cai-platform-db.c9ow4kqay2rx.us-east-2.rds.amazonaws.com` |
| DB Name | `caiplatform` |
| Secrets Manager | `cai-platform/db-credentials` |
| S3 Bucket | `egslatam-cai-dev` |
| Región | `us-east-2` |

### Flujo de deploy

```bash
# 1. Build y push de la imagen al ECR
make ecr-push

# 2. Forzar nuevo deployment en ECS (usa la imagen más reciente)
make ecs-deploy

# 3. Verificar que el servicio levantó
make health
```

### Base de datos

El API usa PostgreSQL automáticamente si `DATABASE_URL` está definido en el task definition de ECS. Las tablas se crean automáticamente al iniciar (`apply_schema()`). Las credenciales se obtienen desde AWS Secrets Manager.

### Esquema de la base de datos

```sql
-- Casos de investigación (aislados por client_id)
CREATE TABLE cases (
    case_id    TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,      -- multi-tenant isolation
    data       JSONB NOT NULL,     -- Case completo serializado
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Artefactos (inputs, outputs, payloads)
CREATE TABLE artifacts (
    artifact_id    TEXT PRIMARY KEY,
    data           JSONB NOT NULL,
    payload        JSONB,
    content_source TEXT,
    created_at     TIMESTAMPTZ NOT NULL
);

-- Runs de investigación (referenciados a cases)
CREATE TABLE runs (
    run_id     TEXT PRIMARY KEY,
    case_id    TEXT,
    data       JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
```

---

## Desarrollo y tests

### Instalación completa para contribuidores

```bash
python3 -m venv .venv
. .venv/bin/activate
make install-dev   # instala todos los paquetes en modo editable
```

### Comandos de desarrollo

```bash
make test          # correr todos los tests (pytest)
make test-fast     # tests sin marcadores lentos
make lint          # ruff + mypy
make build         # build imagen Docker
make up            # levantar API local (http://localhost:8000)
make down          # bajar contenedores
make health        # GET /health contra PLATFORM_API_BASE_URL
make api-dev       # correr API directamente con uvicorn (sin Docker)
```

### Correr un test específico

```bash
pytest tests/test_platform_api.py::test_health -v
pytest tests/ -k "watchguard" -v
```

### Estructura de tests

```
tests/
├── test_platform_api.py          # Tests de integración del API HTTP
├── test_platform_core.py         # Tests de servicios core
├── test_platform_backends.py     # Tests de backends
├── test_cai_terminal_integration.py  # Tests de integración CAI
└── ...
```

Los tests usan runtime en memoria (`DATABASE_URL` no definido) y no requieren Docker ni PostgreSQL.

---

## Cómo agregar un nuevo backend

Seguir estos pasos para agregar un nuevo caso de uso (ej. `vulnerability_scan`):

### 1. Definir el descriptor en `platform-backends`

```python
# packages/platform-backends/src/platform_backends/vulnerability_scan/__init__.py
VULNERABILITY_SCAN_BACKEND_ID = "vulnerability_scan"

def get_vulnerability_scan_backend_descriptor() -> BackendDescriptor:
    return BackendDescriptor(
        backend_id=VULNERABILITY_SCAN_BACKEND_ID,
        display_name="Vulnerability Scanner",
        ...
    )
```

### 2. Implementar `execute_predefined_observation`

```python
# packages/platform-backends/src/platform_backends/vulnerability_scan/execute.py
def execute_predefined_observation(*, run, input_artifact, input_payload, observation_request):
    # lógica determinista aquí
    ...
```

### 3. Registrar en el runtime

En `apps/platform-api/src/platform_api/runtime/memory.py` y `wiring.py`:
```python
from platform_backends.vulnerability_scan import (
    VULNERABILITY_SCAN_BACKEND_ID,
    execute_predefined_observation as _execute_vuln_scan,
    get_vulnerability_scan_backend_descriptor,
)

# En build_default_runtime() y _build_postgres_runtime():
backend_registry=InProcessBackendRegistry([
    get_watchguard_logs_backend_descriptor(),
    get_phishing_email_backend_descriptor(),
    get_vulnerability_scan_backend_descriptor(),  # ← agregar aquí
])

# En AppRuntime.execute_observation():
if backend_id == VULNERABILITY_SCAN_BACKEND_ID:
    return _execute_vuln_scan(...)
```

### 4. Agregar ruta en el API si es necesario

En `apps/platform-api/src/platform_api/routes/runs.py`, agregar el endpoint específico.

### 5. Agregar herramientas al orquestador CAI

En `apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py`, agregar las `@function_tool` necesarias.

---

## Referencia de endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/backends` | Listar backends disponibles |
| `GET` | `/backends/{backend_id}` | Descriptor de un backend |
| `POST` | `/cases` | Crear caso (`client_id` requerido) |
| `GET` | `/cases/{case_id}` | Obtener caso |
| `GET` | `/cases/{case_id}/artifacts` | Listar artefactos del caso |
| `POST` | `/cases/{case_id}/artifacts` | Adjuntar artefacto de entrada |
| `POST` | `/cases/{case_id}/runs` | Crear run |
| `GET` | `/runs/{run_id}` | Obtener run |
| `GET` | `/runs/{run_id}/artifacts` | Listar artefactos del run |
| `GET` | `/artifacts/{artifact_id}` | Obtener artefacto |
| `GET` | `/artifacts/{artifact_id}/content` | Leer contenido del artefacto |
| `POST` | `/runs/{run_id}/observations/watchguard-normalize` | Observación WatchGuard normalize |
| `POST` | `/runs/{run_id}/observations/watchguard-filter-denied` | Filtrar eventos denegados |
| `POST` | `/runs/{run_id}/observations/watchguard-analytics` | Analytics bundle WatchGuard |
| `POST` | `/runs/{run_id}/observations/watchguard-top-talkers` | Top talkers WatchGuard |
| `POST` | `/runs/{run_id}/observations/watchguard-stage-workspace` | Stage ZIP S3 → CSVs |
| `POST` | `/runs/{run_id}/observations/watchguard-duckdb-analytics` | DuckDB analytics sobre S3 |
| `POST` | `/runs/{run_id}/observations/phishing-basic` | Evaluación básica phishing |
| `POST` | `/runs/{run_id}/observations/phishing-header` | Análisis de cabeceras phishing |
| `POST` | `/runs/{run_id}/queries` | Ejecutar query guarded (requiere approval) |
| `POST` | `/approval-decisions` | Registrar decisión de aprobación |

---

## Recursos AWS

Para más detalles operacionales y comandos de administración AWS, ver [docs/operations/README.md](docs/operations/README.md).

Para la arquitectura de decisiones técnicas, ver [docs/architecture/README.md](docs/architecture/README.md).

Para documentación específica de backends, ver [docs/backends/README.md](docs/backends/README.md).
