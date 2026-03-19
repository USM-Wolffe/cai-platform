# Guía Operacional — cai-platform

Referencia práctica para operadores y desarrolladores. Comandos de administración, bootstrapping, smoke tests, y gestión de la infraestructura AWS.

---

## Modelo de runtime

| Componente | Cómo corre |
|---|---|
| `platform-api` | ECS Fargate (producción) / Docker Compose (local) |
| `cai-orchestrator` | Host-run como CLI. No está containerizado. |
| `packages/*` | Librerías instalables. No son servicios. |
| PostgreSQL | RDS `cai-platform-db` (producción) / in-memory (local/tests) |

---

## Bootstrap en host nuevo (EC2 / Linux)

```bash
git clone <repo-url> cai-platform
cd cai-platform

python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip

# CLI del orquestador (mínimo para smoke tests)
pip install -e apps/cai-orchestrator

# Con soporte CAI (para run-cai-terminal)
pip install -e 'apps/cai-orchestrator[cai]'

# Instalar todo (para contribuidores)
make install-dev
```

---

## Smoke test local

```bash
. .venv/bin/activate
set -a && . .env && set +a

make build   # construye imagen Docker del API
make up      # levanta API en http://localhost:8000
make health  # GET /health → debe retornar {"status": "ok"}

python3 -m cai_orchestrator run-watchguard \
  --client-id "test-client" \
  --title "WatchGuard smoke" \
  --summary "Baseline smoke test." \
  --payload-file examples/watchguard/minimal_payload.json

python3 -m cai_orchestrator run-phishing-email-basic-assessment \
  --client-id "test-client" \
  --title "Phishing smoke" \
  --summary "Phishing baseline test." \
  --payload-file examples/phishing/minimal_payload.json
```

Atajos Makefile (requieren orquestador instalado):
```bash
make demo-watchguard      # run-watchguard con payload de ejemplo
make demo-phishing-email  # phishing assessment con payload de ejemplo
```

---

## Smoke test contra producción (ALB)

```bash
. .venv/bin/activate
set -a && . .env && set +a
# PLATFORM_API_BASE_URL debe apuntar al ALB

make health   # GET contra el ALB

python3 -m cai_orchestrator run-watchguard \
  --client-id "egs-prod" \
  --title "Smoke prod" \
  --summary "Verificar producción." \
  --payload-file examples/watchguard/minimal_payload.json
```

---

## Deploy en AWS

### Build y push de imagen

```bash
make ecr-push    # build + tag + push al ECR (cai-platform-api)
```

### Forzar nuevo deployment en ECS

```bash
make ecs-deploy  # fuerza nuevo deployment del servicio ECS
make health      # verifica que el servicio levantó
```

### Verificar logs del servicio

```bash
aws logs tail /ecs/cai-platform-api --follow --region us-east-2
```

### Ver tareas ECS activas

```bash
aws ecs list-tasks --cluster cai-platform-cluster --region us-east-2
aws ecs describe-tasks \
  --cluster cai-platform-cluster \
  --tasks <task-arn> \
  --region us-east-2
```

---

## Recursos AWS

| Recurso | Identificador |
|---|---|
| ALB | `cai-platform-alb` — `cai-platform-alb-472989822.us-east-2.elb.amazonaws.com` |
| ECS Cluster | `cai-platform-cluster` |
| ECS Service | `cai-platform-service` |
| ECR Repository | `cai-platform-api` |
| RDS (PostgreSQL 16) | `cai-platform-db.c9ow4kqay2rx.us-east-2.rds.amazonaws.com` |
| DB Name / User | `caiplatform` / `caiplatform` |
| Secrets Manager | `cai-platform/db-credentials` |
| S3 Bucket | `egslatam-cai-dev` |
| CloudWatch Logs | `/ecs/cai-platform-api` |
| Región | `us-east-2` |

---

## Pipeline WatchGuard S3 (logs masivos)

Para ZIPs de SharePoint con millones de filas. No carga en RAM — usa DuckDB httpfs sobre S3.

### Paso 1: Subir ZIP a S3

```bash
make upload-workspace ZIP=<archivo>.zip WORKSPACE=<workspace_id>
# Ejemplo:
make upload-workspace ZIP=8011029C760FA.zip WORKSPACE=8011029C760FA
```

Destino: `s3://egslatam-cai-dev/workspaces/{WORKSPACE}/input/uploads/{timestamp}/raw.zip`

### Paso 2: Investigación vía CAI

```bash
. .venv/bin/activate
set -a && . .env && set +a

python3 -m cai_orchestrator run-cai-terminal \
  --client-id "cliente-abc" \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0" \
  --prompt "Analiza el workspace 8011029C760FA. Encuentra el ZIP más reciente, crea el caso, estágealo, corre analytics y dime los top IPs con más denials."
```

El agente ejecuta automáticamente:
1. `find_latest_workspace_upload` → s3_uri
2. `attach_workspace_s3_zip_reference` + `create_run`
3. `execute_watchguard_stage_workspace_zip` → extrae CSVs a S3 staging
4. `execute_watchguard_duckdb_workspace_analytics` → agregaciones DuckDB
5. `execute_watchguard_duckdb_workspace_query` → drill-down por IP / alarma / acción

### Variables de entorno requeridas para S3

| Variable | Default | Descripción |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | — | Credencial S3/Bedrock |
| `AWS_SECRET_ACCESS_KEY` | — | Credencial S3/Bedrock |
| `AWS_DEFAULT_REGION` | `us-east-2` | Región |
| `WATCHGUARD_S3_BUCKET` | `egslatam-cai-dev` | Bucket S3 |

---

## Monitor IMAP de phishing

```bash
# Configurar en .env:
# IMAP_HOST=imap.gmail.com
# IMAP_PORT=993
# IMAP_USERNAME=buzón@empresa.com
# IMAP_PASSWORD=app-password-de-gmail

# Dry-run: procesar un email sin marcarlo como leído
python3 -m cai_orchestrator run-phishing-monitor \
  --client-id "cliente-abc" --once --dry-run

# Procesar + investigar con CAI
python3 -m cai_orchestrator run-phishing-monitor \
  --client-id "cliente-abc" --once --cai-investigate \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"

# Loop continuo
python3 -m cai_orchestrator run-phishing-monitor --client-id "cliente-abc"
```

Para Gmail: activar verificación en dos pasos → generar app password en myaccount.google.com/apppasswords.

---

## Base de datos

El API usa PostgreSQL automáticamente si `DATABASE_URL` está definida. Las tablas se crean automáticamente al iniciar (`apply_schema()` es idempotente).

### Conexión directa al RDS (desde EC2 en la VPC)

```bash
# Las credenciales están en Secrets Manager:
aws secretsmanager get-secret-value \
  --secret-id cai-platform/db-credentials \
  --region us-east-2 \
  --query SecretString --output text

psql -h cai-platform-db.c9ow4kqay2rx.us-east-2.rds.amazonaws.com \
     -U caiplatform -d caiplatform
```

### Consultas útiles

```sql
-- Ver todos los casos de un cliente
SELECT case_id, data->>'title', data->>'workflow_type', created_at
FROM cases WHERE client_id = 'cliente-abc' ORDER BY created_at DESC LIMIT 20;

-- Ver runs de un caso
SELECT run_id, data->>'status', data->>'backend_ref', updated_at
FROM runs WHERE case_id = '<case_id>';

-- Contar por cliente
SELECT client_id, COUNT(*) FROM cases GROUP BY client_id;
```

---

## Comandos Makefile completos

```bash
make install-dev     # instalar todos los paquetes en modo editable (contribuidores)
make test            # correr tests completos
make test-fast       # tests rápidos (sin marcadores slow)
make lint            # ruff + mypy
make build           # build imagen Docker del API
make up              # levantar API local (docker compose up)
make down            # bajar contenedores
make health          # GET /health contra PLATFORM_API_BASE_URL
make api-dev         # uvicorn con hot-reload (sin Docker)
make ecr-push        # build + push imagen al ECR
make ecs-deploy      # forzar nuevo deployment ECS
make demo-watchguard      # smoke test WatchGuard
make demo-phishing-email  # smoke test phishing
make upload-workspace ZIP=... WORKSPACE=...  # subir ZIP WatchGuard a S3
```
