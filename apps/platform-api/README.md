# platform-api

API HTTP determinista de cai-platform. Expone la superficie pública para gestión de casos, artefactos, runs, observaciones, queries y aprobaciones.

## Responsabilidad

- Composición de la app FastAPI, rutas delgadas, y wiring del runtime.
- Selecciona automáticamente PostgreSQL (producción) o memoria in-process (desarrollo/tests) según `DATABASE_URL`.
- Registra múltiples backends en proceso: `watchguard_logs` y `phishing_email`.

**No debe contener**: lógica de dominio, implementaciones de backend, código CAI, ni autenticación.

## Runtime

```bash
# Producción: corre en ECS Fargate detrás del ALB
# URL: http://cai-platform-alb-*.us-east-2.elb.amazonaws.com

# Local (Docker Compose):
make up       # levanta API en http://localhost:8000 y UI en http://localhost:8501
make health   # verifica el health check
make down     # baja los contenedores

# Local (sin Docker, para desarrollo):
make api-dev  # uvicorn con hot-reload
```

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `PLATFORM_API_HOST` | `0.0.0.0` | Host de uvicorn |
| `PLATFORM_API_PORT` | `8000` | Puerto de uvicorn |
| `DATABASE_URL` | — | DSN PostgreSQL. Si no se define, usa memoria in-process |

Si `DATABASE_URL` no está definida, el API usa `InMemoryCaseRepository`, `InMemoryArtifactRepository` e `InMemoryRunRepository`. En producción (ECS), `DATABASE_URL` se inyecta desde el task definition con credenciales de AWS Secrets Manager.

## Módulos principales

| Módulo | Descripción |
|---|---|
| `platform_api.app` | Creación de la app FastAPI y entrypoint |
| `platform_api.routes.health` | `GET /health` |
| `platform_api.routes.cases` | CRUD de casos (con `client_id` para multi-tenant) |
| `platform_api.routes.runs` | Runs y todas las observaciones |
| `platform_api.routes.queries` | Queries guarded y decisiones de aprobación |
| `platform_api.routes.artifacts` | Lectura de artefactos y su contenido |
| `platform_api.schemas` | Schemas Pydantic de request/response |
| `platform_api.runtime.memory` | `AppRuntime`, repos in-memory, `AppRuntime.execute_observation()` |
| `platform_api.runtime.postgres` | `PostgresCaseRepository`, `PostgresArtifactRepository`, `PostgresRunRepository`, schema bootstrap |
| `platform_api.runtime.wiring` | `create_runtime()` — selecciona backend según `DATABASE_URL` |

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/backends` | Listar backends |
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
| `POST` | `/runs/{run_id}/observations/watchguard-normalize` | WatchGuard: normalizar logs |
| `POST` | `/runs/{run_id}/observations/watchguard-filter-denied` | WatchGuard: filtrar denegados |
| `POST` | `/runs/{run_id}/observations/watchguard-analytics-basic` | WatchGuard: analytics básico |
| `POST` | `/runs/{run_id}/observations/watchguard-top-talkers-basic` | WatchGuard: top talkers |
| `POST` | `/runs/{run_id}/observations/watchguard-ingest-workspace-zip` | WatchGuard: ingestión ZIP (en RAM) |
| `POST` | `/runs/{run_id}/observations/watchguard-stage-workspace-zip` | WatchGuard: staging ZIP → S3 CSVs |
| `POST` | `/runs/{run_id}/observations/watchguard-duckdb-workspace-analytics` | WatchGuard: analytics DuckDB sobre S3 |
| `POST` | `/runs/{run_id}/observations/watchguard-ddos-temporal-analysis` | WatchGuard DDoS: serie temporal |
| `POST` | `/runs/{run_id}/observations/watchguard-ddos-top-destinations` | WatchGuard DDoS: destinos principales |
| `POST` | `/runs/{run_id}/observations/watchguard-ddos-top-sources` | WatchGuard DDoS: fuentes principales |
| `POST` | `/runs/{run_id}/observations/watchguard-ddos-segment-analysis` | WatchGuard DDoS: análisis por segmento CIDR |
| `POST` | `/runs/{run_id}/observations/watchguard-ddos-ip-profile` | WatchGuard DDoS: perfil de IP |
| `POST` | `/runs/{run_id}/observations/watchguard-ddos-hourly-distribution` | WatchGuard DDoS: distribución horaria |
| `POST` | `/runs/{run_id}/observations/watchguard-ddos-protocol-breakdown` | WatchGuard DDoS: distribución por protocolo |
| `POST` | `/runs/{run_id}/observations/phishing-email-basic-assessment` | Phishing: evaluación básica |
| `POST` | `/runs/{run_id}/observations/phishing-email-header-analysis` | Phishing: análisis de cabeceras |
| `POST` | `/runs/{run_id}/queries/watchguard-guarded-filtered-rows` | Query guarded (requiere aprobación) |
| `POST` | `/runs/{run_id}/queries/watchguard-duckdb-workspace-query` | Query DuckDB guarded (requiere aprobación) |
| `POST` | `/approval-decisions` | Registrar decisión de aprobación |

## Input shapes

**WatchGuard (logs locales):**
```json
{"log_type": "traffic", "csv_rows": ["15/03/2026 00:00,,,,,ALLOW,allow-web,,TCP,,,10.0.0.1,51514,8.8.8.8,53,,,,,,,,traffic,dns-allow"]}
```

**WatchGuard (workspace S3 ZIP):**
```json
{"source": "workspace_s3_zip", "workspace": "8011029C760FA", "s3_uri": "s3://egslatam-cai-dev/workspaces/8011029C760FA/input/uploads/20251022_143055/raw.zip"}
```

**Phishing email:**
```json
{
  "subject": "Urgent action required",
  "sender": {"email": "attacker@example.com", "display_name": "Security"},
  "reply_to": null,
  "urls": ["http://malicious.example/login"],
  "text": "Click here now.",
  "attachments": [{"filename": "invoice.zip", "content_type": "application/zip"}]
}
```

## Agregar un nuevo backend

1. Implementar el backend en `packages/platform-backends/`
2. Registrar su descriptor en `AppRuntime` dentro de `runtime/memory.py` y `runtime/wiring.py`
3. Agregar el dispatch en `AppRuntime.execute_observation()`
4. Agregar el endpoint en `routes/runs.py`

No modificar las rutas para agregar lógica de backend — la lógica va en el backend, las rutas solo pasan `backend_id` y `operation_kind`.

## Base de datos PostgreSQL

El esquema se aplica automáticamente al iniciar con `apply_schema()` (idempotente). Ver [runtime/postgres.py](src/platform_api/runtime/postgres.py) para el SQL completo. Los datos se almacenan como JSONB para evitar migraciones de schema cuando los modelos Pydantic evolucionan.
