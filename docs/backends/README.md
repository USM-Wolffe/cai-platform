# Documentación de Backends

Referencia técnica de los backends disponibles en cai-platform. Cada backend implementa un caso de uso de ciberseguridad y expone observaciones predefinidas y/o queries guarded.

---

## `watchguard_logs`

**backend_id**: `watchguard_logs`
**workflow_type**: `log_investigation`
**Ubicación**: `packages/platform-backends/src/platform_backends/watchguard_logs/`

Analiza logs de firewall WatchGuard exportados desde el portal. Soporta dos modos:
- **Logs locales**: CSV pequeños enviados como payload JSON.
- **Workspace S3 ZIP**: ZIPs de SharePoint (1.5–10M filas) procesados vía DuckDB httpfs sin carga en RAM.

### Observaciones predefinidas

| `operation_kind` | Endpoint | Descripción |
|---|---|---|
| `watchguard_logs.normalize_and_summarize` | `POST /runs/{id}/observations/watchguard-normalize` | Normaliza logs CSV locales, produce registros estructurados + resumen |
| `watchguard_logs.filter_denied_events` | `POST /runs/{id}/observations/watchguard-filter-denied` | Filtra solo eventos con acción `DENY` |
| `watchguard_logs.analytics_bundle_basic` | `POST /runs/{id}/observations/watchguard-analytics-basic` | Estadísticas: distribución de acciones, protocolos, top políticas |
| `watchguard_logs.top_talkers_basic` | `POST /runs/{id}/observations/watchguard-top-talkers-basic` | Top src/dst IPs por volumen de tráfico |
| `watchguard_logs.workspace_zip_ingestion` | `POST /runs/{id}/observations/watchguard-ingest-workspace-zip` | Ingesta ZIP desde S3 cargando en RAM (solo ZIPs pequeños) |
| `watchguard_logs.stage_workspace_zip` | `POST /runs/{id}/observations/watchguard-stage-workspace-zip` | Descarga ZIP streaming → extrae TARs → sube CSVs individuales a S3 staging. **Preferido para ZIPs grandes.** |
| `watchguard_logs.duckdb_workspace_analytics` | `POST /runs/{id}/observations/watchguard-duckdb-workspace-analytics` | DuckDB lee CSVs desde S3 via httpfs. Retorna: `top_src_ips`, `top_dst_ips`, `action_counts`, `deny_count`, `protocol_breakdown`, `alarm_type_counts`, `time_range` |

### Queries guarded (requieren aprobación explícita)

| `query_class` | Endpoint | Descripción |
|---|---|---|
| `watchguard_logs.guarded_filtered_rows` | `POST /runs/{id}/queries/watchguard-guarded-filtered-rows` | Filtro guarded sobre logs normalizados en memoria |
| `watchguard_logs.duckdb_workspace_query` | `POST /runs/{id}/queries/watchguard-duckdb-workspace-query` | Filtro DuckDB guarded sobre CSVs staged en S3. Max 500 filas. |

### Shapes de input artifacts

**Logs locales** (para observaciones de normalización/filtrado):
```json
{
  "log_type": "traffic",
  "csv_rows": [
    "15/03/2026 00:00,,,,,DENY,deny-policy,,TCP,,,10.0.0.1,1234,8.8.8.8,53,,,,,,,,traffic,dns-block"
  ]
}
```

**Workspace S3 ZIP** (para staging y analytics DuckDB):
```json
{
  "source": "workspace_s3_zip",
  "workspace": "8011029C760FA_8011029DE7578",
  "s3_uri": "s3://egslatam-cai-dev/workspaces/8011029C760FA_8011029DE7578/input/uploads/20251022_143055/raw.zip"
}
```

**Workspace staging** (producido por `stage_workspace_zip`, usado como input de analytics y DuckDB query):
```json
{
  "source": "workspace_staging",
  "workspace": "8011029C760FA_8011029DE7578",
  "bucket": "egslatam-cai-dev",
  "staging_prefix": "workspaces/8011029C760FA_8011029DE7578/staging/20251022_143055",
  "upload_id": "20251022_143055",
  "families": ["traffic", "alarm", "event"],
  "file_counts": {"traffic": 42, "alarm": 3, "event": 8},
  "date_range": {"min": "2025-10-22", "max": "2025-10-24"}
}
```

### DuckDB workspace query — campos permitidos por familia

| Familia | Campos permitidos |
|---|---|
| `traffic` | `src_ip`, `dst_ip`, `action`, `protocol`, `policy`, `src_port`, `dst_port` |
| `alarm` | `alarm_type`, `src_ip`, `timestamp` |
| `event` | `type`, `timestamp` |

Operadores soportados: `=`, `!=`, `like`, `in`, `>`, `<`, `>=`, `<=`.

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

---

## `phishing_email`

**backend_id**: `phishing_email`
**workflow_type**: `defensive_analysis`
**Ubicación**: `packages/platform-backends/src/platform_backends/phishing_email/`

Analiza emails sospechosos para detectar phishing. Soporta evaluación heurística completa y análisis técnico de cabeceras SMTP.

### Observaciones predefinidas

| `operation_kind` | Endpoint | Descripción |
|---|---|---|
| `phishing_email.basic_assessment` | `POST /runs/{id}/observations/phishing-email-basic-assessment` | Evaluación completa: reglas heurísticas, señales URL, adjuntos, autenticación SPF/DKIM/DMARC |
| `phishing_email.header_analysis` | `POST /runs/{id}/observations/phishing-email-header-analysis` | Análisis técnico de cabeceras SMTP: SPF, DKIM, DMARC, cadena Received |

### Shape de input artifact

```json
{
  "subject": "Urgent action required: verify your account",
  "sender": {
    "email": "security.alerts@gmail.com",
    "display_name": "Security Support"
  },
  "reply_to": {
    "email": "billing@corp-payments.example",
    "display_name": "Billing Desk"
  },
  "urls": ["http://198.51.100.7/login?verify=1"],
  "text": "Immediately update your account. Payment required today to avoid suspension.",
  "attachments": [
    {"filename": "invoice.zip", "content_type": "application/zip"}
  ]
}
```

Notas:
- `reply_to` puede ser `null`.
- `urls` y `attachments` deben ser listas explícitas (vacías si no hay).
- Para el análisis de cabeceras, el payload incluye las cabeceras SMTP raw.

### Pipeline multi-agente (CAI)

El backend `phishing_email` está diseñado para ser usado por el pipeline multi-agente:

```
phishing-triage
  ├─ phishing_email.basic_assessment
  └─ handoff según señales detectadas:
       URLs sospechosas    → phishing-url-specialist
       Cabeceras anómalas  → phishing-header-specialist
       Adjuntos peligrosos → phishing-attachment-specialist
       (sin señales)       → phishing-synthesis (directo)

phishing-synthesis → veredicto JSON estructurado
```

**Campos del veredicto**:
- `overall_verdict`: `phishing` | `suspicious` | `legitimate` | `uncertain`
- `risk_level`: `critical` | `high` | `medium` | `low`
- `confidence`: `0.0` – `1.0`
- `triggered_rules`: lista de reglas heurísticas activadas
- `authentication_summary`: resultado SPF/DKIM/DMARC
- `url_summary`: análisis de URLs encontradas
- `attachment_summary`: análisis de adjuntos
- `recommended_action`: acción recomendada al analista
- `evidence_summary`: resumen de evidencia

---

## Agregar un nuevo backend

Para agregar un nuevo caso de uso (ej. `vulnerability_scan`):

1. **Crear el paquete** en `packages/platform-backends/src/platform_backends/<nombre>/`
2. **Implementar `descriptor.py`**: `get_<nombre>_backend_descriptor()` que retorna un `BackendDescriptor` con sus `QueryDefinition` y capacidades
3. **Implementar `execute.py`**: `execute_predefined_observation(*, run, input_artifact, input_payload, observation_request)` con la lógica determinista
4. **Registrar en el runtime** ([apps/platform-api/src/platform_api/runtime/memory.py](../../apps/platform-api/src/platform_api/runtime/memory.py)):
   - Agregar el descriptor a `InProcessBackendRegistry` en `build_default_runtime()` y `_build_postgres_runtime()`
   - Agregar el dispatch en `AppRuntime.execute_observation()`
5. **Agregar endpoint en el API** ([apps/platform-api/src/platform_api/routes/runs.py](../../apps/platform-api/src/platform_api/routes/runs.py))
6. **Agregar herramientas CAI** ([apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py](../../apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py))
7. **Documentar** en este archivo

Ver [docs/architecture/README.md](../architecture/README.md) para las reglas de dependencias entre capas.
