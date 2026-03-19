# platform-backends

Implementaciones deterministas de backends para cai-platform. Cada backend es un caso de uso de ciberseguridad.

## Responsabilidad

- Implementar la lógica de investigación para cada backend (`watchguard_logs`, `phishing_email`).
- Exponer descriptores (`BackendDescriptor`) con las operaciones disponibles y sus niveles de riesgo.
- Ser completamente deterministas: misma entrada → mismo resultado.

**No debe contener**: lógica de casos, persistencia, código CAI, handlers HTTP, ni sistemas de plugins genéricos.

## Backends implementados

### `platform_backends.watchguard_logs`

**backend_id**: `watchguard_logs` | **workflow_type**: `log_investigation`

Analiza logs WatchGuard. Soporta logs locales (CSV en payload JSON) y workspace ZIPs grandes desde S3 (DuckDB httpfs, sin carga en RAM).

| Módulo | Descripción |
|---|---|
| `watchguard_logs.descriptor` | `get_watchguard_logs_backend_descriptor()` — todas las operaciones declaradas |
| `watchguard_logs.execute` | `execute_predefined_observation()` — dispatcher de operaciones |
| `watchguard_logs.models` | Modelos internos del backend |
| `watchguard_logs.errors` | Errores específicos del backend |

**Operaciones**: `normalize_and_summarize`, `filter_denied_events`, `analytics_bundle_basic`, `top_talkers_basic`, `workspace_zip_ingestion`, `stage_workspace_zip`, `duckdb_workspace_analytics`, `guarded_filtered_rows` (guarded), `duckdb_workspace_query` (guarded).

### `platform_backends.phishing_email`

**backend_id**: `phishing_email` | **workflow_type**: `defensive_analysis`

Analiza emails sospechosos usando reglas heurísticas deterministas. Sin lookups de internet.

| Módulo | Descripción |
|---|---|
| `phishing_email.descriptor` | `get_phishing_email_backend_descriptor()` |
| `phishing_email.execute` | `execute_predefined_observation()`, `execute_header_analysis_observation()` |
| `phishing_email.models` | Modelos internos |
| `phishing_email.errors` | Errores específicos |

**Operaciones**: `basic_assessment`, `header_analysis`.

## Patrón de implementación de un backend

Cada backend debe implementar:

```python
# descriptor.py
def get_<backend>_backend_descriptor() -> BackendDescriptor:
    return BackendDescriptor(
        backend_id=BACKEND_ID,
        display_name="...",
        supported_workflow_types=[WorkflowType.LOG_INVESTIGATION],
        predefined_queries=[QueryDefinition(query_class="...", risk_class=RiskClass.LOW)],
        ...
    )

# execute.py
def execute_predefined_observation(
    *, run: Run, input_artifact: Artifact,
    input_payload: object, observation_request: ObservationRequest
) -> object:
    # lógica determinista → retorna payload del resultado
    ...
```

Ver [docs/backends/README.md](../../docs/backends/README.md) para documentación completa de cada backend, shapes de input/output, y campos permitidos en queries.

## Regla de dependencias

Puede importar de `platform-contracts`, `platform-core`, y `platform-adapters`. No puede importar de `platform-api` ni de `cai-orchestrator`.
