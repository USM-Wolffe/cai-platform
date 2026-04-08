# Mapa del repositorio cai-platform (referencia experta)

Este documento resume la estructura real del repositorio, con énfasis en el despliegue actual en AWS y en cómo se conectan las capas de código.

## 1. Visión general

`cai-platform` es un monorepo Python para investigación de ciberseguridad. La plataforma expone un API determinista, una UI Streamlit y un orquestador host-run para agentes CAI.

- Fuente de verdad documental: [docs/README.md](../README.md)
- Operación y despliegue: [docs/operations/README.md](../operations/README.md) y [docs/operations/deploy-aws.md](../operations/deploy-aws.md)

## 2. Estructura del repositorio

```mermaid
flowchart TB
  subgraph apps [Apps]
    platformApi[platform-api]
    platformUi[platform-ui]
    caiOrchestrator[cai-orchestrator]
  end
  subgraph packages [Packages]
    contracts[platform-contracts]
    core[platform-core]
    adapters[platform-adapters]
    backends[platform-backends]
  end
  subgraph support [Support]
    testsDir[tests]
    docsDir[docs]
    infraDir[infrastructure]
    examplesDir[examples]
  end
  contracts --> core
  contracts --> adapters
  contracts --> backends
  core --> backends
  contracts --> platformApi
  core --> platformApi
  backends --> platformApi
  platformApi --> platformUi
  platformApi --> caiOrchestrator
```

| Área | Ubicación | Rol |
|---|---|---|
| Contratos | `packages/platform-contracts/` | Schemas Pydantic compartidos: casos, artifacts, runs, observaciones, queries y aprobaciones. |
| Core | `packages/platform-core/` | Servicios de coordinación, audit trail, approvals y puertos de persistencia. |
| Adapters | `packages/platform-adapters/` | Normalización de WatchGuard y phishing email. |
| Backends | `packages/platform-backends/` | Lógica determinista de `watchguard_logs` y `phishing_email`. |
| API | `apps/platform-api/` | FastAPI, runtime in-memory o PostgreSQL según `DATABASE_URL`, y exposición HTTP de observaciones/queries. |
| UI | `apps/platform-ui/` | Streamlit para investigaciones WatchGuard, phishing e IMAP. |
| Orquestador | `apps/cai-orchestrator/` | CLI host-run, agentes CAI, pipeline DDoS e informes offline. |
| Infra | `infrastructure/terraform/` | ECS, ALB, RDS, S3, ECR, IAM y monitoreo en AWS. |
| Tests | `tests/` | Cobertura por boundary: `contracts/`, `core/`, `adapters/`, `backends/`, `apps/`. |

## 3. Topología de ejecución

### Producción

```mermaid
flowchart LR
  user[Analista] --> alb[ALB]
  alb --> apiSvc[platform-api on ECS]
  alb --> uiSvc[platform-ui on ECS]
  apiSvc --> rds[(RDS PostgreSQL)]
  apiSvc --> s3[(S3 workspaces)]
  orchestrator[cai-orchestrator host-run] --> apiSvc
```

- El cluster ECS se crea con `name_prefix`, que en `prod` hoy es `cai-platform`.
- `platform-api` recibe `DATABASE_URL` desde Secrets Manager.
- `platform-ui` consume `PLATFORM_API_BASE_URL` apuntando al ALB.

### Desarrollo local

- `compose.yml` levanta `platform-api` y `platform-ui`.
- `make api-dev` corre solo el API local.
- Si `DATABASE_URL` no está definida, el runtime usa repositorios in-memory.

## 4. Stack tecnológico

| Capa | Tecnología |
|---|---|
| Lenguaje | Python 3.12+ |
| Empaquetado | setuptools con layout `src/` |
| API HTTP | FastAPI + uvicorn |
| UI | Streamlit |
| Cliente HTTP | httpx |
| Contratos | Pydantic 2 |
| Persistencia | PostgreSQL en prod / in-memory en dev y tests |
| Infra | AWS ECS Fargate, ALB, RDS, S3, ECR, Secrets Manager, CloudWatch |
| CAI | Dependencia opcional `cai-framework` en `apps/cai-orchestrator[cai]` |

## 5. Entradas principales

### `platform-api`

- Entrada: `apps/platform-api/src/platform_api/app.py`
- Runtime: `apps/platform-api/src/platform_api/runtime/wiring.py`
- Rutas: `apps/platform-api/src/platform_api/routes/`
- Backends registrados: `watchguard_logs`, `phishing_email`

Observaciones expuestas hoy:

- WatchGuard clásico: ingest, normalize, filter denied, analytics basic, top talkers, stage workspace zip, duckdb analytics
- WatchGuard DDoS: temporal analysis, top destinations, top sources, segment analysis, ip profile, hourly distribution, protocol breakdown
- Phishing: basic assessment, header analysis
- Queries: `watchguard-guarded-filtered-rows`, `watchguard-duckdb-workspace-query`

### `cai-orchestrator`

- Entrada: `apps/cai-orchestrator/src/cai_orchestrator/app.py`
- Cliente: `cai_orchestrator.client.PlatformApiClient`
- Configuración: `PLATFORM_API_BASE_URL`, `CAI_AGENT_TYPE`, `CAI_MODEL`

Subcomandos CLI actuales:

| Subcomando | Descripción |
|---|---|
| `run-watchguard` | Análisis básico de logs WatchGuard (normalización + resumen) |
| `run-watchguard-filter-denied` | Filtrado de eventos denegados |
| `run-watchguard-analytics-basic` | Bundle de analytics básico |
| `run-watchguard-top-talkers-basic` | Top IPs por tráfico |
| `run-watchguard-guarded-query` | Query guarded con aprobación explícita |
| `run-phishing-email-basic-assessment` | Evaluación heurística de un email de phishing |
| `run-phishing-monitor` | Loop IMAP: monitorea un buzón y analiza emails reenviados |
| `run-phishing-investigate` | Pipeline multi-agente de phishing sobre un payload |
| `run-cai-terminal` | Terminal interactiva con el agente `egs-analist` |
| `run-ddos-investigate` | Pipeline híbrido DDoS de 3 fases sobre un workspace S3 |
| `run-blueteam-investigate` | Pipeline de investigación blue team sobre logs multi-fuente |
| `run-log-monitor` | Monitor de logs en tiempo real |
| `report-collect` | Recolecta artifacts de un caso para un informe |
| `report-generate` | Genera informe PDF/HTML a partir de artifacts recolectados |
| `get-run-status` | Consulta el estado de un run por ID |
| `list-run-artifacts` | Lista los artifacts de un run |
| `read-artifact-content` | Lee el contenido de un artifact |

## 6. Flujo de datos

1. El orquestador o la UI llaman al `platform-api`.
2. Las rutas construyen `ObservationRequest` o `QueryRequest`.
3. `AppRuntime.execute_observation()` despacha a `platform_backends.*`.
4. El resultado se guarda como artifact derivado y se publica sobre el run/case.
5. En producción, ese estado termina en PostgreSQL; en local, en memoria.

## 7. Archivos operativos clave

| Archivo | Propósito |
|---|---|
| `.env.example` | Variables de referencia para API, UI y orquestador |
| `compose.yml` | Stack local con `platform-api` y `platform-ui` |
| `Makefile` | Comandos de desarrollo, smoke tests, Terraform y operación ECS |
| `.github/workflows/deploy.yml` | Pipeline de despliegue |
| `infrastructure/terraform/outputs.tf` | Outputs de `alb_dns`, `rds_endpoint`, ECR y dashboard |

## 8. Backend summary

### `watchguard_logs`

- Inputs: logs CSV pequeños o referencias `workspace_s3_zip`
- Outputs:
  - Clásicas: `normalize_and_summarize`, `filter_denied_events`, `analytics_bundle_basic`, `top_talkers_basic`, `workspace_zip_ingestion`
  - S3/DuckDB: `stage_workspace_zip`, `duckdb_workspace_analytics`
  - DDoS: `ddos_temporal_analysis`, `ddos_top_sources`, `ddos_top_destinations`, `ddos_segment_analysis`, `ddos_ip_profile`, `ddos_protocol_breakdown`, `ddos_hourly_distribution`
- Queries guarded: `guarded_filtered_rows`, `duckdb_workspace_query`
- Artifact especial: `watchguard.nist_case_snapshot` — serialización del estado NIST completo (decisiones, evidencia, etapas) para consumo de la UI sin acceso al host local

### `phishing_email`

- Inputs: payload JSON de email o `.eml` parseado por el orquestador
- Outputs: `basic_assessment`, `header_analysis`
- Uso extendido: pipeline multi-agente en `phishing_agents.py` (triage → especialistas → síntesis)

## 9. Tests

- `tests/contracts/`: surface e invariantes de contratos
- `tests/core/`: casos, runs, observations, approvals, audit
- `tests/adapters/`: normalización WatchGuard y phishing
- `tests/backends/`: conformancia de backends y boundaries
- `tests/apps/`: API, orquestador, terminal CAI y smoke tests de integración

Ejecución habitual:

- `make test`
- `make test-apps`
- `python3 -m pytest tests/backends/test_watchguard_logs_backend.py`

## 10. Convenciones

- Cada package/app usa `src/<package_name>/`.
- Los README de package resumen límites locales; la documentación transversal vive en `docs/`.
- La plataforma está pensada para producción en AWS; los ejemplos locales son para desarrollo y contribución.
