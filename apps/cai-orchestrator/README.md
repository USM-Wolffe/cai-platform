# cai-orchestrator

CLI y app de orquestación CAI para cai-platform. Conecta los agentes de IA (CAI/Claude) con el API de la plataforma. Se ejecuta en el host, no está containerizado.

## Responsabilidad

- CLI para investigaciones WatchGuard y phishing.
- Terminal CAI interactiva (`egs-analist` y sub-agentes especializados).
- Monitor IMAP para phishing automatizado.
- Cliente HTTP delgado sobre `platform-api`.

**No debe contener**: lógica de backends, persistencia canónica, código de vendor adaptado, ni estado interno de casos.

## Instalación

```bash
python3 -m venv .venv
. .venv/bin/activate

# Instalación base (CLI sin CAI)
pip install -e apps/cai-orchestrator

# Con soporte CAI (para run-cai-terminal)
pip install -e 'apps/cai-orchestrator[cai]'
```

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `PLATFORM_API_BASE_URL` | `http://127.0.0.1:8000` | URL del `platform-api`; en producción normalmente apunta al ALB de AWS |
| `CAI_MODEL` | — | Modelo Bedrock, ej. `bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0` |
| `CAI_AGENT_TYPE` | `egs-analist` | Tipo de agente CAI |

## Comandos CLI

Todos los comandos requieren `--client-id` para aislamiento multi-tenant.

### WatchGuard

```bash
# Normalización y resumen
python3 -m cai_orchestrator run-watchguard \
  --client-id "cliente-abc" \
  --title "Logs enero" \
  --summary "Analizar tráfico denegado." \
  --payload-file examples/watchguard/minimal_payload.json

# Filtrar eventos denegados
python3 -m cai_orchestrator run-watchguard-filter-denied \
  --client-id "cliente-abc" --title "..." --summary "..." --payload-file ...

# Analytics básico
python3 -m cai_orchestrator run-watchguard-analytics-basic \
  --client-id "cliente-abc" --title "..." --summary "..." --payload-file ...

# Top talkers
python3 -m cai_orchestrator run-watchguard-top-talkers-basic \
  --client-id "cliente-abc" --title "..." --summary "..." --payload-file ...

# Query guarded (requiere aprobación)
python3 -m cai_orchestrator run-watchguard-guarded-query \
  --client-id "cliente-abc" \
  --title "Query guarded" \
  --summary "Investigar IP específica." \
  --payload-file examples/watchguard/minimal_payload.json \
  --query-file examples/watchguard/guarded_query_src_ip.json \
  --reason "Investigar src_ip 10.0.0.1" \
  --approval-reason "Analista aprobó."
```

### Phishing

```bash
python3 -m cai_orchestrator run-phishing-email-basic-assessment \
  --client-id "cliente-abc" \
  --title "Email sospechoso" \
  --summary "Verificar si es phishing." \
  --payload-file examples/phishing/minimal_payload.json
```

```bash
# Pipeline multi-agente desde un .eml
python3 -m cai_orchestrator run-phishing-investigate \
  --client-id "cliente-abc" \
  --eml-file "/ruta/al/email-sospechoso.eml" \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"
```

### Monitor IMAP

```bash
# Dry-run (un email, sin marcarlo como leído)
python3 -m cai_orchestrator run-phishing-monitor \
  --client-id "cliente-abc" --once --dry-run

# Procesar un email + investigación CAI completa
python3 -m cai_orchestrator run-phishing-monitor \
  --client-id "cliente-abc" --once --cai-investigate \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"

# Loop continuo (intervalo por defecto: 60 s)
python3 -m cai_orchestrator run-phishing-monitor --client-id "cliente-abc"
```

### Terminal CAI interactiva

```bash
# Modo interactivo (el agente pide input)
python3 -m cai_orchestrator run-cai-terminal \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"

# One-shot con prompt
python3 -m cai_orchestrator run-cai-terminal \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0" \
  --prompt "Analiza el workspace 8011029C760FA. Estágealo, corre analytics y muéstrame los top IPs denegados."
```

### Pipeline DDoS e informes

```bash
# Investigación híbrida DDoS sobre un workspace ya subido a S3
python3 -m cai_orchestrator run-ddos-investigate \
  --workspace-id "logs-ejemplo-ddos" \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"

# Recolectar datos del caso para el informe offline
python3 -m cai_orchestrator report-collect case-0009e49b2476

# Generar informe HTML o PDF a partir del caso recolectado
python3 -m cai_orchestrator report-generate case-0009e49b2476 \
  --client "Productos Fernandez" \
  --informante "Analista SOC" \
  --crm-case "LL-IR-PFALIMENTOS-2026-001" \
  --format html
```

### Inspección de runs y artefactos

```bash
python3 -m cai_orchestrator get-run-status --run-id <run_id>
python3 -m cai_orchestrator list-run-artifacts --run-id <run_id>
python3 -m cai_orchestrator read-artifact-content --artifact-id <artifact_id>
```

## Agentes CAI disponibles

| `CAI_AGENT_TYPE` | Descripción |
|---|---|
| `egs-analist` (default) | Agente general. Puede delegar a phishing-investigator. |
| `platform_investigation_agent` | Alias de `egs-analist` |
| `phishing_investigator` | Entra directamente al pipeline multi-agente de phishing |
| `ddos_investigator` | Ejecuta el pipeline híbrido DDoS basado en staging S3 e informe |

### Herramientas disponibles en `egs-analist`

**Core**: `health`, `create_case`, `attach_input_artifact`, `attach_workspace_s3_zip_reference`, `create_run`

**Pipeline S3**: `find_latest_workspace_upload`, `execute_watchguard_stage_workspace_zip`, `execute_watchguard_duckdb_workspace_analytics`, `execute_watchguard_duckdb_workspace_query`

**WatchGuard clásico**: `execute_watchguard_workspace_zip_ingestion`, `execute_watchguard_normalize`, `execute_watchguard_filter_denied`, `execute_watchguard_analytics_basic`, `execute_watchguard_top_talkers_basic`, `execute_watchguard_guarded_custom_query`

**DDoS sobre staging**: `execute_watchguard_ddos_temporal_analysis`, `execute_watchguard_ddos_top_destinations`, `execute_watchguard_ddos_top_sources`, `execute_watchguard_ddos_segment_analysis`, `execute_watchguard_ddos_ip_profile`, `execute_watchguard_ddos_hourly_distribution`, `execute_watchguard_ddos_protocol_breakdown`

**Phishing**: `execute_phishing_email_basic_assessment`

**Inspección**: `get_case`, `get_run`, `get_run_status`, `list_run_artifacts`, `read_artifact_content`

## Pipeline multi-agente de phishing

```
phishing-triage
  ├─ execute_phishing_email_basic_assessment
  ├─ read_artifact_content
  └─ handoff según señales:
       phishing-url-specialist        → phishing-synthesis
       phishing-header-specialist     → phishing-synthesis
       phishing-attachment-specialist → phishing-synthesis
       (sin señales)                  → phishing-synthesis

phishing-synthesis → veredicto JSON
```

## Módulos principales

| Módulo | Descripción |
|---|---|
| `cai_orchestrator.app` | CLI (argparse), entrypoint |
| `cai_orchestrator.client` | Cliente HTTP sobre `platform-api` |
| `cai_orchestrator.flows` | Flows de investigación (WatchGuard, phishing) |
| `cai_orchestrator.cai_terminal` | Agente `egs-analist` y herramientas CAI |
| `cai_orchestrator.phishing_agents` | Pipeline multi-agente de phishing |
| `cai_orchestrator.cai_tools` | `PlatformApiToolService` — wrapper del cliente para herramientas CAI |
| `cai_orchestrator.email_bridge` | Parser EML → payload de plataforma (stdlib, sin imports cross-layer) |
| `cai_orchestrator.config` | Configuración desde env vars |

## Notas

- Los flujos S3 (`stage_workspace_zip`, `duckdb_workspace_analytics`, `duckdb_workspace_query`) no tienen subcomandos CLI propios — se usan exclusivamente desde la terminal CAI.
- El pipeline DDoS sí tiene un subcomando dedicado (`run-ddos-investigate`) y utilidades de reporte offline (`report-collect`, `report-generate`).
- CAI no está vendorizado en este repo; se importa como dependencia opcional.
- No requiere Docker. No está en `compose.yml`.
