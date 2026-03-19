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
| `PLATFORM_API_BASE_URL` | `http://127.0.0.1:8000` | URL del platform-api |
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
  --client-id "cliente-abc" \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"

# One-shot con prompt
python3 -m cai_orchestrator run-cai-terminal \
  --client-id "cliente-abc" \
  --model "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0" \
  --prompt "Analiza el workspace 8011029C760FA. Estágealo, corre analytics y muéstrame los top IPs denegados."
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
| `phishing_investigator_agent` | Entra directamente al pipeline multi-agente de phishing |

### Herramientas disponibles en `egs-analist`

**Core**: `health`, `create_case`, `attach_input_artifact`, `attach_workspace_s3_zip_reference`, `create_run`

**Pipeline S3**: `find_latest_workspace_upload`, `execute_watchguard_stage_workspace_zip`, `execute_watchguard_duckdb_workspace_analytics`, `execute_watchguard_duckdb_workspace_query`

**WatchGuard clásico**: `execute_watchguard_workspace_zip_ingestion`, `execute_watchguard_normalize`, `execute_watchguard_filter_denied`, `execute_watchguard_analytics_basic`, `execute_watchguard_top_talkers_basic`, `execute_watchguard_guarded_custom_query`

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
- CAI no está vendorizado en este repo; se importa como dependencia opcional.
- No requiere Docker. No está en `compose.yml`.
