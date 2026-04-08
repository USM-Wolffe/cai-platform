# Plan histórico: Pipeline multi-agente de investigación DDoS

> **Este documento es el plan de diseño original** escrito antes de la implementación. La arquitectura real difiere en varios aspectos — en particular la gestión del estado compartido usa `cai.egs_orchestration` (NIST case state local + snapshot en platform-api), no el artifact JSON `InvestigationState` descrito aquí. Para la implementación real ver `apps/cai-orchestrator/src/cai_orchestrator/ddos_agents.py`.

Objetivo final: a partir de un `workspace_id` (ZIP de logs WatchGuard ya subido a S3), el pipeline produce automáticamente un informe LaTeX siguiendo NIST SP 800-61, equivalente al informe manual [`docs/reference/LL-IR-PFALIMENTOS_23-10-25.pdf`](../reference/LL-IR-PFALIMENTOS_23-10-25.pdf).

---

## Contexto y decisiones de diseño

### Restricción de modelo
El modelo es Haiku (presupuesto fijo). La compensación es diseño determinista:
- Cada tool devuelve un JSON schema cerrado — no texto libre
- Cada agente tiene una sola responsabilidad atómica
- Ningún agente razona sobre datos crudos — siempre recibe agregaciones
- El estado compartido viaja como artifact estructurado, no como texto en handoffs
- Se usa `output_type` en agentes de recolección para forzar output JSON

### Problema del context loss en handoffs
El `final_output` de un agente llega al siguiente como string. Si el collector calculó tablas completas, ese contexto se aplana. Solución: **InvestigationState artifact** — un artifact JSON en platform-api que cada agente lee y escribe. El handoff solo pasa `investigation_state_artifact_id`.

### Estrategia NIST → datos
Las secciones del informe definen los datos necesarios (backward design):

| Sección informe | Datos requeridos |
|---|---|
| 3.2 Detección — tabla protocolos/puertos | `ddos_segment_analysis` por IP de alerta |
| 3.2 Detección — análisis por bloque | `ddos_segment_analysis` por /16 |
| 3.3 Contención | Acciones tomadas (campo manual del analista) |
| 3.4 Lecciones aprendidas | Template semiestructurado + datos del incidente |
| 3.5 Top 10 destinos | `ddos_top_destinations` |
| 3.5 Top 10 orígenes | `ddos_top_sources` |
| 3.5 Distribución temporal | `ddos_temporal_analysis` |
| 3.6 Conclusiones | Síntesis del synthesizer sobre el evidence completo |
| 3.7 Línea base Firebox | Template fijo EGS (parametrizado con países del incidente) |

---

## Fase 0 — Desbloqueadores (sin código)

- ZIP se sube a S3 manualmente (ver `docs/operations/s3-manual-upload.md`)
- Modelo queda en Haiku — se compensa con diseño determinista

---

## Fase 1 — Nuevas operaciones DuckDB para DDoS

Agregar al backend `watchguard_logs` en `execute.py` y `descriptor.py`:

### `watchguard_logs.ddos_temporal_analysis`
Input: staging manifest artifact
Output:
```json
{
  "by_day": [
    {"date": "2025-10-13", "events": 25291, "variation_pct": null, "observation": "Alto volumen inicial"},
    ...
  ],
  "peak_day": "2025-10-16",
  "peak_events": 27477,
  "total_events": 232398,
  "date_range": {"from": "2025-10-13", "to": "2025-10-22"},
  "pattern": "cyclic_business_hours"
}
```

### `watchguard_logs.ddos_top_destinations`
Input: staging manifest
Output:
```json
{
  "destinations": [
    {
      "rank": 1, "dst_ip": "190.82.90.36",
      "events": 144228, "pct": 62.06,
      "top_policy": "SNAT_BALANCEADOR_DE_CARGA_HTTPS",
      "top_action": "allow"
    }
  ],
  "total_events": 232398
}
```

### `watchguard_logs.ddos_top_sources`
Input: staging manifest
Output:
```json
{
  "sources": [
    {
      "rank": 1, "src_ip": "159.60.166.4",
      "segment_16": "159.60.0.0/16",
      "events": 49709, "pct": 21.39,
      "top_action": "allow"
    }
  ],
  "segments": [
    {"segment": "159.60.0.0/16", "events": 185794, "pct": 79.95, "ip_count": 7}
  ],
  "total_events": 232398
}
```

### `watchguard_logs.ddos_segment_analysis`
Input: staging manifest + `segment` param (ej. `"159.60.0.0/16"`)
Output:
```json
{
  "segment": "159.60.0.0/16",
  "total_events": 185794,
  "allow_events": 183000,
  "deny_events": 2794,
  "top_dst_ports": [{"port": 443, "protocol": "TCP", "events": 180000}, ...],
  "top_policies": [{"policy": "SNAT_BALANCEADOR_CARGA_HTTPS", "events": 120000}, ...],
  "top_dst_ips": [...],
  "date_range": {"from": "...", "to": "..."}
}
```

### `watchguard_logs.ddos_ip_profile`
Input: staging manifest + `ip` param
Output:
```json
{
  "ip": "223.123.92.149",
  "total_events": 1200,
  "allow_events": 300,
  "deny_events": 900,
  "first_seen": "2025-10-13T08:00:00Z",
  "last_seen": "2025-10-22T21:50:00Z",
  "top_dst_ports": [{"port": 80, "protocol": "TCP", "action": "deny", "events": 400}, ...],
  "top_policies": [...],
  "top_dst_ips": [...]
}
```

### `watchguard_logs.ddos_hourly_distribution`
Input: staging manifest + `date` param (ej. `"2025-10-16"`)
Output:
```json
{
  "date": "2025-10-16",
  "by_hour": [
    {"hour": 9, "events": 3200, "observation": "peak_morning"},
    ...
  ],
  "peak_hour": 9,
  "pattern": "business_hours"
}
```

---

## Fase 2 — InvestigationState artifact

Schema completo del estado compartido entre agentes:

```json
{
  "investigation_id": "ddos-{case_id}",
  "workspace_id": "string",
  "case_id": "string",
  "run_id": "string",
  "staging_artifact_id": "string",
  "phase": "init | data_collection | ip_profiling | synthesis | done",
  "client_name": "string",
  "incident_date_range": {"from": "string", "to": "string"},

  "evidence": {
    "temporal": null,
    "top_destinations": null,
    "top_sources": null,
    "protocol_breakdown": null,
    "ip_profiles": {},
    "segment_profiles": {},
    "peak_day_hourly": null,
    "anomalies": []
  },

  "nist_sections": {
    "preparation": "",
    "detection_analysis": "",
    "containment": "",
    "lessons_learned": "",
    "statistics_destinations_table": "",
    "statistics_sources_table": "",
    "statistics_temporal_table": "",
    "conclusions": "",
    "recommendations": [],
    "firebox_baseline_countries": []
  },

  "latex_output": ""
}
```

El artifact se crea al inicio con `phase=init` y se actualiza en cada paso. El `artifact_id` es lo único que viaja entre agentes en los handoffs.

---

## Fase 3 — Agentes

### `ddos-orchestrator`
- Instrucciones: crear caso, staging si no existe, crear InvestigationState artifact, handoff a data-collector
- Tools: create_case, create_run, execute_watchguard_stage_workspace_zip, create_investigation_state, get_investigation_state
- Modelo: Haiku
- Output: investigation_state_artifact_id

### `data-collector`
- Instrucciones: leer state, correr las 3 queries analíticas EN PARALELO (temporal + destinations + sources), escribir results en evidence, handoff a ip-profiler
- Tools: execute_ddos_temporal_analysis, execute_ddos_top_destinations, execute_ddos_top_sources, read_investigation_state, update_investigation_state
- Modelo: Haiku
- Clave: instrucciones explícitas de "llama a las tres tools en el mismo turno" para aprovechar parallel_tool_executor
- Output: investigation_state_artifact_id (enriquecido)

### `ip-profiler`
- Instrucciones: leer state, para CADA segmento /16 en top_sources ejecutar ddos_segment_analysis EN PARALELO, para las top 3 IPs individuales ejecutar ddos_ip_profile, escribir ip_profiles en state, handoff a synthesizer
- Tools: execute_ddos_segment_analysis, execute_ddos_ip_profile, read_investigation_state, update_investigation_state
- Modelo: Haiku
- Output: investigation_state_artifact_id (con ip_profiles completo)

### `report-synthesizer`
- Instrucciones: leer state completo, llenar CADA sección NIST usando SOLO los datos del evidence (nunca inventar números), generar LaTeX completo, escribir latex_output al state
- Tools: read_investigation_state, update_investigation_state, get_latex_template
- Modelo: Haiku
- Prompt key: "Si un campo del evidence es null, escribir 'Datos no disponibles' en esa sección. NUNCA inventar números."
- Output: state con latex_output poblado

---

## Fase 4 — LaTeX template

Completar el template existente (aesthetic) con:
- `\seccionNIST{preparation}{CONTENIDO}`
- `\tablaTopIPs{JSON_DATA}` — macro que genera tabla LaTeX desde JSON
- `\tablaTemporalDist{JSON_DATA}`
- `\tablaProtocolos{JSON_DATA}`
- `\seccionLineaBase{countries_list}`

El synthesizer recibe el template como string con marcadores `%%SECTION_NAME%%` y los reemplaza con el contenido generado.

---

## Fase 5 — Enrichment (futuro)

Sin API keys actualmente. Opciones:
- Brave Search MCP (tier gratuito) — busca la IP, extrae reputación del HTML de Cisco Talos
- Cuando EGS tenga API keys AbuseIPDB/VirusTotal: reemplazar con tool directo

---

## Archivos a crear/modificar

| Archivo | Acción |
|---|---|
| `packages/platform-backends/src/platform_backends/watchguard_logs/execute.py` | Agregar 6 nuevas funciones DDoS |
| `packages/platform-backends/src/platform_backends/watchguard_logs/descriptor.py` | Registrar nuevas operaciones |
| `apps/cai-orchestrator/src/cai_orchestrator/ddos_agents.py` | Crear — 4 agentes nuevos |
| `apps/cai-orchestrator/src/cai_orchestrator/cai_tools.py` | Agregar tools para nuevas operaciones |
| `apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py` | Registrar ddos pipeline |
| `apps/platform-api/src/platform_api/routes/runs.py` | Agregar endpoints para operaciones DDoS |
| `apps/platform-api/src/platform_api/runtime/wiring.py` | Registrar nuevas operaciones |
| `docs/operations/s3-manual-upload.md` | Crear — guía para analistas |
