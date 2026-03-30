# Arquitectura — cai-platform

Descripción de los límites de la plataforma, reglas de dependencias y topología del repositorio.

---

## Principio central

cai-platform es una plataforma de **investigación determinista**. Los backends producen resultados reproducibles dada la misma entrada. CAI (el agente de IA) es una capa de orquestación por encima de la plataforma, no dentro de ella.

---

## Capas y dependencias

```
platform-contracts
       ↑
platform-core
       ↑
platform-adapters
       ↑
platform-backends
       ↑
platform-api ←── cai-orchestrator
```

Las dependencias solo van hacia arriba (hacia `platform-contracts`). Ninguna capa puede importar de una capa superior.

| Capa | Qué hace | Qué NO puede hacer |
|---|---|---|
| `platform-contracts` | Define tipos del dominio | Importar de cualquier otra capa |
| `platform-core` | Servicios de coordinación, puertos | Importar de adapters, backends, apps |
| `platform-adapters` | Traducir formatos vendor | Importar de backends o apps |
| `platform-backends` | Lógica determinista por caso de uso | Importar de apps |
| `platform-api` | API HTTP, wiring de runtime | Importar de `cai-orchestrator` |
| `cai-orchestrator` | CLI + agentes CAI | Contener lógica de dominio |

---

## Modelo de objetos

```
Case
  client_id    ← aislamiento multi-tenant
  workflow_type
  artifact_refs → [Artifact, ...]
  run_refs → [Run, ...]

Run
  backend_ref → BackendDescriptor
  status: CREATED | RUNNING | COMPLETED | FAILED
  input_artifact_refs → [Artifact, ...]
  output_artifact_refs → [Artifact, ...]
  observation_refs → [ObservationResult, ...]

Artifact
  kind: INPUT | OUTPUT
  format
  payload (JSONB en PostgreSQL)
  content_hash

ObservationResult
  operation_kind
  output_artifact_ref → Artifact
```

---

## Aislamiento multi-tenant

- El campo `client_id` en `Case` es **requerido** y sin default.
- Toda operación de lista/filtrado de casos usa `client_id` como filtro.
- En PostgreSQL, hay un índice sobre `client_id` en la tabla `cases`.
- El `client_id` se propaga desde el CLI (`--client-id`) → `cai-orchestrator` → `POST /cases` → `Case`.

---

## Persistencia

El runtime selecciona automáticamente el backend de persistencia:

```
DATABASE_URL definida → PostgreSQL (producción/ECS)
DATABASE_URL no definida → In-memory (desarrollo/tests)
```

Los datos se almacenan como **JSONB** en PostgreSQL. Esto permite que los modelos Pydantic evolucionen sin migraciones de schema explícitas — el JSONB contiene el modelo serializado completo.

---

## Backends

Un backend es un caso de uso de ciberseguridad con:
- Un `BackendDescriptor` que declara sus operaciones y niveles de riesgo.
- Una función `execute_predefined_observation()` que produce resultados deterministas.
- Opcionalmente, una función de query guarded que requiere aprobación explícita.

**Queries guarded**: Las queries de `RiskClass.HIGH` o `RiskClass.CRITICAL`, y las queries de modo `CUSTOM_GUARDED`, requieren que el caller registre una `ApprovalDecision` antes de ejecutar. Esto implementa un control de acceso explícito por operación.

---

## CAI como capa de orquestación

CAI (aliasrobotics/cai) es una dependencia **externa y opcional**. Solo aparece en `cai-orchestrator`. El framework CAI provee `Agent`, `Runner`, y `@function_tool`. Los agentes usan las herramientas del orquestador para llamar al `platform-api` vía HTTP.

```
cai-orchestrator
  └── Agent (egs-analist)
        ├── @function_tool create_case → POST /cases
        ├── @function_tool execute_watchguard_normalize → POST /runs/{id}/observations/...
        └── handoff → phishing_investigator
              ├── phishing-triage
              ├── phishing-specialists
              └── phishing-synthesis
```

---

## Runtime en producción (AWS)

```
Internet → ALB → ECS Fargate → platform-api
                                    ↓
                              RDS PostgreSQL

cai-orchestrator (EC2 host-run) → HTTP → ALB → platform-api
```

- `platform-api` es el único servicio containerizado.
- `cai-orchestrator` corre en el host (EC2) como CLI.
- El API es stateless; todo el estado está en PostgreSQL.
- Las credenciales de BD vienen de AWS Secrets Manager.
