# platform-contracts

Vocabulario compartido de cai-platform. Define los tipos y contratos que usan todas las capas del sistema.

## Responsabilidad

- Modelos Pydantic para todos los conceptos del dominio: `Case`, `Run`, `Artifact`, `BackendDescriptor`, `ObservationRequest`, `ObservationResult`, `QueryDefinition`, `QueryRequest`, `ApprovalDecision`, etc.
- Es la capa más estable del repositorio. Todos los demás paquetes dependen de ella.

**No debe contener**: lógica de orquestación, implementaciones de backend, código CAI, ni handlers de transporte.

## Módulos

| Módulo | Contenido clave |
|---|---|
| `platform_contracts.common` | `generate_opaque_id()`, `utc_now()`, tipos base |
| `platform_contracts.cases` | `Case`, `WorkflowType` |
| `platform_contracts.artifacts` | `Artifact`, `ArtifactKind` |
| `platform_contracts.backends` | `BackendDescriptor`, `QueryDefinition`, `RiskClass`, `QueryMode` |
| `platform_contracts.runs` | `Run`, `RunStatus` |
| `platform_contracts.observations` | `ObservationRequest`, `ObservationResult` |
| `platform_contracts.investigations` | Tipos de investigación |
| `platform_contracts.queries` | `QueryRequest` |
| `platform_contracts.approvals` | `ApprovalDecision`, `ApprovalStatus`, `ApprovalScopeKind` |

## Modelo de datos principal

```
Case (client_id, workflow_type, artifact_refs)
  └── Run (backend_ref, status, input_artifact_refs, output_artifact_refs, observation_refs)
        ├── Artifact (kind=INPUT, payload)
        ├── Artifact (kind=OUTPUT, payload)
        └── ObservationResult (operation_kind, output_artifact_ref)
```

## Multi-tenant

El campo `client_id: str` en `Case` es el mecanismo de aislamiento multi-tenant. Es requerido (sin default). Todos los casos están asociados a un cliente de EGS y se listan/filtran por `client_id`.

## Regla de dependencias

```
platform-contracts ← platform-core ← platform-adapters ← platform-backends ← platform-api
                                                                              ← cai-orchestrator
```

Este paquete no puede importar de ningún otro paquete de la plataforma.
