# platform-core

Lógica de coordinación neutral al vendor. Define los puertos (interfaces) que separan la lógica de dominio de la persistencia y los backends.

## Responsabilidad

- **Puertos**: protocolos (`CaseRepository`, `ArtifactRepository`, `RunRepository`) que `platform-api` implementa con repos in-memory o PostgreSQL.
- **Servicios**: `create_case()`, `attach_artifact()`, `create_run()`, `publish_observation_result()`, `gate_query_by_approval()`.
- **Errores canónicos**: `NotFoundError`, `InvalidStateError`, `ApprovalRequiredError`.

**No debe contener**: parsing de vendors, clientes HTTP, código CAI, motores de persistencia, handlers de transporte, ni lógica de backend.

## Módulos

| Módulo | Contenido clave |
|---|---|
| `platform_core.ports` | `CaseRepository`, `ArtifactRepository`, `RunRepository` (protocolos) |
| `platform_core.cases` | `create_case(client_id, title, workflow_type, ...)` |
| `platform_core.runs` | `create_run(case_id, backend_id, artifact_ids, ...)` |
| `platform_core.artifacts` | `attach_input_artifact(case_id, payload, ...)` |
| `platform_core.observations` | Publicación de resultados de observación |
| `platform_core.queries` | Validación y despacho de queries guarded |
| `platform_core.approvals` | `gate_query_by_approval()` |
| `platform_core.audit` | `append_timeline_event()`, `append_decision_record()` |
| `platform_core.errors` | `NotFoundError`, `InvalidStateError`, `ApprovalRequiredError` |

## Patrón de puertos

Los repositorios son protocolos (duck typing), no clases base:

```python
# platform_core/ports/repositories.py
class CaseRepository(Protocol):
    def get_case(self, case_id: str) -> Case | None: ...
    def save_case(self, case: Case) -> Case: ...
    def list_cases_by_client(self, client_id: str) -> list[Case]: ...
```

Las implementaciones (`InMemoryCaseRepository`, `PostgresCaseRepository`) están en `platform-api` — no en este paquete.

## Regla de dependencias

Solo puede depender de `platform-contracts`. No puede importar de `platform-adapters`, `platform-backends`, ni de las apps.
