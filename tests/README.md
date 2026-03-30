# Tests

Suite de tests de cai-platform. Organizada por capa de arquitectura.

## Estructura

```
tests/
├── contracts/    # Invariantes de contratos Pydantic y modelos compartidos
├── core/         # Comportamiento de servicios de platform-core
├── adapters/     # Tests de normalización y traducción de adapters
├── backends/     # Conformancia y lógica de backends
└── apps/         # Tests de integración del API HTTP (FastAPI + httpx)
```

## Correr los tests

```bash
. .venv/bin/activate
make install-dev   # instalar todos los paquetes (si no está hecho)

make test          # todos los tests
pytest tests/apps/ -v              # solo tests del API
pytest tests/ -k "watchguard" -v   # filtrar por nombre
pytest tests/backends/test_watchguard_logs_backend.py::test_normalize -v  # un test específico
```

## Entorno de tests

- Los tests usan el runtime in-memory (`DATABASE_URL` no definida). No requieren Docker, PostgreSQL, ni AWS.
- El cliente de test usa `httpx.AsyncClient` con `ASGITransport` para el API FastAPI.
- Los backends se testean de forma aislada con payloads JSON directos.

## Convenciones

- Los tests siguen los límites de paquete — no mezclan lógica de capas distintas.
- Los fixtures de `client_id` usan `"test-client"` por convención.
- Las observaciones de test usan `requested_by="test-user"`.
- Los payloads de ejemplo están en `examples/` (raíz del repo).
