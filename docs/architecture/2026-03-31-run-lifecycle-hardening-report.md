# Informe Técnico — Hardening CAI, Lifecycle Explícito de Run y Cobertura

Fecha de redacción: 2026-03-31 14:58:31Z

Estado del trabajo:
- Implementación local: completada
- Suite local: verde (`234 passed`)
- Despliegue cloud: no realizado desde esta sesión
- Verificación cloud: realizada contra ALB de producción y paths de staging

---

## 1. Propósito de este documento

Este documento describe en detalle el trabajo realizado sobre la rama actual para:

- estabilizar la integración de `cai_terminal`;
- formalizar el lifecycle de `Run` con finalización explícita;
- añadir cobertura de tests para los cambios recientes de CAI, `multi_source_logs` y automatización SOC;
- documentar el estado deliberadamente incompleto de `multi_source_logs` en producción;
- registrar el resultado de la validación local y la validación contra la nube.

La intención es que cualquier persona técnica pueda:

- entender exactamente qué se cambió;
- entender por qué se cambió;
- identificar qué queda pendiente antes de llevar esto a producción;
- revertir el cambio si hiciera falta;
- reanudar el trabajo sin depender del contexto oral de esta sesión.

---

## 2. Contexto previo de la rama

Este trabajo no arrancó desde un árbol limpio. La rama ya venía con tres líneas previas de desarrollo:

### 2.1. Phase 1 — CAI hardening

Ya existían cambios previos en:

- `apps/cai-orchestrator/src/cai_orchestrator/phishing_agents.py`
- `apps/cai-orchestrator/src/cai_orchestrator/ddos_agents.py`
- `apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py`

Esos cambios previos introducían:

- `output_type` en agentes;
- `RunConfig` en `Runner.run(...)`;
- manejo de `InputGuardrailTripwireTriggered`;
- endurecimiento general de la integración con CAI.

### 2.2. Phase 2 — Backend `multi_source_logs`

Ya existían en la rama:

- los archivos del backend `packages/platform-backends/src/platform_backends/multi_source_logs/`;
- el wiring dev/in-memory en `apps/platform-api/src/platform_api/runtime/memory.py`;
- las rutas HTTP del backend en `apps/platform-api/src/platform_api/routes/runs.py`;
- métodos cliente en `apps/cai-orchestrator/src/cai_orchestrator/client.py`;
- wrappers en `apps/cai-orchestrator/src/cai_orchestrator/cai_tools.py`.

### 2.3. Phase 3 — SOC automation

Ya existían:

- `apps/cai-orchestrator/src/cai_orchestrator/log_monitor.py`;
- `apps/cai-orchestrator/src/cai_orchestrator/blueteam_agents.py`;
- comandos CLI asociados en `apps/cai-orchestrator/src/cai_orchestrator/app.py`.

### 2.4. Qué hizo realmente esta sesión

Esta sesión no creó desde cero esas tres fases. Lo que hizo fue:

- estabilizar la integración CAI para que el branch pueda testearse de forma confiable;
- cerrar la semántica de `Run` mediante un endpoint explícito de completion;
- alinear tests con el estado real del branch;
- añadir cobertura donde todavía no había;
- comprobar qué pasa realmente contra la nube;
- documentar deuda y riesgos de despliegue.

Importante: este trabajo se aplicó **encima** de un worktree ya modificado. No se revirtieron cambios ajenos ni se intentó “limpiar” la rama.

---

## 3. Problemas que se buscó resolver

### 3.1. Fragilidad de `cai_terminal` por dependencia rígida de `think`

El terminal CAI dependía de un import duro de:

```python
from cai.tools.misc.reasoning import think
```

Eso hacía frágil la construcción del agente cuando esa superficie no estaba disponible en determinadas versiones/distribuciones del SDK CAI o en el fake SDK de tests.

### 3.2. Ambigüedad del lifecycle de `Run`

La lógica de publicación de observaciones dejaba a los runs exitosos en `running`. Eso por sí solo no era incorrecto, pero faltaba un cierre semántico explícito:

- el run debía poder reutilizarse mientras siguiera activo;
- cuando un flujo “one-shot” terminaba, debía existir una transición explícita a `completed`.

Antes de este trabajo, ese cierre no existía.

### 3.3. Cobertura de tests incompleta

La rama tenía poca o nula cobertura específica para:

- `multi_source_logs`;
- el nuevo lifecycle de `Run`;
- automatización SOC (`blueteam_agents`, `log_monitor`);
- el estado real de la superficie CAI endurecida.

### 3.4. Falta de documentación explícita sobre `multi_source_logs` en prod

El backend `multi_source_logs` estaba cableado para dev/in-memory, pero no para runtime PostgreSQL/prod. Era importante dejar eso documentado para no generar falsas expectativas.

---

## 4. Decisiones de diseño tomadas

### 4.1. `Run` se reutiliza mientras está activo

Se decidió mantener la semántica:

- `created` y `running` son estados activos/reutilizables;
- publicar observaciones o query artifacts **no** completa automáticamente el run;
- `completed` es un cierre explícito, no derivado de cualquier observación exitosa.

Esto preserva la reutilización del run para flujos interactivos o multietapa.

### 4.2. Completion explícita por endpoint

Se introdujo:

- `POST /runs/{run_id}/complete`

con payload:

```json
{
  "requested_by": "<string>",
  "reason": "<string|null>"
}
```

Semántica:

- permitido desde `created` o `running`;
- idempotente si el run ya está `completed`;
- rechaza estados terminales no completados (`cancelled`, `failed`, etc.);
- agrega evento `run_completed` a la timeline del caso;
- no cierra el `Case`.

### 4.3. No tocar prod wiring de `multi_source_logs`

Se decidió **no** registrar `multi_source_logs` en PostgreSQL/prod todavía.

Razón:

- el backend todavía no se considera prod-ready;
- la prioridad era estabilizar y documentar, no exponerlo prematuramente en producción.

### 4.4. No introducir migraciones ni cambios de schema

Este trabajo no cambia la estructura persistente de PostgreSQL. El rollout es puramente de código.

Esto simplifica mucho el rollback.

---

## 5. Implementación realizada

## 5.1. Estabilización de `cai_terminal`

### Cambio

En `apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py` se reemplazó la dependencia rígida de `think` por una resolución opcional:

- si `cai.tools.misc.reasoning.think` existe, se usa;
- si no existe, se expone un fallback no-op decorado como `@function_tool`.

### Motivación

Esto evita que la construcción del agente falle por una superficie opcional del SDK CAI.

### Resultado

- el agente mantiene la herramienta `think` en su surface;
- no se eliminó `think`;
- se mejoró la compatibilidad de tests y de entornos donde ese módulo no está disponible.

---

## 5.2. Endpoint y servicio de completion explícita de `Run`

### Cambio de core

Se agregó `complete_run(...)` en:

- `packages/platform-core/src/platform_core/runs/services.py`

y se exportó desde:

- `packages/platform-core/src/platform_core/runs/__init__.py`
- `packages/platform-core/src/platform_core/__init__.py`

### Comportamiento implementado

`complete_run(...)`:

- carga el run;
- valida que exista y esté ligado a un caso;
- valida que el caso exista;
- si ya está `completed`, devuelve sin error;
- si el estado no es `created` o `running`, lanza `InvalidStateError`;
- guarda el run como `completed`;
- borra `error_summary`;
- agrega un evento `run_completed` a la timeline del caso;
- registra el evento en `audit_port`.

### Cambio de API

Se agregó:

- `CompleteRunRequest` en `apps/platform-api/src/platform_api/schemas.py`
- `POST /runs/{run_id}/complete` en `apps/platform-api/src/platform_api/routes/runs.py`

### Motivación

La plataforma necesitaba un cierre semántico de runs que fuera:

- explícito;
- auditable;
- compatible con reutilización de runs activos.

---

## 5.3. Extensión del cliente/orquestador para completion

Se agregó soporte de `complete_run(...)` en:

- `apps/cai-orchestrator/src/cai_orchestrator/client.py`
- `apps/cai-orchestrator/src/cai_orchestrator/cai_tools.py`
- `apps/cai-orchestrator/src/cai_orchestrator/app.py`

Esto permite que:

- el CLI clásico;
- herramientas CAI;
- pipelines híbridos

puedan cerrar runs de forma uniforme a través del mismo endpoint.

---

## 5.4. Auto-completion de flujos one-shot

### Se auto-completan ahora

Desde `apps/cai-orchestrator/src/cai_orchestrator/app.py`:

- `run-watchguard`
- `run-watchguard-filter-denied`
- `run-watchguard-analytics-basic`
- `run-watchguard-top-talkers-basic`
- `run-watchguard-guarded-query`
- `run-phishing-email-basic-assessment`

La secuencia ahora es:

1. ejecutar el flujo normal;
2. tomar `result.run["run_id"]`;
3. llamar a `complete_run(...)`;
4. sobrescribir el `run` de salida con la versión completada;
5. devolver `case` actualizado si viene en la respuesta.

### Motivación

Estos comandos representan ejecuciones cerradas de una sola corrida, por lo que semánticamente sí deben terminar en `completed`.

---

## 5.5. Completion en `run-phishing-monitor`

En `apps/cai-orchestrator/src/cai_orchestrator/app.py`:

- cuando `run-phishing-monitor` procesa un email y **no** lanza investigación CAI posterior, el run se completa explícitamente;
- cuando `--cai-investigate` está activo, **no** se completa antes, para no bloquear pasos adicionales sobre el mismo run.

### Motivación

Esto respeta la idea de:

- runs cerrados para flujos cerrados;
- runs activos para flujos encadenados.

---

## 5.6. Completion en pipelines híbridos

Se agregó completion al final de:

- `apps/cai-orchestrator/src/cai_orchestrator/ddos_agents.py`
- `apps/cai-orchestrator/src/cai_orchestrator/blueteam_agents.py`

La completion se ejecuta después de la fase final de síntesis.

### Motivación

Estos pipelines tienen un punto claro de terminación conceptual:

- setup;
- colección determinista;
- síntesis final.

Si las tres etapas terminan bien, el run ya no debería quedar “flotando” en `running`.

---

## 5.7. Documentación de deuda técnica

Se agregó el ítem 11 a:

- `docs/architecture/pendientes.md`

para dejar explícito que:

- `multi_source_logs` sigue siendo dev-only;
- el runtime PostgreSQL/prod no lo registra;
- al madurar habrá que alinear `_build_postgres_runtime()`.

### Motivación

Evitar asumir incorrectamente que este backend ya forma parte de la superficie de producción.

---

## 5.8. Alineación de tests con el branch real

Los tests de `cai_terminal` ya no coincidían con la superficie actual del agente ni con el hardening previo de CAI.

Se actualizaron para reflejar:

- presencia de `think`;
- presencia de herramientas DDoS;
- presencia de herramientas de manejo de CaseState/NIST;
- `RunConfig` en las llamadas a `Runner.run(...)`;
- manejo de `InputGuardrailTripwireTriggered`.

Esto se hizo principalmente en:

- `tests/apps/test_cai_terminal_integration.py`

### Motivación

No se quiso “ablandar” la implementación para que pasaran tests viejos. En su lugar, se alinearon los tests con el diseño ya adoptado en la rama.

---

## 6. Inventario de archivos tocados

Esta sección enumera los archivos tocados por este trabajo y el propósito de cada cambio.

## 6.1. Archivos de producción / runtime

### `apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py`

Cambio:
- fallback opcional para `think`.

Razón:
- evitar que la construcción del agente dependa rígidamente de un módulo opcional.

Rollback:
- volver al import duro de `think`.

Riesgo:
- bajo; el fallback solo actúa cuando el import falla.

### `apps/cai-orchestrator/src/cai_orchestrator/client.py`

Cambio:
- nuevo método `complete_run(...)`.

Razón:
- exponer el nuevo endpoint HTTP al cliente thin.

Rollback:
- eliminar el método.

Riesgo:
- bajo; es una extensión aditiva.

### `apps/cai-orchestrator/src/cai_orchestrator/cai_tools.py`

Cambio:
- wrapper `complete_run(...)` para herramientas CAI.

Razón:
- permitir que herramientas/orquestadores usen el cierre explícito.

Rollback:
- eliminar el wrapper.

Riesgo:
- bajo.

### `apps/cai-orchestrator/src/cai_orchestrator/app.py`

Cambios:
- método `CaiOrchestratorApp.complete_run(...)`;
- auto-completion de comandos one-shot;
- completion condicional en `run-phishing-monitor`.

Razón:
- cerrar correctamente runs de flujos que conceptualmente terminan.

Rollback:
- quitar llamadas a `complete_run(...)` y volver a imprimir `result.to_dict()` directo.

Riesgo:
- medio, porque introduce dependencia explícita del orquestador hacia el nuevo endpoint del API.

Observación importante:
- este archivo es uno de los que hacen visible el problema de despliegue secuencial: si el consumidor se despliega antes que el API, los flujos fallan con 404 en `/complete`.

### `apps/cai-orchestrator/src/cai_orchestrator/ddos_agents.py`

Cambio:
- completion del run después de síntesis final.

Razón:
- el pipeline híbrido tiene fin semántico claro.

Rollback:
- eliminar la llamada a `client.complete_run(...)`.

Riesgo:
- medio, porque depende del nuevo endpoint.

### `apps/cai-orchestrator/src/cai_orchestrator/blueteam_agents.py`

Cambio:
- completion del run al final del pipeline híbrido.

Razón:
- misma semántica que DDoS.

Rollback:
- eliminar la llamada a `client.complete_run(...)`.

Riesgo:
- medio.

### `apps/platform-api/src/platform_api/schemas.py`

Cambio:
- nuevo modelo `CompleteRunRequest`.

Razón:
- tipar y validar el request del endpoint nuevo.

Rollback:
- eliminar el modelo.

Riesgo:
- bajo.

### `apps/platform-api/src/platform_api/routes/runs.py`

Cambio:
- nuevo endpoint `POST /runs/{run_id}/complete`.

Razón:
- exponer completion explícita por HTTP.

Rollback:
- eliminar la ruta y su import asociado.

Riesgo:
- bajo a medio; es aditivo, pero crea una nueva dependencia de los consumidores.

### `packages/platform-core/src/platform_core/runs/services.py`

Cambio:
- nuevo servicio `complete_run(...)`.

Razón:
- centralizar la transición explícita de lifecycle en core.

Rollback:
- eliminar la función y sus exports.

Riesgo:
- bajo.

### `packages/platform-core/src/platform_core/runs/__init__.py`
### `packages/platform-core/src/platform_core/__init__.py`

Cambio:
- exportar `complete_run`.

Razón:
- mantener consistente la API pública de `platform-core`.

Rollback:
- quitar el export.

Riesgo:
- bajo.

### `docs/architecture/pendientes.md`

Cambio:
- nuevo ítem que declara `multi_source_logs` como dev-only.

Razón:
- documentar estado actual real.

Rollback:
- eliminar el ítem 11 si cambia la decisión.

Riesgo:
- nulo.

## 6.2. Archivos de tests modificados

### `tests/apps/test_cai_terminal_integration.py`

Cambio:
- alineación del fake SDK y de la surface del agente;
- nuevo test de guardrail;
- tests para `complete_run` y `multi_source_logs` wrappers.

Razón:
- reflejar la realidad del branch.

### `tests/apps/test_cai_orchestrator.py`

Cambio:
- tests del cliente para `complete_run`;
- tests del cliente para endpoints `multi_source_logs`;
- test de completion explícita a través del app layer.

Razón:
- cubrir boundary de orquestación.

### `tests/apps/test_runtime_baseline.py`

Cambio:
- adaptar fakes de CLI para esperar `run.status == "completed"` en flujos one-shot.

Razón:
- el CLI ahora completa runs de flujos cerrados.

### `tests/apps/test_phishing_email_orchestrator.py`

Cambio:
- adaptar fake app del CLI de phishing para soportar `complete_run`.

Razón:
- alineación con lifecycle nuevo.

### `tests/apps/test_platform_api.py`

Cambio:
- tests de:
  - create-run con `multi_source_logs`;
  - `POST /runs/{id}/complete`;
  - estados inválidos de completion;
  - rutas `multi-source-logs-*`.

Razón:
- cubrir API pública nueva y superficie del backend.

### `tests/core/test_observation_publication.py`

Cambio:
- tests de completion explícita;
- validación de idempotencia;
- rechazo en estados terminales inválidos.

Razón:
- fijar la semántica del lifecycle en core.

## 6.3. Archivos de tests nuevos

### `tests/apps/test_soc_automation.py` (nuevo)

Cubre:

- pipeline híbrido blue team sin Slack;
- path opcional de Slack con mock de `requests.post`;
- CLI `run-blueteam-investigate`;
- CLI `run-log-monitor`.

### `tests/backends/test_multi_source_logs_backend.py` (nuevo)

Cubre:

- normalización por source type;
- detecciones principales:
  - failed auth;
  - lateral movement;
  - privilege escalation;
  - dns anomaly;
  - cross-source correlation;
- `execute_predefined_observation(...)` por operación.

---

## 7. Qué NO se cambió intencionalmente

Estas omisiones son deliberadas y deben leerse como parte del diseño actual:

### 7.1. No se cambió el wiring PostgreSQL/prod para `multi_source_logs`

No se tocó:

- `apps/platform-api/src/platform_api/runtime/wiring.py`

Razón:
- `multi_source_logs` sigue marcado como no prod-ready.

### 7.2. No se cambió la semántica base de publicación de observaciones

`publish_observation_result(...)` sigue dejando al run en `running` después de una observación exitosa.

Razón:
- esa es justamente la semántica deseada para permitir reutilización del run mientras siga activo.

### 7.3. No se hicieron migraciones de base de datos

No hay migraciones ni cambios de schema.

Razón:
- no eran necesarias para este cambio.

### 7.4. No se modificó `platform-ui`

No se tocaron archivos de:

- `apps/platform-ui/`

Razón:
- el foco estuvo en API/core/orchestrator/tests.

Consecuencia:
- la UI deberá validarse funcionalmente cuando se despliegue con el nuevo orquestador y contra el API ya actualizado.

### 7.5. No se implementó fallback de compatibilidad cuando `/complete` no existe

Actualmente, si un consumidor nuevo corre contra un API viejo, falla con 404.

Esto fue descubierto durante la validación cloud.

Razón:
- no se implementó una tolerancia temporal del tipo “si `/complete` da 404, continuar sin completion”.

Esto queda como punto de mejora opcional antes del rollout si se quiere minimizar riesgo de incompatibilidad temporal.

---

## 8. Validación local realizada

## 8.1. Estado final de tests

Se corrió:

```bash
python3 -m pytest tests -q
```

Resultado final:

```text
234 passed in 8.66s
```

## 8.2. Subconjuntos relevantes ejecutados durante el trabajo

Se validaron, entre otros:

- `tests/apps/test_cai_terminal_integration.py`
- `tests/core/test_observation_publication.py`
- `tests/apps/test_platform_api.py`
- `tests/apps/test_cai_orchestrator.py`
- `tests/apps/test_runtime_baseline.py`
- `tests/apps/test_phishing_email_orchestrator.py`
- `tests/apps/test_soc_automation.py`
- `tests/backends/test_multi_source_logs_backend.py`

## 8.3. Conclusión de la validación local

La implementación local está consistente:

- el lifecycle explícito funciona;
- los consumidores están alineados con el endpoint nuevo;
- la cobertura quedó significativamente más fuerte;
- no hay fallos conocidos en la suite local.

---

## 9. Verificación realizada contra la nube

La validación cloud se hizo usando:

- `.env` local del usuario;
- `PLATFORM_API_BASE_URL=http://cai-platform-alb-472989822.us-east-2.elb.amazonaws.com`

## 9.1. Producción

### Health

Comando:

```bash
curl http://cai-platform-alb-472989822.us-east-2.elb.amazonaws.com/health
```

Respuesta:

```json
{"status":"ok","backend_ids":["phishing_email","watchguard_logs"]}
```

Observación:

- el API de prod está vivo;
- `multi_source_logs` no aparece, lo cual es consistente con la decisión de no habilitarlo en PostgreSQL/prod.

### Smoke test 1 — WatchGuard

Se ejecutó:

```bash
.venv/bin/python -m cai_orchestrator run-watchguard \
  --client-id "codex-smoke" \
  --title "Smoke prod 2026-03-31 watchguard" \
  --summary "Smoke test ejecutado por Codex contra ALB para validar run completion." \
  --payload-file examples/watchguard/minimal_payload.json
```

Resultado:

- el flujo creó caso, artefacto, run y observación;
- falló al intentar `POST /runs/{id}/complete`;
- error recibido: `404`.

Run creado:

- `run_adacb9808d26420ba8d3f3078076fd00`

Caso creado:

- `case_9814ce1f99bc44b5958ed0cb4ef12e39`

Estado consultado luego:

- `status = running`
- observación `succeeded`

### Smoke test 2 — Phishing

Se ejecutó:

```bash
.venv/bin/python -m cai_orchestrator run-phishing-email-basic-assessment \
  --client-id "codex-smoke" \
  --title "Smoke prod 2026-03-31 phishing" \
  --summary "Smoke test ejecutado por Codex contra ALB para validar run completion." \
  --payload-file examples/phishing/minimal_payload.json
```

Resultado:

- el flujo creó caso, artefacto, run y observación;
- falló al intentar `POST /runs/{id}/complete`;
- error recibido: `404`.

Run creado:

- `run_ee924b6537074b408e875821f053d37c`

Caso creado:

- `case_53da49b5cca9400386850b4392b6a1b3`

Estado consultado luego:

- `status = running`
- observación `succeeded`

### Conclusión sobre producción

La conclusión técnica es inequívoca:

- producción **todavía no tiene desplegado** el endpoint nuevo `POST /runs/{run_id}/complete`;
- el código nuevo del orquestador ya depende de ese endpoint;
- por lo tanto, **no se puede desplegar el consumidor nuevo sin desplegar primero el API**.

En otras palabras:

- el código local está bien;
- el entorno cloud todavía está en una versión de API anterior a este cambio.

## 9.2. Staging

Se probó:

```bash
curl http://cai-platform-alb-472989822.us-east-2.elb.amazonaws.com/staging/health
curl http://cai-platform-alb-472989822.us-east-2.elb.amazonaws.com/staging-ui/_stcore/health
```

Ambos devolvieron `503`.

Interpretación más probable:

- staging está apagado / sin targets saludables;
- esto es consistente con la documentación, que indica que staging puede quedar en reposo con desired count = 0.

## 9.3. Limitación operacional encontrada

Se intentó consultar ECS directamente con AWS CLI, pero la shell actual no tenía credenciales AWS cargadas:

```text
Unable to locate credentials. You can configure credentials by running "aws configure".
```

Por lo tanto, el estado de ECS no fue verificado por CLI en esta sesión, solo por comportamiento observable del ALB.

---

## 10. Hallazgo más importante de despliegue

El riesgo principal descubierto no es de lógica de negocio sino de rollout:

### Problema

Los consumidores (`cai-orchestrator`, y por extensión cualquier UI que lo embeba) ahora llaman a:

```text
POST /runs/{run_id}/complete
```

Si el API desplegado no tiene todavía esa ruta, los flujos one-shot fallan al final aunque la observación principal haya salido bien.

### Impacto práctico

Esto ya ocurrió en producción durante el smoke test.

### Implicación de despliegue

El orden correcto de rollout debe ser:

1. desplegar `platform-api`;
2. verificar que `/runs/{id}/complete` exista;
3. recién después desplegar `platform-ui` o cualquier consumidor que use el orquestador nuevo.

### Mejora opcional no implementada

Si se quiere reducir el riesgo de despliegues desincronizados, se podría introducir un fallback temporal:

- si `complete_run()` devuelve `404`, registrar warning y continuar devolviendo el resultado principal.

Ese fallback **no** se implementó en esta sesión.

---

## 11. Trabajo pendiente antes de producción

Esta sección enumera lo que todavía falta según la línea actual de implementación.

## 11.1. Desplegar `platform-api` antes que los consumidores

Pendiente:

- desplegar la versión nueva del API;
- validar que `POST /runs/{id}/complete` responda.

Sin esto, los consumidores nuevos fallan.

## 11.2. Levantar staging y hacer smoke test ahí primero

Pendiente:

- subir staging;
- validar `GET /staging/health`;
- correr un smoke test `run-watchguard` contra `/staging`;
- confirmar que el run termina en `completed`.

## 11.3. Validación funcional de `platform-ui`

Aunque la UI no fue modificada directamente, si corre con el orquestador embebido actualizado deberá validarse:

- WatchGuard one-shot;
- phishing one-shot;
- historial/lectura de runs;
- cualquier flujo que dependa del cierre explícito.

## 11.4. Definir si se quiere compatibilidad temporal con API viejo

Opción:

- agregar fallback no fatal para `404` en `/complete`.

Esto no es estrictamente necesario si el deploy se coordina bien, pero sí reduce fragilidad operacional.

## 11.5. `multi_source_logs` sigue fuera de prod

Pendiente deliberado:

- no tocar producción todavía;
- al madurar, registrar backend en runtime PostgreSQL y revalidar superficie completa.

## 11.6. Validación cloud de DDoS / blue team

No se hizo smoke test cloud de:

- `run-ddos-investigate`
- `run-blueteam-investigate`
- `run-log-monitor`

Razones:

- DDoS y blue team dependen de etapas adicionales, CAI y/o backends no expuestos aún en prod;
- staging no estaba arriba durante esta sesión;
- no era razonable tratar esos flujos como primer smoke antes de resolver el endpoint de completion en API.

---

## 12. Plan de rollback

Este cambio es relativamente fácil de revertir porque:

- no hubo migraciones de DB;
- no hubo cambios de schema persistente;
- no hubo cambios de infraestructura;
- todo el impacto es de código y despliegue.

## 12.1. Rollback conceptual

Si hay que volver atrás, hay dos niveles:

### A. Rollback de código local / rama

Revertir los cambios en:

- `apps/platform-api/src/platform_api/routes/runs.py`
- `apps/platform-api/src/platform_api/schemas.py`
- `packages/platform-core/src/platform_core/runs/services.py`
- `packages/platform-core/src/platform_core/runs/__init__.py`
- `packages/platform-core/src/platform_core/__init__.py`
- `apps/cai-orchestrator/src/cai_orchestrator/client.py`
- `apps/cai-orchestrator/src/cai_orchestrator/cai_tools.py`
- `apps/cai-orchestrator/src/cai_orchestrator/app.py`
- `apps/cai-orchestrator/src/cai_orchestrator/ddos_agents.py`
- `apps/cai-orchestrator/src/cai_orchestrator/blueteam_agents.py`
- `apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py`
- tests y docs asociados.

### B. Rollback de despliegue

Si el API nuevo ya estuviera desplegado y hubiera problemas:

- volver a desplegar la imagen previa de `platform-api`;
- pero si al mismo tiempo ya se desplegaron consumidores nuevos, hay que revertirlos también o quedarán rotos por ausencia de `/complete`.

Esto lleva a una regla práctica:

> El rollback debe ser coherente entre API y consumidores.

## 12.2. Rollback mínimo por riesgo

Si el único problema observado fuera la dependencia fuerte de `/complete`, el rollback mínimo es:

1. quitar las llamadas a `complete_run(...)` de consumidores;
2. dejar el endpoint en API o no, indistinto;
3. mantener el resto de la estabilización/test coverage.

Esto devolvería el comportamiento a:

- runs permanecen en `running`;
- flujos one-shot dejan de cerrar explícitamente.

## 12.3. Rollback de `think` fallback

Si el fallback de `think` diera algún problema inesperado, puede revertirse de forma aislada:

- restaurar el import duro original;
- dejar intacto el resto del trabajo.

No hay acoplamiento fuerte entre ese cambio y el lifecycle de run.

---

## 13. Casos/corridas creados durante la verificación cloud

Durante la prueba real contra producción se crearon artefactos de smoke test con:

- `client_id = codex-smoke`

Identificadores relevantes:

### WatchGuard

- `case_9814ce1f99bc44b5958ed0cb4ef12e39`
- `run_adacb9808d26420ba8d3f3078076fd00`

### Phishing

- `case_53da49b5cca9400386850b4392b6a1b3`
- `run_ee924b6537074b408e875821f053d37c`

Esto sirve para:

- auditoría;
- inspección manual desde la UI;
- correlación con logs del ALB / API.

Nota:

- la plataforma no ofrece en esta rama una API de delete para limpieza, por lo que esos casos quedarán visibles salvo limpieza manual.

---

## 14. Recomendación operativa concreta antes de prod

La secuencia recomendada es:

1. levantar staging;
2. desplegar `platform-api` en staging;
3. verificar:

```bash
curl http://<alb>/staging/health
curl -X POST http://<alb>/staging/runs/<run_id>/complete ...
```

4. correr smoke test `run-watchguard` contra staging;
5. confirmar `run.status == completed`;
6. desplegar consumidores que usen el orquestador nuevo;
7. repetir smoke test en prod;
8. recién después validar UI y pipelines adicionales.

---

## 15. Resumen ejecutivo

Lo más importante de todo este trabajo es:

- se formalizó correctamente el lifecycle de `Run`;
- la reutilización del run se preservó mientras esté activo;
- los flujos cerrados ahora pueden terminar en `completed`;
- la cobertura local quedó fuerte y toda la suite está verde;
- `multi_source_logs` quedó explícitamente documentado como dev-only;
- se descubrió un riesgo real de despliegue: consumidores nuevos fallan contra un API viejo porque `/runs/{id}/complete` todavía no existe en producción.

En otras palabras:

- el cambio local está listo técnicamente;
- no está listo operacionalmente para prod hasta que se haga un rollout coordinado, preferentemente vía staging primero.

---

## 16. Anexo — Lista resumida de archivos modificados por este trabajo

Producción / runtime:

- `apps/cai-orchestrator/src/cai_orchestrator/cai_terminal.py`
- `apps/cai-orchestrator/src/cai_orchestrator/client.py`
- `apps/cai-orchestrator/src/cai_orchestrator/cai_tools.py`
- `apps/cai-orchestrator/src/cai_orchestrator/app.py`
- `apps/cai-orchestrator/src/cai_orchestrator/ddos_agents.py`
- `apps/cai-orchestrator/src/cai_orchestrator/blueteam_agents.py`
- `apps/platform-api/src/platform_api/routes/runs.py`
- `apps/platform-api/src/platform_api/schemas.py`
- `packages/platform-core/src/platform_core/runs/services.py`
- `packages/platform-core/src/platform_core/runs/__init__.py`
- `packages/platform-core/src/platform_core/__init__.py`
- `docs/architecture/pendientes.md`

Tests modificados:

- `tests/apps/test_cai_terminal_integration.py`
- `tests/apps/test_cai_orchestrator.py`
- `tests/apps/test_runtime_baseline.py`
- `tests/apps/test_phishing_email_orchestrator.py`
- `tests/apps/test_platform_api.py`
- `tests/core/test_observation_publication.py`

Tests nuevos:

- `tests/apps/test_soc_automation.py`
- `tests/backends/test_multi_source_logs_backend.py`

Archivos existentes en el worktree pero no descritos como parte de este cambio:

- `.gitignore`
- `CLAUDE.md`

Esos no forman parte del alcance funcional de este informe.
