# Pendientes técnicos — cai-platform

Decisiones intencionales que quedan como deuda técnica o trabajo futuro.
Cada ítem incluye el contexto de por qué se tomó la decisión actual.

---

## 1. ProductionApprovalPolicy con controles externos

**Estado actual:** `DevelopmentApprovalPolicy` se usa tanto en desarrollo como en producción (ECS). La aprobación de queries guarded la gestiona el agente CAI mediante el handshake hardcodeado en `execute_watchguard_guarded_custom_query`.

**Por qué es aceptable hoy:** hay un solo flujo de aprobación (el agente CAI) y un volumen bajo de usuarios simultáneos.

**Qué hacer cuando escale:** implementar una `ProductionApprovalPolicy` que soporte controles externos — por ejemplo, un webhook de aprobación humana real o un sistema de permisos por rol. El punto de extensión ya está definido: reemplazar la instancia en `wiring._build_postgres_runtime()`.

---

## 2. Persistencia de ObservationRequests, QueryRequests y ApprovalDecisions

**Estado actual:** `AppRuntime` mantiene `observation_requests`, `observation_results`, `query_requests` y `approval_decisions` en dicts en memoria (`field(default_factory=dict)`), incluso en el modo PostgreSQL. Un restart del ECS task los pierde.

**Por qué es aceptable hoy:** son objetos efímeros del ciclo de vida de un run individual. Si el ECS reinicia durante una query guarded en vuelo, el usuario simplemente la reintenta.

**Qué hacer si se necesita durabilidad:** agregar tablas `observation_requests`, `query_requests` y `approval_decisions` en PostgreSQL, y mover el despacho al mismo patrón JSONB que `cases` / `runs` / `artifacts`. Evaluar si el volumen de retries lo justifica.

---

## 3. AuditPort persistente en PostgreSQL

**Estado actual:** `InMemoryAuditPort` se usa en producción. Los timeline events y decision records solo viven en RAM.

**Por qué es aceptable hoy:** el audit log no tiene casos de uso reales definidos — nadie lo lee todavía.

**Qué hacer cuando haya un requisito concreto:** cuando exista un requisito de compliance o revisión de analistas, implementar `PostgresAuditPort` con una tabla `audit_events` (JSONB) y reemplazar la instancia en `wiring._build_postgres_runtime()`. El puerto ya está abstraído en `InMemoryAuditPort`, el cambio es solo de wiring.

---

## 4. Integridad referencial runs → cases

**Estado actual:** `case_id` en la tabla `runs` es `TEXT` sin `REFERENCES cases(case_id)`. No hay FK a nivel de base de datos.

**Por qué es aceptable hoy:** la integridad la garantiza `platform-core` a nivel de aplicación. El modelo de storage es JSONB y evitar FK facilita evolucionar los modelos sin migraciones de schema. Los runs huérfanos no son un problema operacional porque todo acceso pasa por los servicios de `platform-core`.

**Qué considerar si cambia el diseño:** si en el futuro se necesitan queries SQL directas sobre la BD (reporting, dashboards), agregar la FK y un `ON DELETE SET NULL` o `ON DELETE CASCADE` según el requisito.

---

## 5. Autenticación en el API

**Estado actual:** el ALB está público sin ningún mecanismo de autenticación. Cualquiera con la URL puede crear casos, adjuntar artefactos y ejecutar observaciones.

**Por qué es aceptable hoy:** la URL del ALB no es pública en ningún documento publicado y el uso es interno entre analistas de EGS.

**Qué hacer antes de escalar a más usuarios:** evaluar e implementar una de estas opciones según el modelo de uso:
- **API key simple en el ALB** (Listener Rule + Lambda authorizer) — mínima fricción, suficiente para equipo pequeño.
- **Cognito User Pool** — si se necesita gestión de usuarios, MFA o integración con SSO corporativo.
- **Restricción por IP/VPN** — si todos los analistas operan desde una red conocida, es la opción de menor complejidad.

El punto de extensión natural es un middleware FastAPI o una regla en el ALB antes de que los requests lleguen a ECS.

---

## 6. platform-ui (Streamlit) como interfaz principal para analistas

**Estado actual:** existe `apps/platform-ui/` con una interfaz Streamlit de 3 tabs — WatchGuard S3 Investigation, Phishing Investigation, Monitor IMAP — que envuelve el mismo `cai-orchestrator` que el CLI. Es funcional pero no está documentada como camino principal.

**Contexto:** la UI corre localmente (`make ui`, puerto 8501) Y en ECS Fargate (accesible vía ALB en `/ui`). Lee las mismas variables de entorno que el CLI. El sidebar permite editar API URL, Client ID, modelo CAI y credenciales AWS sin reiniciar. Tiene un workaround para el conflicto de SIGINT entre Streamlit y CAI.

**Estado en nube:** ECS service `platform-ui` corriendo, 1 task Fargate. Accesible en `http://cai-platform-alb-472989822.us-east-2.elb.amazonaws.com/ui`. Health check configurado en `/ui/_stcore/health` (el baseUrlPath `/ui` desplaza todos los endpoints de Streamlit, incluyendo el health check).

**Qué considerar:** la UI ya es el camino principal para analistas. Pendientes concretos antes de compartirla ampliamente:
- Agregar autenticación básica (ver ítem 5) — actualmente cualquiera con el link tiene acceso completo.
- Documentar el flujo de instalación recomendado para desarrollo local (`make install-ui-cai`).

---

## 8. Adaptive DDoS collection (future)

**Estado actual:** `_run_ddos_collection()` always runs the same 7 fixed observations on the top segment and top IP regardless of traffic volume or source distribution.

**Por qué es aceptable hoy:** deterministic behavior eliminates LLM stall risk and produces consistent, reproducible output for any log volume.

**Qué hacer cuando se necesite:** add detection logic inside `_run_ddos_collection` to:
- Run segment/IP analysis on top-N (not just top-1) when traffic is spread across many sources
- Skip hourly distribution when the dataset spans less than 3 hours
- Trigger an alert when total_events < threshold (possibly not a real DDoS)
- At that point, consider whether a lightweight LLM decision step is worth re-introducing to choose which observations to run based on the data characteristics.

---

## 9. Credenciales root de AWS — migrar a usuario IAM con mínimo privilegio

**Estado actual:** la AWS Access Key activa (`AKIA5W3VQRLDWVZB3AN5`) pertenece a la cuenta root (AccountId = UserId en `get-caller-identity`). No existen usuarios IAM en la cuenta.

**Por qué es un riesgo:** las credenciales root tienen acceso irrevocable a todo en AWS y no pueden ser restringidas por políticas IAM. Si la key se filtra (por ejemplo por un commit accidental del `.env`), un atacante tiene control total de la cuenta.

**Qué hacer antes de llevar a producción:**
- Crear un usuario IAM `cai-orchestrator-operator` con política de mínimo privilegio: solo `s3:GetObject` / `s3:PutObject` en `egslatam-cai-dev`, `bedrock:InvokeModel`, y nada más.
- Generar una key para ese usuario y actualizar el `.env`.
- Deshabilitar o eliminar la key root actual.
- Habilitar MFA obligatorio para el root account (la cuenta ya tiene MFA activado según `AccountMFAEnabled=1`, verificar que siga activo).

---

## 10. HTTPS en el ALB

**Estado actual:** el ALB `cai-platform-alb` tiene un único listener en HTTP:80. El tráfico entre el orchestrator/UI y la API viaja sin cifrado.

**Por qué es un riesgo:** el ALB es `internet-facing`. Cualquier intermediario puede leer o modificar los payloads (logs de clientes, resultados de análisis). No es aceptable para datos de clientes reales.

**Qué hacer antes de llevar a producción:**
- Registrar un dominio y emitir un certificado en ACM (gratuito).
- Agregar listener HTTPS:443 al ALB apuntando al mismo target group.
- Agregar regla de redirect HTTP → HTTPS en el listener 80.
- Actualizar `PLATFORM_API_BASE_URL` en `.env` y en los scripts de demo.

---

## 7. ECS scale-to-zero cuando no hay investigaciones activas

**Estado actual:** el ECS service `cai-platform-service` corre continuamente (1 task Fargate), generando ~$0.59/día de costo aunque no haya investigaciones en curso.

**Por qué es aceptable hoy:** el costo es bajo y simplifica las operaciones (el API siempre está listo).

**Opciones para reducir costo cuando no se usa:**
- **Scale to 0 manual**: `aws ecs update-service --desired-count 0` cuando se termina el día, `--desired-count 1` para retomar. Agrega ~30 s de cold start.
- **Scheduled scaling**: EventBridge Scheduler que escale a 0 fuera del horario laboral (ej. 20:00–08:00 ART) y a 1 al inicio del día.
- **Application Auto Scaling con target tracking**: escala según CPU/memoria; con umbral bajo baja a 1 task en inactividad (no llega a 0, pero reduce costo si se usa una task más pequeña).

El comando `make ecs-stop` / `make ecs-start` ya existe en el Makefile para escalar manualmente.
