# Próximos pasos — Abril 2026

Recomendaciones priorizadas tras el primer pipeline end-to-end en producción
(case-08ccad5bc997, 47M eventos, $0.088).

---

## ~~1. Terraform drift — riesgo inmediato~~ ✓ COMPLETADO

**Qué era:** Las task definitions de ECS (`cai-platform-api:5`, `cai-platform-ui:2`) se
modificaron ad-hoc vía AWS CLI. Si alguien corre `terraform apply` sin actualizar los
`.tf`, las revierte a la versión anterior (memoria 1024 MB → OOM, `DATABASE_URL` roto).

**Completado:** `infrastructure/terraform/modules/ecs/main.tf` sincronizado (commit `6ebb36c`).

---

## ~~2. Generación del reporte desde la UI~~ ✓ COMPLETADO

**Qué era:** `report-collect` y `report-generate` son CLI. `generate_report_from_context()`
ya existe en memoria pero no hay flujo en platform-ui para buscar un case → generar PDF
→ descargarlo. Sin esto, generar un informe requiere acceso SSH al servidor.

**Completado:** Expander "Exportar Informe DDoS" añadido al tab Case History (commit `8c89d2d`).
Usa los artifact payloads almacenados en platform-api — sin dependencia de `.egs_cases/` local.

---

## ~~3. Cierre del caso desde la plataforma~~ ✓ COMPLETADO

**Qué era:** El pipeline deja los casos "En revisión" (`mitre_enrichment_optional`
in_progress). No hay acción que avance a `findings_consolidation` y marque el caso como
completado. El informe lo refleja pero no lo resuelve.

**Completado:** `run_ddos_investigation` avanza determinísticamente las etapas restantes
post-síntesis: salta `mitre_enrichment_optional` y completa `findings_consolidation`
→ estado `READY_FOR_REPORT` (commit `97155a9`).

---

## 4. Blue team pipeline end-to-end con logs reales

**Qué es:** `blueteam_agents.py` tiene 234 tests unitarios pero nunca se corrió contra
logs reales de S3. El DDoS pipeline sí se validó en producción; el blue team no.

**Prioridad:** Media — necesario para poder ofrecerlo a clientes.

---

## 5. Logs de DDoS con IPs externas reales

**Qué es:** El case de prueba tenía IPs privadas RFC-1918 (tráfico interno). Para
validar que el pipeline produce análisis genuinamente accionables se necesitan logs con
un ataque real con IPs públicas. La calidad del análisis del LLM depende de esto.

**Prioridad:** Media — sin datos reales no se puede evaluar la precisión del producto.
