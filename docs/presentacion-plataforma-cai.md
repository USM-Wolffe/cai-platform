# Presentación: Plataforma CAI en la nube

Documento guía para armar el PowerPoint: **título**, **qué mostrar en pantalla** (gráfico) y **guion** para explicar la plataforma de forma sencilla (equipo técnico y no técnico).

---

## Slide 1 — Título

**Título sugerido:** Nuestra plataforma de investigaciones en la nube
**Subtítulo (opcional):** Del problema real a la solución — infraestructura estable + inteligencia asistida con CAI

### Qué ir gráficamente

- Logo del equipo o de la empresa (si aplica).
- Fondo limpio (blanco o azul muy suave); evitar mucho texto.
- Opcional: una sola imagen evocativa (nube + "investigación" o "seguridad"), sin diagramas técnicos todavía.

### Guion (qué decir)

> "Hoy les cuento la historia real de lo que construimos y cómo llegamos hasta acá. No empezamos con un diseño perfecto: **empezamos con un problema** y fuimos resolviendo. La idea es que todos tengamos el mismo relato."

---

## Slide 2 — El problema real que teníamos

**Título:** ¿Por qué tuvimos que construir esto?

### Qué ir gráficamente

- Tres íconos o cajas mostrando los tres dolores reales:
  1. **Logs imposibles de cargar** — archivos de 1.5 a 10 millones de filas
  2. **Infraestructura cara e inestable** — EC2 encendida siempre a ~$2/día, conexiones que se cortaban
  3. **Terminal incomprensible** — solo técnicos podían operar; el resto del equipo, afuera

### Guion

> "Los logs de WatchGuard llegaban en archivos enormes — hablamos de **millones de filas**. Intentar cargarlos en una EC2 era caro (~$2 por día solo de cómputo), la conexión se cortaba a mitad de una sesión y cuando volvías tenías que arrancar de cero. Además, la única manera de operar era a través de una **terminal**, lo que dejaba afuera a cualquier persona del equipo que no fuese desarrolladora. No era sostenible."

---

## Slide 3 — El camino que recorrimos

**Título:** De la EC2 a la nube: tres etapas reales

### Qué ir gráficamente

- **Línea de tiempo** o diagrama de etapas:
  1. **Etapa 1 — EC2 + terminal:** logs en disco, analistas en SSH, costo constante, conexiones caídas
  2. **Etapa 2 — Primeros agentes CAI:** automatización prometedora, pero reportes inconsistentes y costo alto
  3. **Etapa 3 — Plataforma híbrida en la nube:** API + base de datos + agentes donde realmente suman + UI web

- Flecha de izquierda a derecha con cada etapa marcada. Resaltar "Etapa 3" con color más fuerte.

### Guion

> "No llegamos aquí de golpe. **Primero** probamos con EC2 y todo manual — funcionaba, pero era caro y frágil. **Después** exploramos usar agentes de inteligencia artificial para automatizar todo el análisis — prometedor, pero los agentes a veces inventaban datos o producían reportes cortos y sin formato. **Hoy** tenemos una arquitectura híbrida: lo que es lógica pura lo hace Python determinístico, y los agentes de IA entran solo donde realmente tienen valor."

---

## Slide 4 — Qué es la plataforma hoy (en una frase)

**Título:** Un solo lugar para los casos de investigación

### Qué ir gráficamente

- Tres cajas o íconos en fila con etiquetas cortas:
  1. **Registrar el caso** (quién, qué pasó).
  2. **Ejecutar el análisis** (lo que hace el sistema por nosotros).
  3. **Guardar el resultado** (informes, evidencia, decisión).
- Opcional: una "caja" que envuelve esas tres cosas con el texto "Plataforma".

### Guion

> "Piensen la plataforma como **el escritorio oficial** de una investigación: ahí **abrimos el caso**, **corremos los análisis que ya están definidos** y **dejamos el resultado ordenado**. No es un chat suelto: es **un proceso** que todos seguimos de la misma manera, con los mismos pasos y el mismo formato de salida."

---

## Slide 5 — Dónde vive: en la nube

**Título:** Infraestructura en la nube — sin EC2 encendida todo el día

### Qué ir gráficamente

- Antes/Después en dos columnas:
  - **Antes:** una PC o EC2 encendida siempre, $2/día, logs en disco, conexión SSH que se cortaba
  - **Después:** AWS ECS Fargate (se enciende cuando se necesita), DuckDB lee los logs directamente desde S3 sin descargarlos, UI web accesible para todo el equipo

### Guion

> "Mudamos todo a AWS. Los logs ya no se descargan a ninguna máquina: **DuckDB los lee directo desde S3** mientras hace las consultas — eso resolvió el problema de memoria y costo. Los servicios corren en **contenedores** que se pueden apagar cuando no se usan. Y en vez de conectarse por terminal, ahora hay **una interfaz web** accesible para cualquiera del equipo con la URL."

---

## Slide 6 — El problema de los agentes "full-IA"

**Título:** Por qué los agentes solos no eran suficientes

### Qué ir gráficamente

- Dos columnas con íconos de alerta:
  - **Problema 1 — Inventaban datos:** el agente a veces generaba IPs o números que no estaban en los logs
  - **Problema 2 — Reportes inconsistentes:** cada ejecución podía dar un formato distinto, o un análisis más corto que otro
  - **Problema 3 — Costo alto:** un pipeline de 4 agentes costaba ~$10 por investigación
- Abajo: flecha hacia la solución "arquitectura híbrida"

### Guion

> "Probamos con 4 agentes de IA encadenados — uno recolectaba datos, otro los analizaba, otro los perfilaba, otro resumía. El problema: los agentes de IA a veces **paraban a mitad de un análisis**, **confundían pasos** o directamente **inventaban valores** que no existían en los logs. Además costaba casi $10 por investigación. Eso no era aceptable para un proceso de seguridad donde la precisión es todo."

---

## Slide 7 — La solución: dos capas bien separadas

**Título:** Lo que siempre hace lo mismo + lo que ayuda a interpretar

### Qué ir gráficamente

- **Dos bloques apilados** (abajo = cimiento, arriba = asistente):

| Capa inferior (más ancha, "cimiento") | Capa superior |
|----------------------------------------|---------------|
| **Plataforma + Python determinístico** — mismas 7 observaciones, mismo orden, mismo formato, siempre | **Agentes CAI** — setup inicial + interpretación final; no tocan los datos crudos |

- Flecha indicando: "los agentes usan la plataforma, no la reemplazan".
- Nota: "De $10 a menos de $1 por investigación"

### Guion

> "La solución fue separar qué hace el agente y qué hace el sistema. **Abajo**, todo lo que tiene que ser predecible: las 7 observaciones sobre los logs se ejecutan siempre en el mismo orden, con el mismo código Python, sin LLM. **Arriba**, los agentes CAI hacen lo que realmente saben hacer: **preparar el caso** al inicio y **interpretar los resultados** al final. Eso nos bajó el costo de investigación de ~$10 a menos de $1, y los reportes ahora son siempre completos y en el formato correcto."

---

## Slide 8 — Antes y después de un informe

**Título:** Reportes que se pueden mostrar

### Qué ir gráficamente

- Dos recuadros (estilo "hoja de papel"):
  - **Antes (con agentes full-IA):** texto corto, datos inventados, formato variable, a veces incompleto
  - **Después (arquitectura híbrida):** secciones fijas (evidencia, hallazgos, decisión de contención), datos reales de los logs, longitud consistente

### Guion

> "La diferencia más visible para el analista es el reporte. **Antes**, dependiendo del día, el agente podía darte tres líneas o tres páginas, con datos que sonaban bien pero no siempre coincidían con los logs. **Hoy**, el reporte tiene **secciones fijas**: evidencia registrada, hallazgo con severidad, decisión de contención recomendada. Si analizamos el mismo incidente dos veces, obtenemos el mismo resultado. Eso es lo que necesitamos para mostrar el trabajo al cliente."

---

## Slide 9 — La interfaz web (Streamlit)

**Título:** Accesible para todo el equipo, no solo para desarrolladores

### Qué ir gráficamente

- Captura de pantalla simplificada (o mockup) de la UI Streamlit con los 3 tabs visibles:
  - WatchGuard Investigation
  - Phishing Investigation
  - Monitor IMAP
- Texto en una línea: *Disponible ya en la URL pública del equipo*

### Guion

> "Una de las cosas que me importaba resolver era que **cualquier persona del equipo** pudiera lanzar una investigación, no solo alguien que sepa escribir comandos de terminal. Hoy existe una **interfaz web** con tabs para los distintos tipos de análisis. Todavía estamos terminando detalles de UX, pero ya está corriendo en AWS y accesible desde el navegador. Esto es lo que vamos a mostrar en demo cuando sea el momento."

---

## Slide 10 — Qué ganamos todos

**Título:** Qué cambió en el trabajo diario

### Qué ir gráficamente

- **4 íconos con una línea cada uno:**
  - **Costo** — de ~$10/investigación a <$1; EC2 apagada
  - **Confianza** — resultados determinísticos, mismos datos, mismo formato siempre
  - **Acceso** — interfaz web, no terminal; el equipo completo puede operar
  - **Escalabilidad** — nuevos tipos de análisis sin reescribir todo

### Guion

> "En resumen: **ahorramos** en cómputo y en costo por investigación. **Confiamos** en los resultados porque no dependen del humor de un agente IA. **Abrimos** la herramienta a todo el equipo con una UI web. Y **preparamos el terreno** para agregar nuevos tipos de análisis sin empezar de cero cada vez."

---

## Slide 11 — Hacia dónde vamos

**Título:** Lo que se viene

### Qué ir gráficamente

- **Línea de tiempo horizontal** con tres puntos:
  - **Corto plazo:** terminar UX de la UI, primera demo real al equipo, incorporar más analistas
  - **Mediano plazo:** nuevos tipos de análisis (nuevos "backends") enchufados a la misma plataforma
  - **Largo plazo:** MCP (protocolos estándar para que los agentes usen herramientas externas), agentes paralelos para investigaciones más rápidas, flujos multi-agente más sofisticados con las herramientas built-in del framework CAI
- Resaltar "Corto plazo" con color más fuerte.

### Guion

> "**Ahora mismo** estamos terminando la UI y preparando la primera demo real para el equipo. **Pronto** vamos a incorporar nuevos tipos de análisis a la misma base: el diseño ya lo permite, es solo agregar el nuevo servicio y conectarlo. **A futuro**, el framework CAI tiene capacidades para agentes que corren en paralelo, herramientas built-in más potentes y soporte para MCP — un protocolo estándar que permite a los agentes conectarse con sistemas externos de forma estandarizada. Eso nos abre la puerta a investigaciones mucho más ricas sin perder el control de la capa determinística que ya construimos."

---

## Slide 12 — Cierre y preguntas

**Título:** La plataforma como base para investigar mejor

### Qué ir gráficamente

- **Mini resumen visual** (tres íconos en una fila):
  1. Nube / disponibilidad
  2. Python determinístico / confianza
  3. CAI / asistencia inteligente donde suma
- Debajo: contacto o próximos pasos (URL de la UI, canal de dudas, fecha de demo).

### Guion

> "Para cerrar: lo que construimos es una **base sólida** para investigar incidentes de seguridad de manera consistente. Empezamos con un problema real — logs gigantes, EC2 cara, terminal inaccesible — y fuimos construyendo la solución paso a paso, aprendiendo en el camino qué funciona y qué no. **CAI** es la capa que potencia al analista, pero la confianza viene del proceso determinístico que está abajo. Gracias; abrimos preguntas."

---

## Notas para quien arma el PPT

- **Una idea por diapositiva.** Si algo suena denso, dividir en dos slides.
- **Gráficos:** preferir figuras simples (cajas, flechas, íconos) antes que capturas de código o Terraform.
- **Términos:** si se dice "API", "SDK" o "DuckDB", dar **una palabra en castellano** al lado la primera vez (*interfaz de servicios*, *kit de desarrollo*, *motor de consultas*).
- **Tiempo orientativo:** 1–1,5 minutos por slide → unos **15–18 minutos** de charla + preguntas.
- **No mencionar costos específicos** a audiencia no técnica si no es necesario — enfocarse en "barato y estable" en vez de cifras.
- **Slide 3 (el camino)** es el corazón de la presentación para audiencia mixta — asegurarse de que las tres etapas queden visualmente claras.

---

*Documento actualizado con la historia real del proyecto cai-platform.*
