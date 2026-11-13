# ADR-003: Semántica de procedencia, clave de caché compuesta y arquitectura de solo lectura en tres capas

- **Estado:** Aceptada
- **Fecha:** 2026-11-12

## Contexto

El diseño del servidor MCP forense se fundamenta en dos principios irrenunciables: el contrato de seguridad sobre la evidencia y la procedencia verificable de cada resultado devuelto al agente de IA. Al implementar la extracción de metadatos (RF2) y el cálculo de hashes (RF1) sobre la imagen de estudio de 4,87 GB (`hacking-case.dd`), surgieron decisiones de compromiso sobre el rendimiento temporal (RNF4), la uniformidad del modelo de procedencia y las garantías de preservación de la evidencia.

## Decisiones

### 1. Semántica del campo `hash` en el bloque de procedencia
El campo `hash` del modelo `Provenance` (bloque de seis campos obligatorio en todas las respuestas) contiene **siempre** el hash SHA-256 canónico de la imagen forense como artefacto de origen, precedido del prefijo `sha256:` (por ejemplo, `sha256:65e2002fed0b286f49541c7e97dcec0dda913d51a063ceeed86782bdacda2312`).

Los hashes calculados sobre ficheros individuales analizados o extraídos dentro de la imagen residen en el modelo específico de la operación (`HashResult.md5`, `HashResult.sha256`), nunca en el bloque de procedencia. Esto garantiza que la estructura y la semántica de `Provenance` sean universales e idénticas en todas las herramientas del servidor.

### 2. Formato estructurado del campo `inodo_ruta`
Para localizar de forma unívoca cualquier artefacto dentro de un contenedor forense, el campo `inodo_ruta` adopta el formato compuesto:
- Para ficheros/directorios individuales: `offset:<sector>:inode:<inodo>:<nombre>` (o `offset:<sector>:inode:<inodo>` si no existe nombre asociado).
- Para listados paginados de directorio: `offset:<sector>:inode:<inodo>:paged[<offset>:<offset+limit>]` (o `offset:<sector>:root:paged[...]`).
- Para ficheros sueltos en el sistema anfitrión: la ruta resuelta del fichero.

### 3. Política de caché de hash con clave compuesta
Calcular el hash SHA-256 completo de una imagen de 4,87 GB requiere ~65 segundos en el entorno de pruebas, lo que violaría el requisito no funcional RNF4 (tiempo de respuesta inferior a 30 segundos en consultas habituales de triaje) si se ejecutase en cada consulta de metadatos.

Para resolverlo sin comprometer la integridad:
- Se implementa una caché en memoria cuya clave es estrictamente **compuesta**: `(ruta_absoluta, tamaño_en_bytes, mtime_en_nanosegundos)`.
- Si el fichero no cambia, las consultas de metadatos devuelven la procedencia en milisegundos.
- Cualquier divergencia en el tamaño, la fecha de modificación o la ruta invalida inmediatamente la entrada y fuerza el recálculo en flujo, eliminando el riesgo de proveniencia obsoleta.

### 4. Arquitectura de garantía de solo lectura en tres capas
La inmutabilidad de la evidencia no se confía a un único mecanismo, sino a una defensa en profundidad en tres capas:

1. **Capa 1 (Guardián en proceso):** La función `open_evidence_readonly` valida que cualquier descriptor de fichero abierto por el servidor utilice exclusivamente `os.O_RDONLY` en modo binario `'rb'`, rechazando con error explícito (`READ_ONLY_VIOLATION`) cualquier intento de apertura en modo de escritura o creación.
2. **Capa 2 (Garantía arquitectural en herramientas externas):** Las invocaciones a binarios de The Sleuth Kit (`mmls`, `fls`, `istat`) se realizan mediante `subprocess.run` con listas estrictas de argumentos y `shell=False`. Dado que estas invocaciones delegan la lectura al binario externo y no pasan por el guardián de descriptores en memoria, la garantía en este nivel es puramente arquitectural: el catálogo de comandos es cerrado y ninguna de las herramientas invocadas posee flags ni capacidades de modificación sobre el soporte físico.
3. **Capa 3 (Sistema de ficheros y entorno de ejecución):** Protección a nivel de permisos del sistema operativo (POSIX / ext4). Al iniciar, el servidor verifica si `FORENSIC_MCP_EVIDENCE_ROOT` es gravable (`os.access(..., os.W_OK)`); si lo es, emite un registro de advertencia en `audit.jsonl` indicando que la seguridad depende en ese momento de las capas 1 y 2.

### 5. Determinismo analítico frente a metadados de auditoría
El requisito de determinismo y reproducibilidad (RNF2) aplica estrictamente a los hallazgos sobre la evidencia: los datos del evento analizado (`timestamp_utc` del artefacto, ruta, inodo, tipo de marca, tamaño y asignación) son rigurosamente idénticos ante invocaciones repetidas. En contraste, los campos `timestamp_utc` y `rpc_call_id` del bloque `Provenance` pertenecen a la capa de auditoría del acto pericial; registran cuándo se ejecutó la consulta analítica y varían legítimamente en cada invocación sin comprometer el determinismo científico de los resultados.

## Consecuencias

- **Positivas:** Cumplimiento simultáneo del RNF4 (< 30s) y de la auditabilidad estricta; semántica de procedencia homogénea y predecible para el agente de IA; protección en profundidad documentada con claridad técnica sobre los límites de cada capa.
- **Negativas / Limitaciones:** En sistemas de ficheros montados desde Windows a través del driver 9P del WSL, las ACLs del host pueden permitir escritura al proceso, por lo que la tercera capa exige mantener la evidencia en ext4 nativo para una verificación formal completa de permisos POSIX.
