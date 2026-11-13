# Changelog

Todos los cambios relevantes de este proyecto se documentarán en este fichero.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), y este proyecto sigue [Semantic Versioning](https://semver.org/lang/v2.0.0/).

## [Unreleased]

### Pendiente

- Herramienta de *parsing* estructurado de registros de autenticación, sistema y transferencias (RF4).
- Herramienta de ejecución de *scripts* preaprobados mediante catálogo cerrado versionado (RF5).
- Integración del agente de IA y desarrollo de la interfaz web de revisión.

## [0.3.0] - 2026-11-13

### Añadido

- Herramienta MCP `build_timeline` (RF3) para generación, filtrado en flujo y paginación determinista de líneas temporales forenses basadas en el formato *bodyfile* de The Sleuth Kit (`fls -m`).
- Procesamiento en flujo (*streaming*) de eventos que evita materializar ficheros o estructuras completas en memoria (filtrado al vuelo por intervalo temporal UTC, prefijo de ruta, tipo de marca MACB e inclusión de eliminados).
- Ordenación determinista estricta (cronológica ascendente con desempate por inodo, ruta y tipo de marca) que asegura idéntico resultado ante ejecuciones repetidas (RNF2).
- Tratamiento seguro de nombres de fichero con caracteres de separación (`|`) y marcas temporales indefinidas (timestamp `<= 0` excluido de la línea temporal sin conversión a 1970).
- Registro de decisión de arquitectura [ADR-004](docs/adr/004-linea-temporal-bodyfile-tsk-frente-a-plaso.md) que justifica el uso de TSK bodyfile en lugar de Plaso para la fase de triaje.
- Suite de pruebas ampliada a 36 casos con validación de empates de timestamp, pipes en nombres, filtros temporales y pruebas de integración sobre la imagen real.

## [0.2.1] - 2026-11-12

### Añadido

- Clave de caché en memoria compuesta por ruta absoluta, tamaño en bytes y `mtime` en nanosegundos para evitar lecturas de procedencia obsoleta.
- Pruebas unitarias de invalidación de caché ante modificaciones de `mtime` y tamaño de fichero.
- Comprobación en arranque de si `FORENSIC_MCP_EVIDENCE_ROOT` tiene permisos de escritura, registrando advertencia en `audit.jsonl`.
- Registro de decisión de arquitectura [ADR-003](docs/adr/003-procedencia-y-cache.md) (semántica de procedencia, caché compuesta y solo lectura en 3 capas).
- Documentación explícita de la semántica del campo `hash` (SHA-256 de la imagen como artefacto de origen) en código y README.

## [0.2.0] - 2026-11-12

### Añadido

- Adaptador The Sleuth Kit (`TSKAdapter`) con ejecución segura (`subprocess` sin *shell*), control de *timeout* configurable y detección de binarios no instalados (`TSK_NOT_INSTALLED`, `TSK_TIMEOUT`).
- Validación de integridad de geometría MBR en `mmls` (`IMAGE_GEOMETRY_TRUNCATED`) para detectar imágenes truncadas o incompletas frente al tamaño real del fichero.
- Herramienta MCP `get_file_metadata` (RF2) para extracción de metadados normalizados de inodo (MACB UTC, tamaños real y alocado, atributos/streams y *flags*) con bloque de procedencia de 6 campos.
- Herramienta MCP `list_directory` (RF2) con listado paginado determinista (`limit`, `offset`) basado en `fls` no recursivo.
- Salidas reales de TSK guardadas como texto en `tests/fixtures/tsk/` para pruebas de *parsing* desacopladas del entorno.
- Pruebas unitarias de *parsers* y pruebas de integración contra la imagen real `hacking-case.dd`.

## [0.1.0] - 2026-11-12

### Añadido

- Servidor MCP base sobre transporte `stdio` usando el SDK oficial de Python (`mcp>=2.3.0`).
- Herramienta `hash_evidence_file` para cálculo en flujo y verificación de hashes MD5 y SHA-256.
- Modelo central de procedencia `Provenance` con los seis campos obligatorios (`case_id`, `source_id`, `hash`, `inodo_ruta`, `timestamp_utc`, `rpc_call_id`).
- Registro de auditoría `AuditLogger` en formato JSONL *append-only* aislado de la carpeta de evidencias.
- Guardián de lectura exclusiva `open_evidence_readonly` con apertura `os.O_RDONLY` y rechazo explícito de modos de escritura.
- Suite de 13 pruebas con `pytest`, incluyendo *fixture* `.dd` sintética, contraste con `sha256sum`, bloqueo de *sockets* y validación de errores estructurados.
- Registros de decisiones de arquitectura [ADR-001](docs/adr/001-lectura-directa-de-la-imagen.md) (lectura directa) y [ADR-002](docs/adr/002-separacion-de-evidencia-y-codigo.md) (separación entre evidencia y código).

[Unreleased]: https://github.com/paulojur/forensic-mcp/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/paulojur/forensic-mcp/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/paulojur/forensic-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/paulojur/forensic-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/paulojur/forensic-mcp/releases/tag/v0.1.0
