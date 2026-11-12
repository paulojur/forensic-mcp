# Changelog

Todos los cambios relevantes de este proyecto se documentarán en este fichero.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), y este proyecto sigue [Semantic Versioning](https://semver.org/lang/v2.0.0/).

## [Unreleased]

### Pendiente

- Herramienta de extracción de metadatos normalizados del sistema de ficheros.
- Herramienta de generación, filtrado y paginación de líneas temporales de eventos.
- Herramienta de *parsing* estructurado de registros de autenticación, sistema y transferencias.
- Herramienta de ejecución de *scripts* preaprobados mediante catálogo cerrado versionado.
- Integración del agente de IA y desarrollo de la interfaz web de revisión.

## [0.1.0] - 2026-11-12

### Añadido

- Servidor MCP base sobre transporte `stdio` usando el SDK oficial de Python (`mcp>=2.3.0`).
- Herramienta `hash_evidence_file` para cálculo en flujo y verificación de hashes MD5 y SHA-256.
- Modelo central de procedencia `Provenance` con los seis campos obligatorios (`case_id`, `source_id`, `hash`, `inodo_ruta`, `timestamp_utc`, `rpc_call_id`).
- Registro de auditoría `AuditLogger` en formato JSONL *append-only* aislado de la carpeta de evidencias.
- Guardián de lectura exclusiva `open_evidence_readonly` con apertura `os.O_RDONLY` y rechazo explícito de modos de escritura.
- Suite de 13 pruebas con `pytest`, incluyendo *fixture* `.dd` sintética, contraste con `sha256sum`, bloqueo de *sockets* y validación de errores estructurados.
- Registros de decisiones de arquitectura [ADR-001](docs/adr/001-lectura-directa-de-la-imagen.md) (lectura directa) y [ADR-002](docs/adr/002-separacion-de-evidencia-y-codigo.md) (separación entre evidencia y código).

[Unreleased]: https://github.com/paulojur/forensic-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/paulojur/forensic-mcp/releases/tag/v0.1.0
