# forensic-mcp

Servidor MCP (Model Context Protocol) de solo lectura para el triaje forense de imágenes de disco Windows, desarrollado como Trabajo Final de Máster en el Máster Universitario en Ciberseguridad y Privacidad de la Universitat Oberta de Catalunya (UOC).

## Qué lo distingue

Impone un contrato de seguridad verificable en código sobre la evidencia y adjunta un bloque de procedencia de seis campos a cada hallazgo devuelto al agente.

## Estado actual

Versión actual: `v0.3.0`.

- Implementado: servidor MCP sobre transporte `stdio`, modelo central de procedencia (`Provenance`), guardián de lectura exclusiva (`open_evidence_readonly`), registro de auditoría JSONL *append-only*, suite de verificación del contrato de seguridad, herramienta `hash_evidence_file` (RF1), adaptador de The Sleuth Kit (`TSKAdapter` con validación de geometría del MBR y control de *timeout*), herramientas de metadados normalizados `get_file_metadata` y listado paginado `list_directory` (RF2), y herramienta de generación, filtrado y paginación en flujo de líneas temporales forenses `build_timeline` (RF3).
- No existe todavía en esta versión: las dos herramientas forenses restantes (*parsing* de registros y ejecución de *scripts* preaprobados), la integración con el agente de IA, la interfaz web de revisión y el empaquetado en Docker.

## Requisitos

- Python 3.11 o superior.
- Linux o WSL2 (Ubuntu).

Windows nativo no se soporta en esta fase porque la verificación de hashes contra la utilidad estándar del sistema (`sha256sum`) y las futuras herramientas forenses de línea de comandos (The Sleuth Kit) dependen de un entorno POSIX.

## Evidencias forenses

Las imágenes forenses no forman parte del repositorio ni deben almacenarse dentro de él. Se mantienen en un directorio externo indicado mediante la variable de entorno `FORENSIC_MCP_EVIDENCE_ROOT`, y el servidor confina todos los accesos a esa raíz rechazando cualquier ruta externa.

Ejemplo de configuración antes de arrancar el servidor:

```bash
export FORENSIC_MCP_EVIDENCE_ROOT=/ruta/a/evidence
forensic-mcp
```

En el caso de estudio utilizado en el TFM, las evidencias corresponden a la imagen unificada `hacking-case.dd` (resultante de los segmentos `SCHARDT.001` a `SCHARDT.008` del *NIST CFReDS Hacking Case*), mantenida fuera del repositorio.

El modo POSIX de solo lectura es verificable en el entorno de análisis (WSL/ext4) y constituye la tercera capa de protección, además del guardián en código y de la ausencia de rutas de escritura. En un sistema de ficheros montado a partir de Windows, el acceso por ACLs de dicho sistema no queda cubierto por esta capa, por lo que la evidencia de referencia se mantiene en ext4 para demostración.

## Modelo de procedencia

Cada resultado devuelto al cliente MCP incorpora un bloque de procedencia (`Provenance`) con seis campos obligatorios: `case_id`, `source_id`, `hash`, `inodo_ruta`, `timestamp_utc` y `rpc_call_id`.

El campo `hash` contiene siempre el SHA-256 de la imagen forense como artefacto de origen, con el prefijo `sha256:`. Los hashes calculados sobre ficheros individuales dentro de la imagen quedan en el modelo de resultado de la operación (`HashResult`), nunca en el bloque de procedencia. El bloque tiene estructura y semántica idénticas en todas las herramientas.

## Instalación

1. Crear el entorno virtual en la raíz del proyecto:
```bash
python3 -m venv .venv
```

2. Activar el entorno virtual:
```bash
source .venv/bin/activate
```

3. Instalar el paquete y las dependencias de desarrollo:
```bash
pip install -e ".[dev]"
```

## Uso

Arrancar el servidor MCP en transporte `stdio`:

```bash
forensic-mcp
```

Variables de entorno opcionales: `FORENSIC_MCP_AUDIT_LOG` (ruta del fichero JSONL de auditoría, por defecto `audit/audit.jsonl`) y `FORENSIC_MCP_EVIDENCE_ROOT` (directorio raíz permitido para las evidencias).

Ejecutar la suite de pruebas:

```bash
pytest -v
```

## Estructura del repositorio

- `pyproject.toml`: definición del paquete, dependencias y punto de entrada `forensic-mcp`.
- `LICENSE`: licencia MIT del proyecto.
- `README.md`: documentación principal del repositorio.
- `CHANGELOG.md`: historial de cambios y elementos pendientes por versión.
- `docs/adr/`: registros de decisiones de arquitectura (ADR).
- `src/forensic_mcp/models.py`: modelos Pydantic de procedencia (`Provenance`), hashes (`HashResult`), metadados de inodo (`FileMetadataResult`), listado de directorios (`DirectoryListingResult`), líneas temporales (`TimelineResult`, `TimelineEvent`) y errores estructurados (`StructuredError`).
- `src/forensic_mcp/evidence.py`: guardián de acceso de solo lectura (`open_evidence_readonly`) y confinamiento de rutas (`resolve_evidence_path`).
- `src/forensic_mcp/audit.py`: registrador de auditoría JSONL *append-only* aislado del directorio de evidencias.
- `src/forensic_mcp/adapters/tsk.py`: adaptador de The Sleuth Kit (`mmls`, `fls`, `istat`) con verificación de geometría MBR, timeouts, *parsers* de texto y streaming de *bodyfile*.
- `src/forensic_mcp/tools/hashing.py`: cálculo y verificación de hashes MD5 y SHA-256 (RF1).
- `src/forensic_mcp/tools/metadata.py`: extracción de metadados normalizados y listado paginado de directorios (RF2).
- `src/forensic_mcp/tools/timeline.py`: generación en flujo, filtrado y paginación determinista de líneas temporales (RF3).
- `src/forensic_mcp/server.py`: servidor `MCPServer` sobre `stdio`, exposición de herramientas (`hash_evidence_file`, `get_file_metadata`, `list_directory`, `build_timeline`) y captura controlada de errores.
- `tests/`: *fixtures* sintéticas, salidas reales de TSK (`tests/fixtures/tsk/`) y pruebas automatizadas (36 pruebas).

## Contrato de seguridad

- Solo lectura verificable: las evidencias se abren exclusivamente mediante `os.O_RDONLY` en modo `'rb'`; cualquier intento de apertura en modo de escritura falla de forma explícita.
- Operación sin red en tiempo de ejecución: el transporte `stdio` no abre *sockets* durante el análisis, verificado mediante prueba automatizada que intercepta `socket.socket`.
- Sin construcción de comandos de *shell*: no se concatenan cadenas para invocar intérpretes ni binarios externos.
- Errores estructurados y auditoría completa: toda llamada genera un `rpc_call_id` único registrado en `audit.jsonl` (solo metadatos, nunca contenido de ficheros) y los errores se devuelven como JSON estructurado sin *stack traces*.

## Licencia y citación

El código de este repositorio se distribuye bajo licencia MIT; consúltese el fichero [LICENSE](LICENSE).

Para citar este trabajo en contexto académico, remítase a la memoria del Trabajo Final de Máster: *MCP Server para la Automatización de Análisis Forense asistido por IA mediante agentes agénticos*, Paulo Ricardo de Oliveira, Máster Universitario en Ciberseguridad y Privacidad, Universitat Oberta de Catalunya (UOC), 2026–2027.

La memoria del Trabajo Final de Máster se distribuye bajo la licencia Creative Commons Reconocimiento-NoComercial-CompartirIgual 3.0 España, conforme a la plantilla de la Universitat Oberta de Catalunya.

