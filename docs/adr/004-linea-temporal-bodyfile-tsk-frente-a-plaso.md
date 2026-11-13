# ADR-004: Generación de líneas temporales mediante bodyfile de The Sleuth Kit frente a Plaso

- **Estado:** Aceptada
- **Fecha:** 2026-11-13

## Contexto

El requisito funcional RF3 exige la generación, filtrado y paginación de líneas temporales forenses sobre las imágenes de disco durante la fase de triaje. Para construir líneas temporales en análisis forense digital existen dos enfoques predominantes:

1. **Plaso (`log2timeline` + `psort`):** Marco de extracción super-timeline capaz de analizar múltiples artefactos del sistema operativo (MFT, registros del sistema, navegadores, logs de eventos).
2. **The Sleuth Kit (`fls -m`):** Generación nativa en flujo del formato *bodyfile* (versión 3.x) que extrae las cuatro marcas temporales MACB (`mtime`, `atime`, `ctime`, `crtime`) a nivel del sistema de ficheros.

## Problema

La adopción de Plaso para la capa de triaje presenta inconvenientes técnicos críticos frente a los requisitos del proyecto:

1. **Latencia y violación del RNF4:** La ejecución de `log2timeline` sobre una imagen de 4,87 GB requiere de minutos a horas, excediendo con creces el límite de 30 segundos establecido en el RNF4 para consultas de triaje.
2. **Estado persistente e impacto en el determinismo (RNF2):** Plaso genera un fichero intermedio SQLite/storage en disco. Esto introduce almacenamiento mutable durante el análisis, complicando las garantías formales de reproducibilidad y ausencia de efectos colaterais requeridas por el RNF2.
3. **Riesgo metodológico declarado:** La Tabla 2 de la memoria de la PEC2 ya cataloga a Plaso como un riesgo explícito (*"log2timeline lento o incompatible con la imagen"*).

## Decisión

Se adopta la **Via B (The Sleuth Kit puro mediante formato bodyfile)** para la herramienta `build_timeline` (RF3):

- El servidor MCP invoca `fls -m / -o <offset> -r <imagen>` en modo *streaming*, derivando el offset de la partición en tiempo de ejecución a través del `TSKAdapter` ya existente.
- El flujo de salida se procesa línea a línea en memoria aplicando los filtros de consulta (intervalo temporal UTC, prefijo de ruta, tipo de marca MACB y exclusión de ficheros eliminados) durante el *parsing*, sin materializar ficheros intermediarios en disco.
- La ordenación de los eventos es estrictamente determinista (cronológica ascendente con desempate por inodo, ruta y tipo de marca), garantizando que consultas idénticas devuelvan páginas idénticas.

## Alternativas rechazadas

- **Plaso (`log2timeline`):** Rechazada por su elevado coste computacional en la fase de triaje, la necesidad de dependencias binarias pesadas y la generación de bases de datos mutables en disco.

## Consecuencias y limitaciones asumidas

- **Positivas:** Reducción drástica del tiempo de generación (1,67 segundos para 98.176 eventos sobre la imagen de 4,87 GB en WSL2); cero almacenamiento intermedio en disco; estricto cumplimiento del determinismo (RNF2) y mitigación directa del riesgo metodológico de la Tabla 2.
- **Limitación asumida:** El *bodyfile* de TSK abarca exclusivamente marcas temporales del sistema de ficheros (MFT / metadatos). Los artefactos de registro de Windows y los registros de sucesos (.evtx) no forman parte de esta línea temporal base y se abordan de manera desacoplada en la herramienta RF4 (*parsing* de logs estructurados).

