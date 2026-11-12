# ADR-002: Separación física entre la evidencia forense y el código del repositorio

- **Estado:** Aceptada
- **Fecha:** 2026-11-12

## Contexto

Durante la implementación inicial del repositorio se constató que los segmentos de la imagen forense del caso de estudio (`SCHARDT.001` a `SCHARDT.005`, pertenecientes al *NIST CFReDS Hacking Case*) se encontraban ubicados en la raíz del proyecto junto al código fuente.

## Problema

Mantener o versionar evidencias forenses dentro de un repositorio público de código plantea tres problemas incompatibles con el diseño del sistema:

1. **Cadena de custodia y separación de responsabilidades:** la evidencia analizada no debe residir junto al código ni bajo el mismo control de versiones que la analiza.
2. **Límites de almacenamiento de GitHub:** las imágenes de disco fragmentadas superan con facilidad los límites de tamaño de fichero y de repositorio de GitHub.
3. **Riesgo de publicación accidental:** la presencia de segmentos binarios en el árbol de trabajo expone el proyecto a incluir datos de evidencia en *commits* públicos.

## Decisión

1. La evidencia forense reside siempre en un directorio externo al repositorio, indicado en tiempo de ejecución mediante la variable de entorno `FORENSIC_MCP_EVIDENCE_ROOT`.
2. El fichero `.gitignore` excluye explícitamente los patrones de imágenes forenses (`*.dd`, `*.raw`, `*.e01`, `*.E01`, `*.img`, `SCHARDT.*`), los registros de auditoría (`audit.jsonl`, `audit/`) y los directorios de evidencias (`evidence/`, `evidences/`).
3. El servidor confina los accesos a `FORENSIC_MCP_EVIDENCE_ROOT` mediante `resolve_evidence_path` y rechaza cualquier ruta fuera de dicha raíz.

## Alternativas rechazadas

- **Guardar la evidencia en el repositorio:** rechazada por incompatibilidad con los límites de GitHub, riesgo de contaminación de la historia de Git y mezcla de código con evidencia.
- **Usar Git LFS:** rechazada porque sigue acoplando artefactos forenses al repositorio de código, introduce dependencias de almacenamiento remoto y no aporta ventajas frente a una ruta externa controlada por variable de entorno.

## Consecuencias

- **Positivas:** repositorio ligero, limpio y publicable en GitHub; separación verificable entre evidencia, registros de auditoría y código.
- **Negativas / Requisitos operativos:** es necesario configurar `FORENSIC_MCP_EVIDENCE_ROOT` antes de arrancar el servidor en modo confinado; el clon del repositorio reproduce únicamente el código y las pruebas sintéticas, no las imágenes reales del caso de estudio.

