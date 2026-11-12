# ADR-001: Lectura directa de la imagen forense en lugar de montaje en el sistema operativo

- **Estado:** Aceptada
- **Fecha:** 2026-11-12

## Contexto

En la memoria de diseño (PEC2, sección 2.3) se describía inicialmente que la imagen forense se montaría en modo de solo lectura en el sistema operativo para que el servidor MCP operase sobre ella. Sin embargo, el requisito no funcional RNF3 exige portabilidad entre Linux y Windows, y la implementación inicial se desarrolla en un entorno Windows 11 con WSL2 (Ubuntu).

Tras este análisis, la sección 2.3 de la memoria se actualizó para reflejar la lectura directa, de modo que el diseño documentado y el código implementado coinciden.

## Problema

Montar una imagen de disco en bruto (`.dd`) a nivel de sistema operativo presenta dos inconvenientes técnicos graves:

1. **Falta de portabilidad:** Windows no dispone de montaje nativo de imágenes `.dd` sin controladores de terceros, y en Linux el montaje mediante `mount -o ro,loop` requiere privilegios elevados (`root`) y puede fallar o intentar reproducir el *journal* en sistemas de ficheros NTFS/ext sucios si no se especifican opciones adicionales.
2. **Dependencia del entorno anfitrión:** Hacer depender la garantía de solo lectura de un montaje del sistema operativo acopla el servidor a la configuración de privilegios y controladores del *host*.

## Decisión

El servidor MCP **nunca monta** la imagen forense en el sistema operativo. En su lugar:

1. Abre la imagen o artefacto directamente en modo binario de solo lectura (`rb` respaldado por `os.O_RDONLY`) a través del guardián `open_evidence_readonly`.
2. Para operaciones de cálculo de hashes sobre la imagen completa o ficheros sueltos (fase actual `v0.1.0`), lee los *bytes* directamente en flujo.
3. Para futuras operaciones sobre ficheros internos de una imagen de disco (extracción de metadatos, listado de inodos o contenido interno), delegará la interpretación del sistema de ficheros a los binarios de **The Sleuth Kit** (`mmls`, `fls`, `icat`) invocados mediante `subprocess` con lista de argumentos y sin intérprete de *shell*.

## Alternativas rechazadas

- **Montaje con `mount -o ro,loop`:** Rechazada por no ser portable a Windows, requerir privilegios de administrador y depender de controladores de sistema de ficheros del núcleo.
- **`pytsk3` (bindings Python de The Sleuth Kit):** Rechazada por los problemas recurrentes de compilación de extensiones C/C++ en Python 3.12/3.13 y porque la invocación controlada de los binarios CLI de TSK sin *shell* ofrece el mismo determinismo con menor acoplamiento.

## Consecuencias

- **Positivas:** Portabilidad real de la base de código entre Linux y WSL2 sin necesidad de *drivers* de montaje ni privilegios `root`, y garantía verificable en código de que ningún descriptor se abre en modo escritura.
- **Negativas / Requisitos operativos:** A partir de la segunda herramienta (cuando se requiera inspeccionar el interior de particiones NTFS/FAT), será necesario tener instalado The Sleuth Kit en el entorno de ejecución (p. ej., `apt install sleuthkit` en Ubuntu/WSL2).

