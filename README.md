# Auditoría de Panificadora Nancy — OWASP A01:2025

**Informe de Prueba Sustantiva: Verificación de Controles de Acceso en Endpoints del Sistema – OWASP A01:2025**

Evaluación de caja negra realizada el **7 de octubre de 2026**, limitada a **GET sin autenticación** sobre `https://www.panificadoranancy.com`.

**Resultado: no concluyente para A01.** Las 15 rutas y los 2 controles devolvieron HTTP 200, `text/html` y el mismo cuerpo de 7.541 bytes tanto en Insomnia como en Python. La comparación es consistente con el fallback de la SPA. No se confirmó acceso indebido a datos privados ni se verificó la autorización de las APIs reales.

## Informe y descarga

| Entregable | Acceso |
| --- | --- |
| Informe único, 11 páginas y 6 capturas representativas | [PDF](informe/Informe_A01_Controles_Acceso_Nancy.pdf) |
| Informe editable | [Word](informe/Informe_A01_Controles_Acceso_Nancy.docx) |
| Resumen del informe | [Markdown](informe/Informe_A01_Controles_Acceso_Nancy.md) |
| Paquete completo | [Descargar ZIP](Entrega_A01_Nancy_2026-10-07.zip) |
| Resultados de las 15 rutas y 2 controles | [Tabla CSV](evidencias/tabla_resultados_A01.csv) |
| Evidencias gráficas | [51 capturas originales](capturas/) |
| Colección reutilizable con scripts | [Insomnia JSON](coleccion_insomnia/A01_Nancy_anonimo.insomnia.json) |

## Cobertura y evidencia

- **15 rutas evaluadas:** `/pedidos`, `/mis-pedidos`, `/admin`, `/admin/usuarios`, `/admin/clientes`, `/admin/productos`, `/admin/pedidos`, `/admin/categorias`, `/inventario`, `/inventario/materias-primas`, `/inventario/producciones`, `/inventario/movimientos-caja`, `/user`, `/me` y `/profile`.
- **2 controles:** raíz `/` y ruta de control diseñada como inexistente.
- **34 respuestas HTTP principales válidas:** 17 por herramienta.
- **51 capturas reales de Insomnia:** Preview en modo Source Code, Headers y Tests para cada solicitud.
- **68 aserciones de instrumentación aprobadas:** verifican el registro de las respuestas; **no certifican cumplimiento de A01**.

Las cabeceras salientes de las trazas verifican que no se enviaron `Authorization` ni `Cookie`. Las redirecciones y el envío/almacenamiento de cookies se desactivaron por solicitud; la validación TLS permaneció activada.

La huella SHA-256 común de los 34 cuerpos es:

```text
190646cf684af636c9eac7ea7ffbf2c76986f1d689146c6ff7fd15d8866584a7
```

Para revisar una prueba completa: **/mis-pedidos**, [Preview](capturas/A01-02_preview.png), [Headers](capturas/A01-02_headers.png), [Tests](capturas/A01-02_tests.png) y [traza HTTP](evidencias/insomnia/A01-02.timeline).

## Organización

| Carpeta o archivo | Contenido |
| --- | --- |
| [informe/](informe/) | PDF, Word y resumen Markdown del mismo informe |
| [capturas/](capturas/) | Imágenes sin edición e índice con URL, fecha, ID de respuesta y hashes |
| [evidencias/insomnia/](evidencias/insomnia/) | Solicitudes, respuestas, cuerpos, trazas y textos de la interfaz |
| [Lote Python válido](evidencias/python_20261007_002011/) | TXT, CSV, JSON y cuerpos de las 17 respuestas |
| [Intento inicial fallido](evidencias/python_20261007_001920/) | Incidencia DNS del entorno restringido, excluida de las 34 respuestas válidas |
| [coleccion_insomnia/](coleccion_insomnia/) | Colección sin credenciales, con Pre-request y After-response |
| [scripts/](scripts/) | Enumeración acotada, scripts de respuesta, capturas, generación y verificación |
| [MANIFIESTO_SHA256.txt](MANIFIESTO_SHA256.txt) | Huellas de integridad de los entregables |
| [LEEME.md](LEEME.md) | Instrucciones detalladas del paquete local |

## Uso de los archivos

No es necesario volver a consultar el sitio para leer el informe o las evidencias. La colección JSON se puede importar en Insomnia desde la opción de importación de archivos. El historial está conservado en `evidencias/insomnia/`; no se incluye en la colección importable.

Para usar los scripts, crear un entorno de Python e instalar las dependencias:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Verificar las evidencias y regenerar el manifiesto y el ZIP, sin peticiones al sitio:

```bash
.venv/bin/python scripts/verificar_entrega.py
```

Comprobar los hashes existentes sin regenerar archivos:

```bash
sha256sum -c MANIFIESTO_SHA256.txt
sha256sum -c Entrega_A01_Nancy_2026-10-07.zip.sha256
```

Repetir el lote externo **realiza 17 nuevos GET** y crea una carpeta de evidencias con fecha; ejecutarlo cuando corresponda repetir la prueba dentro del alcance autorizado:

```bash
.venv/bin/python scripts/a01_endpoints.py
```

El script `generar_informe.py` genera el Word y el resumen desde las evidencias. La conversión del Word a PDF utiliza LibreOffice. `insomnia_ui.py` documenta la automatización aplicada sobre el perfil local de auditoría mediante CDP; no es necesario para leer los entregables.

El perfil `.insomnia-a01` y el entorno `.venv` son archivos locales del equipo de ejecución y no se versionan. `abrir_insomnia_auditoria.sh` permite abrir ese perfil conservado en el equipo original; tras clonar este repositorio se debe importar la colección JSON.

## Próxima fase

Por el alcance acordado, quedaron pendientes la identificación y verificación de las APIs reales de datos, el acceso de un cliente a funciones administrativas y las pruebas IDOR/BOLA con dos cuentas propias y objetos de prueba conocidos. Este repositorio no presenta esas pruebas como ejecutadas.

## Referencias

El criterio de autorización se basa en [OWASP A01:2025 — Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/). Los scripts de registro usan las interfaces documentadas por [Kong — Scripts in Insomnia](https://developer.konghq.com/insomnia/scripts/).
