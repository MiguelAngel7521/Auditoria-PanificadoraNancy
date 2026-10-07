# Auditoría A01 — Panificadora Nancy

Fase finalizada: **acceso anónimo**, conforme a la aclaración del usuario.

**Resultado: no concluyente para A01.** Las 15 rutas, la raíz y una ruta de control inexistente devolvieron el mismo HTML de 7.541 bytes en Insomnia y Python. No se confirmó acceso a datos privados; tampoco se verificó la autorización de las APIs reales.

## Entregables

- `informe/Informe_A01_Controles_Acceso_Nancy.pdf`: informe único listo para leer, con seis capturas representativas.
- `informe/Informe_A01_Controles_Acceso_Nancy.docx`: el mismo informe editable.
- `capturas/`: **51 capturas originales de Insomnia**: Preview (Source Code), Headers y Tests de cada una de las 17 solicitudes.
- `capturas/indice_capturas.json`: correspondencia de capturas, URLs, fechas, IDs de respuesta y hashes.
- `evidencias/tabla_resultados_A01.csv`: tabla final de las 15 rutas y 2 controles.
- `evidencias/insomnia/`: solicitudes, respuestas, cuerpos y timelines de las 17 pruebas reales.
- `evidencias/python_20261007_002011/`: lote Python válido con TXT, CSV y JSON.
- `evidencias/python_20261007_001920/`: primer intento fallido por resolución DNS del entorno restringido; no se cuenta como respuesta del servidor.
- `coleccion_insomnia/A01_Nancy_anonimo.insomnia.json`: colección reutilizable, sin secretos, con scripts.
- `MANIFIESTO_SHA256.txt`: huellas de integridad de los entregables.
- `Entrega_A01_Nancy_2026-10-07.zip`: copia transportable de informes, capturas, evidencias, colección y scripts. Excluye el entorno Python y el perfil local de Insomnia; la colección puede importarse en otro equipo.

Los 4/4 tests de cada solicitud verifican la instrumentación y el registro de la respuesta. **No acreditan que el control de acceso cumpla.** El informe distingue explícitamente esta limitación.

## Revisar la sesión de Insomnia

Desde esta carpeta:

```bash
bash abrir_insomnia_auditoria.sh
```

En el equipo original, se abre el perfil local de auditoría, conservado en `.insomnia-a01`, con las 17 solicitudes y respuestas en Scratch Pad. El perfil no se incluye en el ZIP ni en GitHub; al descargar el paquete o clonar el repositorio, importar la colección JSON. Las solicitudes originales del perfil habitual se conservaron. La pestaña Auth hereda un padre sin credenciales; los timelines verifican que no se envió Authorization ni Cookie. Cada petición tiene desactivados el envío/almacenamiento de cookies y las redirecciones.

También puedes importar `coleccion_insomnia/A01_Nancy_anonimo.insomnia.json` desde las opciones de importación de archivos de Insomnia. El archivo contiene los scripts; la colección importada no incluye el historial de respuestas. No hace falta volver a enviar solicitudes para revisar las evidencias ya conservadas.

## Repetir el lote externo

Si se trabaja en otro equipo, preparar las dependencias:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

```bash
.venv/bin/python scripts/a01_endpoints.py
```

Esto sí hace 17 nuevos GET anónimos al sitio, espaciados y sin seguir redirecciones, y crea otra carpeta de evidencias con fecha. Requiere acceso de red. `scripts/preparar_coleccion.py` regenera la colección y `scripts/generar_informe.py` genera el DOCX a partir de los archivos existentes.

La automatización `scripts/insomnia_ui.py` fue usada contra el puerto de depuración local de un perfil separado. No es necesaria para leer el informe ni para abrir la colección normalmente.

## Pendiente para una segunda fase

Por la instrucción «Continuar por ahora solo con acceso anónimo», no se ejecutaron pruebas con cuentas, escalamiento vertical ni IDOR/BOLA. Será necesario identificar las APIs reales y disponer de dos cuentas propias con objetos de prueba conocidos para ampliar el mismo informe.

El informe anterior `Informe de Prueba_ Control de Acceso Basado en Roles.docx` se preservó sin cambios y no se incorporó como evidencia del sitio Nancy.
