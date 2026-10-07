# Informe de Prueba Sustantiva: Verificación de Controles de Acceso en Endpoints del Sistema – OWASP A01:2025

**Resultado: No concluyente para A01.**

Fase ejecutada: GET anónimo, caja negra. Fecha: 07/10/2026, America/La_Paz.

Las 15 rutas y los 2 controles devuelven HTTP 200, text/html, 7.541 bytes y el mismo cuerpo en Insomnia y Python. La respuesta es consistente con el fallback de la SPA. No se confirmó acceso indebido ni se certificó la autorización de la API.

SHA-256 común: `190646cf684af636c9eac7ea7ffbf2c76986f1d689146c6ff7fd15d8866584a7`.

34 respuestas principales válidas; 51 capturas originales; 68 aserciones de instrumentación aprobadas (no son pruebas de cumplimiento A01).

| ID | Endpoint | HTTP Python / Insomnia | Resultado |
|---|---|---|---|
| CTRL-01 | `/` | 200 / 200 | Control: HTML común |
| CTRL-02 | `/__a01_control_inexistente_20261007_7e6a12` | 200 / 200 | Control: HTML común |
| A01-01 | `/pedidos` | 200 / 200 | No concluyente / fallback SPA |
| A01-02 | `/mis-pedidos` | 200 / 200 | No concluyente / fallback SPA |
| A01-03 | `/admin` | 200 / 200 | No concluyente / fallback SPA |
| A01-04 | `/admin/usuarios` | 200 / 200 | No concluyente / fallback SPA |
| A01-05 | `/admin/clientes` | 200 / 200 | No concluyente / fallback SPA |
| A01-06 | `/admin/productos` | 200 / 200 | No concluyente / fallback SPA |
| A01-07 | `/admin/pedidos` | 200 / 200 | No concluyente / fallback SPA |
| A01-08 | `/admin/categorias` | 200 / 200 | No concluyente / fallback SPA |
| A01-09 | `/inventario` | 200 / 200 | No concluyente / fallback SPA |
| A01-10 | `/inventario/materias-primas` | 200 / 200 | No concluyente / fallback SPA |
| A01-11 | `/inventario/producciones` | 200 / 200 | No concluyente / fallback SPA |
| A01-12 | `/inventario/movimientos-caja` | 200 / 200 | No concluyente / fallback SPA |
| A01-13 | `/user` | 200 / 200 | No concluyente / fallback SPA |
| A01-14 | `/me` | 200 / 200 | No concluyente / fallback SPA |
| A01-15 | `/profile` | 200 / 200 | No concluyente / fallback SPA |

Pendientes por el alcance acordado: APIs reales de datos, cliente frente a funciones administrativas, IDOR/BOLA con dos cuentas propias y manipulación de IDs controlados.

El detalle completo, limitaciones y muestra de capturas se encuentran en el DOCX y PDF de este mismo informe.

Evidencia Python: `../evidencias/python_20261007_002011/`. Evidencia Insomnia: `../evidencias/insomnia/`. Capturas: `../capturas/`.

Criterio de autorización: [OWASP A01:2025](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/). Scripts de respuesta: [Kong Insomnia](https://developer.konghq.com/insomnia/scripts/).
