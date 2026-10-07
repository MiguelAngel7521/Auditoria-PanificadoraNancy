// Instrumentación de evidencia; los tests aprobados NO certifican cumplimiento A01.
const status = Number(insomnia.response.code);
const contentType = (insomnia.response.headers.find(h => String(h.key).toLowerCase() === 'content-type')?.value || '').toLowerCase();
const body = insomnia.response.text();
const html = contentType.includes('text/html') || /^\s*(<!doctype\s+html|<html\b)/i.test(body);
const sha256 = require('crypto-js').SHA256(body).toString();
let result = 'Otra respuesta; no concluyente';
if (status === 401) result = 'Bloqueo HTTP: no autenticado';
else if (status === 403) result = 'Bloqueo HTTP: acceso denegado';
else if (status >= 300 && status < 400) result = 'Redireccion sin seguir; no concluyente';
else if (status === 404) result = 'No encontrado u ocultado; no concluyente';
else if (status === 405) result = 'GET no permitido; no concluyente';
else if (status >= 200 && status < 300 && html) result = 'HTML: comparar con controles; no concluyente para A01';
else if (status >= 200 && status < 300) result = 'REVISAR: exito no HTML; validar sensibilidad y permisos';

console.log('A01 EVIDENCIA', JSON.stringify({fecha: new Date().toISOString(), status, contentType, caracteres: body.length, html, sha256, result}));
insomnia.test('Instrumentacion: estado HTTP final valido (no certifica A01)', () => {
  insomnia.expect(Number.isInteger(status) && status >= 200 && status <= 599).to.eql(true);
});
insomnia.test('Instrumentacion: Content-Type recibido', () => {
  insomnia.expect(contentType.length).to.be.above(0);
});
insomnia.test('Instrumentacion: cuerpo recibido y huella SHA-256 calculada', () => {
  insomnia.expect(body.length).to.be.above(0);
  insomnia.expect(sha256).to.match(/^[a-f0-9]{64}$/);
});
insomnia.test('Observacion: ' + result, () => {
  insomnia.expect(result).to.be.a('string');
});
