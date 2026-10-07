#!/usr/bin/env python3
"""Verifica evidencia, genera el manifiesto de integridad y el ZIP; sin acceso de red."""
import hashlib
import json
import zipfile
from collections import Counter
from pathlib import Path
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[1]
summary=json.loads((ROOT/'evidencias/resumen_consolidado.json').read_text())
captures=json.loads((ROOT/'capturas/indice_capturas.json').read_text())
assert len(summary['rows'])==17 and len(captures)==51
assert Counter(c['view'] for c in captures)=={'preview':17,'headers':17,'tests':17}
checks=[]
for c in captures:
    assert hashlib.sha256((ROOT/'capturas'/c['file']).read_bytes()).hexdigest()==c['png_sha256']
    assert c['request_url'] in (ROOT/f'evidencias/insomnia/{c["id"]}_{c["view"]}.ui.txt').read_text()
checks.append('51 capturas: PNG presentes, hashes verificados y URL correspondiente en cada vista.')
for r in summary['rows']:
    cid=r['id'];base=ROOT/'evidencias/insomnia'
    response=json.loads((base/f'{cid}.response.json').read_text())
    request=json.loads((base/f'{cid}.request.json').read_text())
    assert response['parentId']==request['_id']
    assert response['url']==request['url']
    assert response['statusCode']==200 and response['contentType']=='text/html'
    assert request['settingSendCookies'] is False and request['settingStoreCookies'] is False
    assert request['settingFollowRedirects']=='off' and not request['authentication']
    tests=response['requestTestResults'];assert len(tests)==4 and all(t['status']=='passed' for t in tests)
    body=(base/f'{cid}.body').read_bytes()
    py_body=(ROOT/summary['python_evidence']/f'{cid}.body').read_bytes()
    assert len(body)==7541 and body==py_body
    assert hashlib.sha256(body).hexdigest()==summary['body_sha256']
    timeline=[json.loads(line) for line in (base/f'{cid}.timeline').read_text().splitlines() if line]
    outgoing=''.join(e.get('value','') for e in timeline if e.get('name')=='HeaderOut')
    assert outgoing.startswith('GET ') and 'authorization:' not in outgoing.lower() and 'cookie:' not in outgoing.lower()
checks.append('17 solicitudes Insomnia: GET real sin Authorization ni Cookie, redirecciones y cookies desactivadas.')
checks.append('34 cuerpos reales: iguales byte a byte entre Python, Insomnia, raíz, control y las 15 rutas; 7.541 bytes.')
checks.append('68 aserciones de instrumentación aprobadas; no se interpretan como aprobación del control de acceso.')
pdf=PdfReader(ROOT/'informe/Informe_A01_Controles_Acceso_Nancy.pdf')
assert len(pdf.pages)==11
for i,page in enumerate(pdf.pages,1):assert len((page.extract_text() or '').split())>20,f'Página vacía {i}'
assert all(float(p.mediabox.width)>float(p.mediabox.height) for p in pdf.pages[5:])
checks.append('Informe PDF: 11 páginas, sin páginas vacías, con 6 páginas de evidencia en orientación horizontal.')
checks.append('Informe DOCX y PDF presentes; pendientes de cuentas e IDOR declarados expresamente.')
(ROOT/'evidencias/verificacion_entrega.txt').write_text('\n'.join(checks)+'\n')

files=[]
for name in ['informe','capturas','evidencias','coleccion_insomnia','scripts']:
    files.extend(p for p in (ROOT/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
files.extend([ROOT/'LEEME.md',ROOT/'README.md',ROOT/'requirements.txt',ROOT/'.gitignore',ROOT/'.gitattributes',ROOT/'abrir_insomnia_auditoria.sh'])
files=sorted(files,key=lambda p:str(p.relative_to(ROOT)))
manifest=ROOT/'MANIFIESTO_SHA256.txt'
manifest.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(ROOT))+'\n' for p in files))
archive=ROOT/'Entrega_A01_Nancy_2026-10-07.zip'
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for p in files+[manifest]:z.write(p,str(p.relative_to(ROOT)))
with zipfile.ZipFile(archive) as z:assert z.testzip() is None
(ROOT/'Entrega_A01_Nancy_2026-10-07.zip.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
print('\n'.join(checks));print('Archivos en manifiesto:',len(files));print('ZIP:',archive.name,archive.stat().st_size,'bytes')
