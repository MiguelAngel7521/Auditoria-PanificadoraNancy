#!/usr/bin/env python3
"""Auditoría externa acotada: 15 rutas autorizadas + 2 controles, solo GET anónimo."""
import argparse
import csv
import hashlib
import json
import platform
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

BASE = "https://www.panificadoranancy.com"
ENDPOINTS = ["/pedidos", "/mis-pedidos", "/admin", "/admin/usuarios",
             "/admin/clientes", "/admin/productos", "/admin/pedidos", "/admin/categorias",
             "/inventario", "/inventario/materias-primas", "/inventario/producciones",
             "/inventario/movimientos-caja", "/user", "/me", "/profile"]
CONTROL = "/__a01_control_inexistente_20261007_7e6a12"
ROOT = Path(__file__).resolve().parents[1]


def now():
    return datetime.now(ZoneInfo("America/La_Paz")).isoformat(timespec="seconds")


def classify(status, html, same_shell):
    # Un 401/403 puede tener cuerpo HTML: el estado se interpreta primero.
    if status in (401, 403):
        return "Bloqueo HTTP observado; no valida otros roles ni métodos"
    if 300 <= status < 400:
        return "Redirección sin seguir; no concluyente"
    if status == 404:
        return "No encontrado u ocultado; no concluyente"
    if status == 405:
        return "GET no permitido; no concluyente"
    if 200 <= status < 300 and same_shell:
        return "HTML idéntico a raíz y control inexistente; no concluyente para A01"
    if 200 <= status < 300 and html:
        return "HTML; revisar contenido, no demuestra autorización"
    if 200 <= status < 300:
        return "REVISAR: éxito no HTML; confirmar sensibilidad y política de acceso"
    return "Error u otra respuesta; no concluyente"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    out = args.output or ROOT / "evidencias" / ("python_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    out.mkdir(parents=True, exist_ok=False)
    records = []
    cases = [("CTRL-01", "/"), ("CTRL-02", CONTROL)] + [(f"A01-{i:02}", p) for i, p in enumerate(ENDPOINTS, 1)]
    for case_id, endpoint in cases:
        record = {"id": case_id, "endpoint": endpoint, "url": BASE + endpoint,
                  "method": "GET", "identity": "Anónimo", "started_at": now(),
                  "redirects_followed": False, "tls_verify": True}
        try:
            # Sesión nueva por petición, sin .netrc, proxies heredados ni cookies persistentes.
            with requests.Session() as session:
                session.trust_env = False
                with session.get(BASE + endpoint, timeout=(10, 20), allow_redirects=False,
                                 headers={"User-Agent": "insomnia/13.3.0", "Accept": "*/*",
                                          "Accept-Encoding": "identity"}) as response:
                    body = response.content
                    ct = response.headers.get("Content-Type", "")
                    html = "text/html" in ct.lower() or body.lstrip()[:1000].lower().startswith((b"<!doctype html", b"<html"))
                    record.update(status=response.status_code, content_type=ct, body_bytes=len(body),
                                  sha256=hashlib.sha256(body).hexdigest(), is_html=html,
                                  elapsed_ms=round(response.elapsed.total_seconds()*1000),
                                  request_headers=dict(response.request.headers),
                                  response_headers={k: ("[omitido: cookie]" if k.lower()=="set-cookie" else v)
                                                    for k,v in response.headers.items()},
                                  body_file=f"{case_id}.body", completed_at=now())
                    assert not any(h.lower() in ("authorization", "cookie", "proxy-authorization") for h in response.request.headers)
                    (out / record["body_file"]).write_bytes(body)
        except requests.RequestException as error:
            record.update(error=str(error), completed_at=now())
        records.append(record)
        (out / f"{case_id}.json").write_text(json.dumps(record, indent=2, ensure_ascii=False)+"\n")
        print(case_id, endpoint, record.get("status", "ERROR"), record.get("content_type", ""), record.get("body_bytes", ""), flush=True)
        # Un error inicial de conectividad detiene el lote para no multiplicar fallos.
        if len(records) == 1 and "error" in record:
            break
        time.sleep(0.8)
    shell = records[0].get("sha256") if len(records)>1 and records[0].get("is_html") and records[0].get("sha256")==records[1].get("sha256") else None
    for record in records:
        record["same_as_root_and_nonexistent"] = bool(shell and record.get("sha256")==shell)
        record["classification"] = classify(record["status"],record["is_html"],record["same_as_root_and_nonexistent"]) if "status" in record else "Error de transporte; prueba no ejecutada correctamente"
        (out / f"{record['id']}.json").write_text(json.dumps(record, indent=2, ensure_ascii=False)+"\n")
    result = {"base": BASE, "tool": "Python Requests", "requests_version": requests.__version__,
              "python_version": platform.python_version(), "scope": "GET anónimo; sin redirecciones; 15 rutas y 2 controles",
              "completed_at": now(), "records": records}
    (out / "resultados.json").write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n")
    columns = ["id","endpoint","method","identity","status","content_type","body_bytes","sha256","same_as_root_and_nonexistent","classification","started_at"]
    with (out / "resultados.csv").open("w", newline="") as f:
        writer=csv.DictWriter(f,fieldnames=columns,extrasaction="ignore")
        writer.writeheader();writer.writerows(records)
    lines=["OWASP A01:2025 — Evidencia de ejecución real con Python Requests",f"Destino: {BASE}",f"Fecha: {now()}","GET anónimo; sin Authorization, Cookie o .netrc; redirecciones desactivadas; TLS validado.",""]
    for r in records:
        lines.append(f"{r['id']} | {r['endpoint']} | HTTP {r.get('status','ERROR')} | {r.get('content_type','')} | {r.get('body_bytes','')} bytes | {r['classification']}")
        lines.append(f"SHA-256: {r.get('sha256','—')}")
    (out / "evidencia_A01_endpoints.txt").write_text("\n".join(lines)+"\n")
    print("Evidencias:",out,flush=True)


if __name__ == "__main__":
    main()
