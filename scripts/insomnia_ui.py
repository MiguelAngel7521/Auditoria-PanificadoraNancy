#!/usr/bin/env python3
"""Control de UI del perfil Insomnia A01 por CDP local; no altera el DOM mostrado."""
import argparse
import json
import time
import hashlib
import re
import os
import signal
from zoneinfo import ZoneInfo
import urllib.request
from datetime import datetime
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('action',choices=['inspect','click','key','capture','run','close'])
parser.add_argument('value',nargs='?',default='')
parser.add_argument('--role',default='button')
parser.add_argument('--index',type=int,default=0)
args=parser.parse_args()

if args.action=='close':
    # Cierra exclusivamente el proceso de auditoría que abrió este trabajo.
    lock=ROOT/'.insomnia-a01/SingletonLock'
    if not lock.is_symlink():
        print('El perfil de auditoría ya está cerrado.')
        raise SystemExit(0)
    pid=int(lock.readlink().name.rsplit('-',1)[1])
    proc=Path(f'/proc/{pid}/cmdline')
    if not proc.exists():
        print('El proceso de auditoría ya finalizó.')
        raise SystemExit(0)
    args_raw=proc.read_bytes().split(b'\x00')
    assert ('--user-data-dir='+str(ROOT/'.insomnia-a01')).encode() in args_raw
    assert b'--remote-debugging-port=9335' in args_raw
    os.kill(pid,signal.SIGTERM)
    print('Cerrado el proceso del perfil de auditoría; datos y perfil habitual conservados.')
    raise SystemExit(0)

def db(name):
    records={}
    path=ROOT/'.insomnia-a01'/f'insomnia.{name}.db'
    if path.exists():
        for line in path.read_text().splitlines():
            try: value=json.loads(line)
            except ValueError: continue
            if '_id' in value:records[value['_id']]=value
    return [x for x in records.values() if not x.get('$$deleted')]

def latest(request_id):
    return max((r for r in db('Response') if r.get('parentId')==request_id),key=lambda r:r['created'],default=None)

with sync_playwright() as p:
    browser=p.chromium.connect_over_cdp('http://127.0.0.1:9335')
    pages=[page for c in browser.contexts for page in c.pages]
    if args.action=='inspect':
        with urllib.request.urlopen('http://127.0.0.1:9335/json/list') as response:
            print(json.dumps([{k:v for k,v in t.items() if k in ['id','type','title']} for t in json.load(response)],ensure_ascii=False))
        for page in pages:
            print('PAGE',page.url)
            print(page.locator('body').aria_snapshot()[-12000:])
        if not any('insomnia-app.local' in page.url for page in pages):
            raise SystemExit(0)
    page=next(page for page in pages if 'insomnia-app.local' in page.url)
    page.set_default_timeout(12000)
    if args.action=='run':
        page.keyboard.press('Escape')
        out=ROOT/'evidencias/insomnia'
        out.mkdir(exist_ok=True)
        capture_index=[]
        index_file=ROOT/'capturas/indice_capturas.json'
        if index_file.exists():capture_index=json.loads(index_file.read_text())
        requests=sorted(db('Request'),key=lambda r:r['metaSortKey'])
        if args.value:requests=[r for r in requests if r['name'].split()[0] in args.value.split(',')]
        for request in requests:
            assert request['method']=='GET' and request['url'].startswith('https://www.panificadoranancy.com/')
            assert not request['authentication'] and request['settingSendCookies'] is False and request['settingFollowRedirects']=='off'
            cid=request['name'].split()[0]
            if all(any(c['id']==cid and c['view']==mode for c in capture_index) for mode in ['preview','headers','tests']):
                print(cid,'ya capturado; sin reenviar',flush=True)
                continue
            page.get_by_role('row',name=request['name'],exact=True).click()
            page.wait_for_timeout(400)
            response=latest(request['_id'])
            if response is None:
                page.get_by_role('button',name='Send',exact=True).click()
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    response=latest(request['_id'])
                    if response and response.get('requestTestResults'):break
                    page.wait_for_timeout(200)
                if not response:raise RuntimeError('No response: '+cid)
            page.get_by_role('tab',name=re.compile('^Tests')).wait_for(timeout=15000)
            if not response.get('requestTestResults') or any(t['status']!='passed' for t in response['requestTestResults']):
                raise RuntimeError('Test instrumentation failed: '+cid)
            body=Path(response['bodyPath']).read_bytes()
            (out/f'{cid}.body').write_bytes(body)
            timeline=Path(response['timelinePath']).read_bytes()
            assert b'authorization:' not in timeline.lower() and b'cookie:' not in timeline.lower()
            (out/f'{cid}.timeline').write_bytes(timeline)
            (out/f'{cid}.response.json').write_text(json.dumps(response,ensure_ascii=False,indent=2)+'\n')
            (out/f'{cid}.request.json').write_text(json.dumps(request,ensure_ascii=False,indent=2)+'\n')
            page.get_by_role('tab',name='Auth',exact=True).click()
            page.get_by_role('tab',name='Preview',exact=True).click()
            preview_button=page.get_by_role('tabpanel',name='Preview').get_by_role('button').first
            preview_button.click()
            page.get_by_role('button',name=re.compile('Source Code$')).click()
            page.wait_for_timeout(300)
            for mode in ['preview','headers','tests']:
                if mode=='headers':page.get_by_role('tab',name=re.compile('^Headers')).last.click()
                if mode=='tests':page.get_by_role('tab',name=re.compile('^Tests')).click()
                page.wait_for_timeout(250)
                file=f'{cid}_{mode}.png'
                page.screenshot(path=str(ROOT/'capturas'/file))
                (out/f'{cid}_{mode}.ui.txt').write_text(page.locator('body').aria_snapshot())
                capture_index=[c for c in capture_index if c['file']!=file]
                capture_index.append({'id':cid,'file':file,'view':mode,'captured_at':datetime.now(ZoneInfo('America/La_Paz')).isoformat(timespec='seconds'),
                                      'request_url':request['url'],'request_id':request['_id'],'response_id':response['_id'],
                                      'response_created_ms':response['created'],'response_sha256':hashlib.sha256(body).hexdigest(),
                                      'png_sha256':hashlib.sha256((ROOT/'capturas'/file).read_bytes()).hexdigest(),
                                      'method':'Captura directa de la UI de Insomnia mediante Playwright/CDP; sin edición de imagen'})
                index_file.write_text(json.dumps(capture_index,ensure_ascii=False,indent=2)+'\n')
            print(cid,response['statusCode'],response['contentType'],len(body),'tests',len(response['requestTestResults']),'capturas=3',flush=True)
        raise SystemExit(0)
    if args.action=='click':
        page.get_by_role(args.role,name=args.value,exact=True).nth(args.index).click()
    elif args.action=='key':
        page.keyboard.press(args.value)
    elif args.action=='capture':
        name=args.value or 'insomnia'
        assert '/' not in name and '\\' not in name
        page.screenshot(path=str(ROOT/'capturas'/f'{name}.png'))
    time.sleep(.6)
    print('URL',page.url)
    print(page.locator('body').aria_snapshot()[-10000:])
