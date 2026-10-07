#!/usr/bin/env python3
import json
import time
from pathlib import Path
from a01_endpoints import ROOT, BASE, ENDPOINTS, CONTROL

stamp=int(time.time()*1000)
wid='wrk_a01nancy20261007'
resources=[{'_id':wid,'_type':'workspace','parentId':None,'name':'Auditoria Nancy — A01 anonimo',
            'description':'15 rutas + 2 controles. Solo GET sin autenticacion. Tests de instrumentacion, no de cumplimiento A01.',
            'scope':'collection','created':stamp,'modified':stamp},
           {'_id':'env_a01nancy20261007','_type':'environment','parentId':wid,'name':'Base Environment','data':{},'dataPropertyOrder':None,'color':None,'isPrivate':False,'metaSortKey':stamp}]
cases=[('CTRL-01','/'),('CTRL-02',CONTROL)]+[(f'A01-{i:02}',p) for i,p in enumerate(ENDPOINTS,1)]
for i,(cid,endpoint) in enumerate(cases):
    resources.append({'_id':'req_a01nancy_'+cid.lower().replace('-',''),'_type':'request','parentId':wid,
                      'name':cid+' '+endpoint,'description':'GET anonimo. Sin cookies, Authorization ni redirecciones. El HTTP 200 HTML no confirma acceso a datos.',
                      'url':BASE+endpoint,'method':'GET','body':{},'authentication':{},
                      'headers':[{'name':'Accept','value':'*/*'},{'name':'Accept-Encoding','value':'identity'}],
                      'parameters':[],'pathParameters':[],'metaSortKey':i,'isPrivate':False,
                      'settingStoreCookies':False,'settingSendCookies':False,'settingFollowRedirects':'off',
                      'settingDisableRenderRequestBody':False,'settingEncodeUrl':True,'settingRebuildPath':True,
                      'preRequestScript':(ROOT/'scripts/pre_request_anonimo.js').read_text(),
                      'afterResponseScript':(ROOT/'scripts/after_response_a01.js').read_text(),
                      'created':stamp,'modified':stamp})
collection={'_type':'export','__export_format':4,'__export_date':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            '__export_source':'auditoria-a01-nancy','resources':resources}
path=ROOT/'coleccion_insomnia/A01_Nancy_anonimo.insomnia.json'
path.write_text(json.dumps(collection,indent=2,ensure_ascii=False)+'\n')
print(path)
