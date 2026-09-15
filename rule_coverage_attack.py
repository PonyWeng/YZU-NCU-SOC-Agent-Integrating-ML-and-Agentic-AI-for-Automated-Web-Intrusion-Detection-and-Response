"""Exercise every built-in detection rule against local demo services only."""
import argparse
import concurrent.futures
import json
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

import requests

SERVICES=('http://127.0.0.1','http://127.0.0.1:8081','http://127.0.0.1:8082')
SIEM='http://127.0.0.1:8000/api'
HEADERS={'X-SIEM-Request':'dashboard','Content-Type':'application/json'}

CASES={
  'SQLI':'198.51.100.121','XSS':'198.51.100.122','TRAVERSAL':'198.51.100.123',
  'FLOOD':'198.51.100.124','MULTI_SERVICE':'198.51.100.125','PATH_SCAN':'198.51.100.126',
  '404_SCAN':'198.51.100.127','SERVER_ERROR':'198.51.100.128','METHOD':'198.51.100.129',
  'SENSITIVE':'198.51.100.130','TOOL_UA':'198.51.100.131','MULTI_ATTACK':'198.51.100.132',
  'INTEL':'198.51.100.133','DUAL_DETECTOR':'198.51.100.134'}

def request(base,path='/',ip=None,method='GET',ua='Mozilla/5.0 NCU-PDCLAB rule coverage'):
    headers={'User-Agent':ua}
    if ip: headers.update({'X-Real-IP':ip,'X-Demo-Source-IP':ip})
    try:
        return requests.request(method,base+path,headers=headers,timeout=8,allow_redirects=False).status_code
    except requests.RequestException as exc:
        print(f'  ERROR {base}{path}: {exc}')
        return 0

def burst(base,path,ip,count,workers=24,method='GET',ua=None):
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        statuses=list(pool.map(lambda _:request(base,path,ip,method,ua or 'Mozilla/5.0 rule-coverage'),range(count)))
    print(f'  {ip}: {count} requests, HTTP {sorted(set(statuses))}')

def attack_path(payload): return '/search?q='+quote(payload,safe='')

def main():
    args=argparse.ArgumentParser(description='Trigger all local SIEM demo rules')
    args.add_argument('--wait',type=int,default=12,help='Seconds to wait for collector evaluation')
    opts=args.parse_args(); started=datetime.now(timezone.utc).isoformat(timespec='seconds')
    print('NCU-PDCLAB mini SIEM — rule coverage test')
    for base in SERVICES:
        if request(base,'/health') == 0: raise SystemExit(f'Service unavailable: {base}')

    print('[1/9] ML classes and WAF/ML correlation')
    request(SERVICES[0],attack_path("' OR 1=1--"),CASES['SQLI'])
    request(SERVICES[1],attack_path('<iframe src="javascript:alert(\'XSS\')">'),CASES['XSS'])
    request(SERVICES[2],attack_path('../../../etc/passwd'),CASES['TRAVERSAL'])
    request(SERVICES[0],attack_path("' UNION SELECT password FROM users--"),CASES['DUAL_DETECTOR'])

    print('[2/9] 300-request burst (50/min, 300/5min, 100/10sec)')
    burst(SERVICES[1],'/search?q=load-test',CASES['FLOOD'],300,32)
    print('[3/9] Same source across three protected services')
    for base in SERVICES: request(base,attack_path("' OR 1=1-- multi-service"),CASES['MULTI_SERVICE'])
    print('[4/9] 30 distinct paths')
    for i in range(30): request(SERVICES[2],f'/scan-{i}?coverage=path',CASES['PATH_SCAN'])
    print('[5/9] 30 requests with at least 70% HTTP 404')
    for i in range(30): request(SERVICES[1],f'/missing-{i}',CASES['404_SCAN'])
    print('[6/9] 10 server errors')
    for _ in range(10): request(SERVICES[1],'/demo-error',CASES['SERVER_ERROR'])
    print('[7/9] Suspicious method, sensitive path, and scanner User-Agent')
    request(SERVICES[0],'/',CASES['METHOD'],'TRACE')
    request(SERVICES[1],'/.env',CASES['SENSITIVE'])
    request(SERVICES[2],'/search?q=inventory',CASES['TOOL_UA'],ua='sqlmap/1.8 demo')
    print('[8/9] Multiple attack types from one source')
    request(SERVICES[0],attack_path("' OR 1=1--"),CASES['MULTI_ATTACK'])
    request(SERVICES[0],attack_path('<svg/onload=alert(1)>'),CASES['MULTI_ATTACK'])
    print('[9/9] Threat-intelligence source hit')
    intel={'kind':'ip','value':CASES['INTEL'],'source':'rule-coverage-test','confidence':95,
           'verdict':'malicious','tags':['demo','coverage'],'notes':'Local rule coverage test'}
    response=requests.post(SIEM+'/intel',headers=HEADERS,data=json.dumps(intel),timeout=5)
    if response.status_code not in (200,409): response.raise_for_status()
    request(SERVICES[2],'/?coverage=intel',CASES['INTEL'])

    print(f'Waiting {opts.wait}s for collection and rule evaluation...')
    time.sleep(opts.wait)
    incidents=requests.get(SIEM+'/incidents?page=1',timeout=5).json()['items']
    relevant=[row for row in incidents if row['created_at']>=started or row['src_ip'] in CASES.values()]
    seen={row['rule_id'] for row in relevant}
    rules=requests.get(SIEM+'/rules',timeout=5).json()
    enabled=[r for r in rules if r['enabled']]
    print('\nCoverage result')
    for rule in enabled:
        mark='PASS' if rule['id'] in seen else 'MISS'
        print(f'  [{mark}] {rule["rule_uid"]} {rule["display_name"]}')
    print(f'Created/matched incidents: {len(relevant)}; coverage {len(seen)}/{len(enabled)}')
    if len(seen)<len(enabled): sys.exit(2)

if __name__=='__main__': main()
