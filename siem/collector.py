"""Batch inference with stable event IDs and transactional file checkpoints."""
import hashlib
import json
import os
import pickle
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_plus
from siem.parsers import parse

from siem import store

LOG = re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "(.*?)" (\d{3}) (\S+)(?: "(.*?)" "(.*?)")?')


def timestamp(raw, fallback=None):
    match = LOG.match(raw)
    if match:
        try:
            return datetime.strptime(match[2], '%d/%b/%Y:%H:%M:%S %z').astimezone(timezone.utc).isoformat(timespec='seconds')
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(fallback.replace('Z', '+00:00')).astimezone(timezone.utc).isoformat(timespec='seconds')
    except (ValueError, AttributeError):
        return store.now()


def normalize(record, origin='legacy-import'):
    raw = record.get('log_record', '')
    match = LOG.match(raw)
    request = record.get('URL', match[3] if match else '')
    parts = request.split(' ', 2)
    from config import PROTECTED_SERVER_SERVICE
    return {'id': str(record.get('id') or hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest()),
            'timestamp': timestamp(raw,record.get('@timestamp')), 'received_at': store.now(),
            'src_ip':record.get('src_ip') or (match[1] if match else 'unknown'),
            'target':record.get('service_name',PROTECTED_SERVER_SERVICE), 'method':parts[0] if len(parts)>1 else '',
            'url':parts[1] if len(parts)>1 else request, 'status':int(record.get('return_code') or 0),
            'attack':int(record.get('attack_prediction',-1)), 'description':record.get('description',''),
            'raw':raw, 'origin':origin, 'service_name':record.get('service_name',PROTECTED_SERVER_SERVICE),
            'service_host':record.get('service_host','127.0.0.1'),'service_port':int(record.get('service_port',80)),
            'src_port':record.get('src_port'),'dst_ip':record.get('dst_ip',record.get('service_host','127.0.0.1')),
            'transport':record.get('transport','tcp'),'protocol':record.get('protocol','http'),
            'http_version':record.get('http_version',''),'response_bytes':int(record.get('response_bytes') or 0),
            'referer':record.get('referer',''),'user_agent':record.get('user_agent',''),
            'parser_name':record.get('parser_name',origin)}


class Classifier:
    def __init__(self, path):
        # Only load the project's trusted local model.
        with open(path,'rb') as f:
            self.model = pickle.load(f)

    def event(self, raw, event_id, fmt='apache_combined', service_name=None, host='127.0.0.1', port=80):
        parsed = parse(raw,fmt,service_name or 'apache',host,port)
        # RelevantOnly can still write transactions such as backend 5xx responses
        # without a CRS message. They are valid audit JSON, but not WAF detections.
        if fmt == 'modsecurity_json' and not parsed:
            return None
        if fmt == 'modsecurity_json' and parsed:
            return normalize({'id':event_id,'log_record':raw,'attack_prediction':parsed['attack'],
                'return_code':parsed['status'],'description':parsed['description'],'service_name':parsed['target'],
                'service_host':parsed['host'],'service_port':parsed['port'],'src_ip':parsed['src_ip'],
                'src_port':parsed['src_port'],'dst_ip':parsed['dst_ip'],'transport':parsed['transport'],
                'protocol':parsed['protocol'],'http_version':parsed['http_version'],'response_bytes':parsed['response_bytes'],
                'referer':parsed['referer'],'user_agent':parsed['user_agent'],'parser_name':fmt,
                'URL':f"{parsed['method']} {parsed['url']} {parsed['http_version']}",'@timestamp':parsed['timestamp']},'modsecurity-crs')
        match = LOG.match(raw)
        code, description = -1, '無法解析 Apache 日誌'
        if parsed and (match is None or (match[5] == '-' or match[5].isdigit())):
            request = unquote_plus((parsed['method']+' '+parsed['url'])).replace(',', '_')
            size = 0 if not match or match[5] == '-' else int(match[5])
            special = "[$&+,:;=?@#|'<>.^*()%!-]"
            features = [len(request),len(request.split('&')),int(parsed['status']),size,
                        sum(c.isupper() for c in request),sum(c.islower() for c in request),
                        sum(c in special for c in request),request.count('/')]
            code = int(self.model.predict([features])[0])
            description = store.LABELS.get(code, '未知分類')
        result = normalize({'id':event_id,'log_record':raw,'attack_prediction':code,
                          'return_code':parsed['status'] if parsed else (match[4] if match else 0),'description':description}, fmt)
        if parsed:
            result.update({'timestamp':parsed['timestamp'],'src_ip':parsed['src_ip'],'target':parsed['target'],
                           'method':parsed['method'],'url':parsed['url'],'status':parsed['status'],
                           'service_name':parsed['target'],'service_host':parsed['host'],'service_port':parsed['port'],
                           'src_port':parsed['src_port'],'dst_ip':parsed['dst_ip'],'transport':parsed['transport'],
                           'protocol':parsed['protocol'],'http_version':parsed['http_version'],
                           'response_bytes':parsed['response_bytes'],'referer':parsed['referer'],
                           'user_agent':parsed['user_agent'],'parser_name':parsed['parser_name']})
        return result


def collect_once(path, classifier, service=None, batch_size=200):
    path = Path(path).resolve()
    key = 'cursor:'+str(path)
    old = store.get_state(key, {})
    with path.open('rb') as stream:
        stat = os.fstat(stream.fileno())
        identity = f'{stat.st_dev}:{stat.st_ino}'
        offset = old.get('offset',0)
        # A prefix fingerprint also detects truncate-and-regrow between polls.
        prefix_length = min(offset, 256)
        prefix = hashlib.sha256(stream.read(prefix_length)).hexdigest()
        rotated = (identity != old.get('identity') or stat.st_size < offset or
                   (old.get('prefix') and prefix != old['prefix']))
        if rotated:
            offset = 0
        generation = str(uuid.uuid4()) if rotated else old.get('generation',str(uuid.uuid4()))
        stream.seek(offset)
        events = []
        for _ in range(batch_size):
            start = stream.tell()
            line = stream.readline()
            if not line or not line.endswith(b'\n'):
                stream.seek(start)
                break
            event_id = hashlib.sha256(f'{path}:{generation}:{start}:'.encode()+line).hexdigest()
            event=classifier.event(line.decode('utf-8',errors='replace').rstrip(),event_id,
                (service or {}).get('format','apache_combined'),(service or {}).get('name'),
                (service or {}).get('host','127.0.0.1'),(service or {}).get('port',80))
            if event:
                events.append(event)
        end = stream.tell()
        stream.seek(0)
        prefix = hashlib.sha256(stream.read(min(end,256))).hexdigest()
    cursor = {'identity':identity,'offset':end,'generation':generation,'prefix':prefix}
    count = store.insert_events(events,key,cursor,evaluate=True)
    store.set_state('collector',{'status':'watching','heartbeat':store.now(),'path':str(path),'offset':end,'last_batch':count})
    return count


def import_legacy(path):
    with open(path,encoding='utf-8') as f:
        records = json.load(f)
    if not isinstance(records,list):
        raise ValueError('Expected a JSON array of prediction records')
    total = 0
    for i in range(0,len(records),200):
        total += store.insert_events([normalize(r) for r in records[i:i+200]])
    store.audit('import',f'{path}: {total} records','cli')
    return total


def start_at_end(path):
    """A newly configured collector follows new traffic, avoiding historical replay."""
    path = Path(path).resolve()
    key = 'cursor:'+str(path)
    if store.get_state(key) is not None:
        return
    with path.open('rb') as stream:
        stat = os.fstat(stream.fileno())
        end = stat.st_size
        # Keep an unfinished final line for the next batch.
        if end:
            stream.seek(max(0,end-65536))
            tail=stream.read()
            if not tail.endswith(b'\n'):
                last=tail.rfind(b'\n')
                end=max(0,stat.st_size-len(tail)+last+1) if last>=0 else 0
        stream.seek(0)
        prefix=hashlib.sha256(stream.read(min(end,256))).hexdigest()
    store.set_state(key,{'identity':f'{stat.st_dev}:{stat.st_ino}', 'offset':end,
                         'generation':str(uuid.uuid4()),'prefix':prefix})


def main():
    from config import MODEL_PATH
    store.init_db()
    classifier = Classifier(MODEL_PATH)
    initialized=set()
    while True:
        try:
            with store.connection() as db:
                configured=[dict(r) for r in db.execute('SELECT * FROM protected_services WHERE enabled=1 ORDER BY id')]
            services=[]
            for row in configured:
                services.append({'name':row['name'],'path':row['log_path'],'format':row['parser_format'],
                                 'host':row['host'],'port':row['port']})
                if row['waf_enabled'] and row['waf_log_path']:
                    services.append({'name':row['name'],'path':row['waf_log_path'],'format':'modsecurity_json',
                                     'host':row['host'],'port':row['port']})
            for service in services:
                path=Path(service['path'])
                if not path.is_absolute(): path=store.ROOT/path
                if not path.exists():
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.touch()
                key=str(path.resolve())
                if key not in initialized:
                    start_at_end(path);initialized.add(key)
                collect_once(path,classifier,service)
        except Exception as exc:
            store.set_state('collector',{'status':'error','heartbeat':store.now(),'error':str(exc)})
            print(f'[collector] {exc}',flush=True)
        time.sleep(1)


if __name__ == '__main__':
    main()
