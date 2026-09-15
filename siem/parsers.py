"""Access-log parsers which normalize web server records before ML inference."""
import json, re
from datetime import datetime, timezone

APACHE = re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "(.*?)" (\d{3}) (\S+)(?: "(.*?)" "(.*?)")?')

def _ts(value):
    if not value: return datetime.now(timezone.utc).isoformat(timespec='seconds')
    try: return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc).isoformat(timespec='seconds')
    except ValueError: pass
    for pattern in ('%d/%b/%Y:%H:%M:%S %z','%d/%b/%Y:%H:%M:%S.%f %z'):
        try: return datetime.strptime(value,pattern).astimezone(timezone.utc).isoformat(timespec='seconds')
        except ValueError: pass
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def parse(raw, fmt='apache_combined', service_name='apache', host='127.0.0.1', port=80):
    """Return a stable request record or None for an incomplete/unsupported line."""
    if fmt == 'modsecurity_json':
        try: obj=json.loads(raw); tx=obj['transaction']
        except (TypeError,json.JSONDecodeError,KeyError): return None
        request=obj.get('request') or tx.get('request') or {}; response=obj.get('response') or tx.get('response') or {}
        messages=(obj.get('audit_data') or {}).get('messages') or tx.get('messages') or []
        rendered=[]
        for message in messages:
            if isinstance(message,str):
                rid=re.search(r'\[id "([^"]+)"\]',message); msg=re.search(r'\[msg "([^"]+)"\]',message)
                tags=re.findall(r'\[tag "([^"]+)"\]',message)
                rendered.append({'id':rid.group(1) if rid else 'CRS','message':msg.group(1) if msg else message,'tags':tags})
            else:
                details=message.get('details') or {}
                rendered.append({'id':details.get('ruleId') or details.get('rule_id') or 'CRS',
                                 'message':message.get('message','WAF rule matched'),'tags':details.get('tags') or []})
        text=' '.join(x['message'] for x in rendered).lower()+' '+' '.join(str(tag).lower() for x in rendered for tag in x['tags'])
        attack=1 if 'sqli' in text or 'sql injection' in text else 2 if 'xss' in text or 'cross-site scripting' in text else 3 if any(x in text for x in ('lfi','rfi','path traversal','directory traversal')) else 4
        summaries=[f"{x['id']}: {x['message']}" for x in rendered if x['id'] != '980170']
        if not summaries:
            return None
        headers=request.get('headers') or {}
        request_line=request.get('request_line','').split(' ',2)
        return {'timestamp':_ts(tx.get('time') or tx.get('time_stamp')), 'src_ip':headers.get('X-Demo-Source-IP') or headers.get('X-Real-IP') or tx.get('remote_address') or tx.get('client_ip','unknown'),
                'src_port':tx.get('remote_port') or tx.get('client_port'), 'dst_ip':host,
                'method':request.get('method') or (request_line[0] if request_line else ''),
                'url':request.get('uri') or (request_line[1] if len(request_line)>1 else '/'),
                'status':int(response.get('status') or response.get('http_code') or 0), 'target':service_name, 'host':host,
                'port':int(port), 'transport':'tcp', 'protocol':'http',
                'http_version':str(request.get('http_version') or response.get('protocol') or (request_line[2] if len(request_line)>2 else '')),
                'response_bytes':int(response.get('body_length') or response.get('headers',{}).get('Content-Length') or 0),
                'referer':headers.get('Referer',''), 'user_agent':headers.get('User-Agent',''),
                'parser_name':fmt, 'raw':raw, 'attack':attack,
                'description':' | '.join(summaries) or 'OWASP CRS rule matched'}
    if fmt in ('json','flask_json','django_json'):
        try: obj=json.loads(raw)
        except (TypeError,json.JSONDecodeError): return None
        return {'timestamp':_ts(obj.get('timestamp')), 'src_ip':obj.get('src_ip') or obj.get('remote_addr','unknown'),
                'src_port':obj.get('src_port'), 'dst_ip':obj.get('dst_ip') or host,
                'method':obj.get('method',''), 'url':obj.get('path') or obj.get('url','/'),
                'status':int(obj.get('status') or 0), 'target':service_name, 'host':host, 'port':int(obj.get('port') or port),
                'transport':'tcp', 'protocol':'http', 'http_version':obj.get('http_version','HTTP/1.1'),
                'response_bytes':int(obj.get('response_bytes') or 0), 'referer':obj.get('referer',''),
                'user_agent':obj.get('user_agent',''), 'parser_name':fmt, 'raw':raw}
    m=APACHE.match(raw)
    if not m: return None
    request=m.group(3).split(' ',2)
    return {'timestamp':_ts(m.group(2)), 'src_ip':m.group(1), 'src_port':None, 'dst_ip':host,
            'method':request[0] if request else '',
            'url':request[1] if len(request)>1 else '/', 'status':int(m.group(4)),
            'target':service_name, 'host':host, 'port':int(port), 'transport':'tcp','protocol':'http',
            'http_version':request[2] if len(request)>2 else '',
            'response_bytes':0 if m.group(5)=='-' else int(m.group(5)), 'referer':m.group(6) or '',
            'user_agent':m.group(7) or '', 'parser_name':fmt, 'raw':raw}
