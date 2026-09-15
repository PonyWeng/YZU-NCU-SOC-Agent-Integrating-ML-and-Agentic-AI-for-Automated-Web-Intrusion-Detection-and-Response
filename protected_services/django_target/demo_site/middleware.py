from datetime import datetime, timezone
import json, os

class AccessLogMiddleware:
    def __init__(self, get_response): self.get_response=get_response
    def __call__(self, request):
        response=self.get_response(request)
        # Lab-only simulated source; this demo is not a production proxy policy.
        record={'timestamp':datetime.now(timezone.utc).isoformat(),'src_ip':request.META.get('HTTP_X_DEMO_SOURCE_IP') or request.META.get('HTTP_X_FORWARDED_FOR',request.META.get('REMOTE_ADDR')),
                'method':request.method,'path':request.get_full_path(),'status':response.status_code,
                'dst_ip':request.get_host().split(':')[0], 'service':'django-target','port':8082,
                'http_version':request.META.get('SERVER_PROTOCOL','HTTP/1.1'),
                'response_bytes':len(response.content) if hasattr(response,'content') else 0,
                'referer':request.META.get('HTTP_REFERER',''),'user_agent':request.META.get('HTTP_USER_AGENT','')}
        path='/logs/access.jsonl'; os.makedirs(os.path.dirname(path),exist_ok=True)
        with open(path,'a',encoding='utf-8') as f: f.write(json.dumps(record)+'\n')
        return response
