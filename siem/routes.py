import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from typing import Literal
from siem import store

router = APIRouter(prefix='/api')

SYSTEM_DEFAULTS = {
    'webhook': {'public_url':'','listen_host':'127.0.0.1','listen_port':8002,'auto_register':True},
    'proxy': {'type':'modsecurity-crs','enabled':True,'listen_host':'127.0.0.1','apache_port':80,'flask_port':8081,'django_port':8082,'mode':'detection_only'},
}

def system_settings_data():
    with store.connection() as db:
        result={}
        for key,default in SYSTEM_DEFAULTS.items():
            row=db.execute('SELECT value,updated_at,updated_by FROM system_settings WHERE key=?',(key,)).fetchone()
            result[key]=dict(default,**(json.loads(row['value']) if row else {}),**({'updated_at':row['updated_at'],'updated_by':row['updated_by']} if row else {}))
        state=store.get_state('line_webhook',{})
        result['webhook']['active_url']=state.get('url','')
        result['webhook']['active_status']=state.get('status','not_started')
        return result

@router.get('/settings')
def get_settings(request: Request):
    from siem.auth import require_admin
    require_admin(request)
    return system_settings_data()

class SystemSettings(BaseModel):
    webhook: dict
    proxy: dict

@router.put('/settings')
def save_settings(body: SystemSettings,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    webhook=dict(SYSTEM_DEFAULTS['webhook'],**body.webhook)
    proxy=dict(SYSTEM_DEFAULTS['proxy'],**body.proxy)
    if not 1024 <= int(webhook['listen_port']) <= 65535: raise HTTPException(422,'Webhook port 必須介於 1024 到 65535')
    for key in ('apache_port','flask_port','django_port'):
        if not 1 <= int(proxy[key]) <= 65535: raise HTTPException(422,'代理服務 port 不合法')
    with store.connection() as db:
        for key,value in (('webhook',webhook),('proxy',proxy)):
            db.execute('INSERT OR REPLACE INTO system_settings(key,value,updated_at,updated_by) VALUES (?,?,?,?)',
                       (key,json.dumps(value,ensure_ascii=False),store.now(),actor['username']))
        store.audit('settings.update','更新 Webhook 與反向代理／WAF 設定',actor=actor['username'],db=db)
    return system_settings_data()

class LoginBody(BaseModel):
    username: str=Field(min_length=1,max_length=64)
    password: str=Field(min_length=1,max_length=200)

@router.post('/auth/login')
def auth_login(body: LoginBody, request: Request, response: Response):
    from siem.auth import SESSION_COOKIE, SESSION_HOURS, login
    token,user=login(body.username,body.password,request.headers.get('user-agent',''))
    secure_cookie=os.getenv('SIEM_PUBLIC_ORIGIN','').startswith('https://')
    response.set_cookie(SESSION_COOKIE,token,max_age=SESSION_HOURS*3600,httponly=True,samesite='strict',secure=secure_cookie,path='/')
    return user

@router.post('/auth/logout')
def auth_logout(request: Request, response: Response):
    from siem.auth import SESSION_COOKIE, logout
    logout(request.cookies.get(SESSION_COOKIE));response.delete_cookie(SESSION_COOKIE,path='/')
    return {'ok':True}

@router.get('/auth/me')
def auth_me(request: Request):
    from siem.auth import current_user, public_user
    return public_user(current_user(request))

class OwnAccountUpdate(BaseModel):
    display_name: str=Field(min_length=1,max_length=100)
    current_password: str=Field('',max_length=200)
    new_password: str=Field('',max_length=200)

@router.put('/auth/account')
def auth_account(body: OwnAccountUpdate, request: Request, response: Response):
    from siem.auth import SESSION_COOKIE, current_user, update_own_account
    user=current_user(request)
    signed_out=update_own_account(user['id'],body.display_name,body.current_password,body.new_password)
    if signed_out: response.delete_cookie(SESSION_COOKIE,path='/')
    return {'ok':True,'signed_out':signed_out}

class UserCreate(BaseModel):
    username: str=Field(min_length=1,max_length=64)
    display_name: str=Field(min_length=1,max_length=100)
    password: str=Field(min_length=4,max_length=200)
    role: Literal['admin','analyst']='analyst'

class UserUpdate(BaseModel):
    display_name: str=Field(min_length=1,max_length=100)
    password: str=Field('',max_length=200)
    role: Literal['admin','analyst']
    enabled: bool=True

@router.get('/users')
def users(request: Request):
    from siem.auth import require_admin, public_user
    require_admin(request)
    with store.connection() as db: return [public_user(r) for r in db.execute('SELECT * FROM users ORDER BY id')]

@router.post('/users')
def add_user(body: UserCreate, request: Request):
    from siem.auth import create_user, require_admin
    actor=require_admin(request)
    return {'ok':True,'id':create_user(body.username,body.display_name,body.password,body.role,actor['username'])}

@router.put('/users/{user_id}')
def edit_user(user_id: int, body: UserUpdate, request: Request):
    from siem.auth import require_admin, update_user
    actor=require_admin(request)
    update_user(user_id,body.display_name,body.role,body.enabled,body.password,actor['username'],actor['id'])
    return {'ok':True}


def date_value(value):
    if not value:
        return ''
    try:
        parsed = datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc).isoformat(timespec='seconds')
    except ValueError:
        raise HTTPException(422,'時間須包含時區')


@router.get('/events')
def events(page: int=Query(1,ge=1), page_size: int=Query(50,ge=1,le=200),
           hours: float=Query(24,gt=0,le=8760), q: str=Query('',max_length=500),
           src_ip: str='', attack: int|None=Query(None,ge=-1,le=999),
           status: int|None=Query(None,ge=100,le=599), since: str='', until: str=''):
    since,until = date_value(since),date_value(until)
    if since and until and since > until:
        raise HTTPException(422,'開始時間必須早於結束時間')
    return store.list_events(page,page_size,hours=hours,q=q,src_ip=src_ip,attack=attack,status=status,since=since,until=until)


@router.get('/events/export')
def export(hours: float=Query(24,gt=0,le=8760),q: str='',src_ip: str='',attack: int|None=Query(None,ge=-1,le=999),
           status: int|None=Query(None,ge=100,le=599),since: str='',until: str=''):
    from fastapi.responses import StreamingResponse
    where,params = store.filters(hours=hours,q=q,src_ip=src_ip,attack=attack,status=status,since=date_value(since),until=date_value(until))
    def chunks():
        yield '\ufeff'
        fields = ['timestamp','src_ip','target','method','url','status','attack','description','raw']
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(fields)
        yield buffer.getvalue()
        with store.connection() as db:
            for row in db.execute('SELECT * FROM events WHERE '+where+' ORDER BY timestamp DESC',params):
                buffer.seek(0); buffer.truncate(0)
                values = [str(row[k]) for k in fields]
                writer.writerow(["'"+v if v.lstrip().startswith(('=','+','-','@')) or v.startswith(('\t','\r','\n')) else v for v in values])
                yield buffer.getvalue()
    return StreamingResponse(chunks(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="siem-events.csv"'})


@router.get('/events/{event_id}')
def event(event_id: str):
    with store.connection() as db:
        row = db.execute('SELECT * FROM events WHERE id=?',(event_id,)).fetchone()
        if not row:
            raise HTTPException(404,'找不到日誌')
        return dict(row)


@router.get('/overview')
def overview(hours: float=Query(24,gt=0,le=8760)):
    data = store.overview(hours)
    from assistant.enforcer import load_blacklist
    data['blocked'] = load_blacklist()['ips']
    data['collector'] = store.get_state('collector',{'status':'not_started'})
    return data

@router.get('/geo-map')
def geo_map(hours: float=Query(24,gt=0,le=8760)):
    where,params=store.filters(hours=hours)
    with store.connection() as db:
        points=[dict(r) for r in db.execute(
            'SELECT e.src_ip,g.country,g.country_code,g.city,g.latitude,g.longitude,count(*) total,coalesce(sum(e.attack>0),0) attacks '
            'FROM events e JOIN geo_ip_cache g ON g.ip=e.src_ip WHERE '+where.replace('timestamp','e.timestamp')+
            " AND g.status='ok' AND g.latitude IS NOT NULL GROUP BY e.src_ip ORDER BY attacks DESC,total DESC LIMIT 100",params)]
        countries=[dict(r) for r in db.execute(
            'SELECT g.country_code,g.country,count(*) total,coalesce(sum(e.attack>0),0) attacks '
            'FROM events e JOIN geo_ip_cache g ON g.ip=e.src_ip WHERE '+where.replace('timestamp','e.timestamp')+
            " GROUP BY g.country_code,g.country ORDER BY attacks DESC,total DESC",params)]
        pending=db.execute('SELECT count(DISTINCT e.src_ip) FROM events e LEFT JOIN geo_ip_cache g ON g.ip=e.src_ip WHERE '+where.replace('timestamp','e.timestamp')+' AND g.ip IS NULL',params).fetchone()[0]
    return {'points':points,'countries':countries,'pending':pending}


@router.get('/incidents')
def incidents(status: str='',page: int=Query(1,ge=1),hours: float=Query(24,gt=0,le=8760)):
    time_where,time_params=store.filters(hours=hours)
    recent=time_where.replace('timestamp','last_seen')
    if status in ('new','investigating'):
        where='status=?';params=[status]
    elif status:
        where='status=? AND '+recent;params=[status]+list(time_params)
    else:
        where="status IN ('new','investigating') OR (status NOT IN ('new','investigating') AND "+recent+')'
        params=list(time_params)
    with store.connection() as db:
        total = db.execute('SELECT count(*) FROM incidents WHERE '+where,params).fetchone()[0]
        rows = db.execute('SELECT * FROM incidents WHERE '+where+' ORDER BY id DESC LIMIT 50 OFFSET ?',params+[(page-1)*50]).fetchall()
        return {'total':total,'items':[dict(r) for r in rows]}


@router.get('/incidents/{incident_id}')
def incident(incident_id: int):
    with store.connection() as db:
        row = db.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
        if not row:
            raise HTTPException(404,'找不到事件')
        result = dict(row)
        ids = json.loads(result['evidence'])[:200]
        result['events'] = [dict(r) for r in db.execute('SELECT * FROM events WHERE id IN ('+','.join('?' for _ in ids)+') ORDER BY timestamp',ids)] if ids else []
        result['notifications'] = [dict(r) for r in db.execute('SELECT status,attempts,error FROM notifications WHERE incident_id=?',(incident_id,))]
        return result


class IncidentUpdate(BaseModel):
    status: Literal['new','investigating','resolved','false_positive']
    note: str=Field('',max_length=4000)


@router.patch('/incidents/{incident_id}')
def update_incident(incident_id: int,body: IncidentUpdate,request: Request):
    from siem.auth import current_user
    actor=current_user(request)
    with store.connection() as db:
        if not db.execute('UPDATE incidents SET status=?,note=?,handled_by=?,handled_at=? WHERE id=?',
                          (body.status,body.note,actor['username'],store.now(),incident_id)).rowcount:
            raise HTTPException(404,'找不到事件')
        store.audit('incident.update',f'#{incident_id}: {body.status}; {body.note}',actor=actor['username'],db=db)
    return {'ok':True}


@router.get('/rules')
def rules():
    with store.connection() as db:
        result=[]
        for row in db.execute('SELECT * FROM rules ORDER BY id'):
            item=dict(row);item['display_name']=store.rule_display_name(row);result.append(item)
        return result


RuleMetric = Literal['request_count','distinct_services','distinct_paths','status_404_ratio',
                     'server_error_count','suspicious_method','sensitive_path','suspicious_ua',
                     'multi_attack_types','intel_match','detector_correlation','attack_count']

class RuleUpdate(BaseModel):
    name: str|None=Field(None,min_length=2,max_length=100)
    description: str|None=Field(None,max_length=500)
    metric: RuleMetric|None=None
    threshold: int=Field(ge=1,le=10000)
    window_sec: int=Field(ge=10,le=86400)
    cooldown_sec: int=Field(ge=10,le=86400)
    severity: Literal['low','medium','high','critical']
    enabled: bool


@router.put('/rules/{rule_id}')
def update_rule(rule_id: int,body: RuleUpdate,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    with store.connection() as db:
        current=db.execute('SELECT * FROM rules WHERE id=?',(rule_id,)).fetchone()
        if not current:
            raise HTTPException(404,'找不到規則')
        db.execute('''UPDATE rules SET name=?,description=?,metric=?,threshold=?,window_sec=?,cooldown_sec=?,severity=?,enabled=? WHERE id=?''',
            (body.name or current['name'],body.description if body.description is not None else current['description'],
             body.metric or current['metric'],body.threshold,body.window_sec,body.cooldown_sec,body.severity,int(body.enabled),rule_id))
        store.audit('rule.update',f'#{rule_id}: {body.model_dump()}',actor=actor['username'],db=db)
    return {'ok':True}


class RuleCreate(BaseModel):
    name: str=Field(min_length=2,max_length=100)
    description: str=Field('',max_length=500)
    metric: RuleMetric
    threshold: int=Field(ge=1,le=10000)
    window_sec: int=Field(ge=10,le=86400)
    cooldown_sec: int=Field(ge=10,le=86400)
    severity: Literal['low','medium','high','critical']='high'
    enabled: bool=True


@router.post('/rules')
def create_rule(body: RuleCreate,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    if body.metric=='attack_count':
        raise HTTPException(422,'自訂規則請使用行為指標')
    with store.connection() as db:
        number=db.execute("SELECT coalesce(max(CAST(substr(rule_uid,5) AS INTEGER)),0)+1 FROM rules WHERE rule_uid LIKE 'USR-%'").fetchone()[0]
        uid=f'USR-{number:03d}'
        result=db.execute('''INSERT INTO rules(name,attack,threshold,window_sec,cooldown_sec,severity,enabled,rule_uid,rule_type,description,metric)
            VALUES (?,0,?,?,?,?,?,?, 'behavior',?,?)''',(body.name,body.threshold,body.window_sec,body.cooldown_sec,
            body.severity,int(body.enabled),uid,body.description,body.metric))
        store.audit('rule.create',f'{uid}: {body.model_dump()}',actor=actor['username'],db=db)
        return {'ok':True,'id':result.lastrowid,'rule_uid':uid}


@router.delete('/rules/{rule_id}')
def delete_rule(rule_id: int,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    with store.connection() as db:
        row=db.execute('SELECT rule_uid,rule_type FROM rules WHERE id=?',(rule_id,)).fetchone()
        if not row: raise HTTPException(404,'找不到規則')
        if row['rule_type']!='behavior': raise HTTPException(409,'系統關聯規則不能刪除，只能停用')
        if db.execute('SELECT 1 FROM incidents WHERE rule_id=? LIMIT 1',(rule_id,)).fetchone():
            raise HTTPException(409,'規則已有事件紀錄，請停用以保留稽核關聯')
        db.execute('DELETE FROM rules WHERE id=?',(rule_id,))
        store.audit('rule.delete',row['rule_uid'],actor=actor['username'],db=db)
    return {'ok':True}


ServiceKind = Literal['apache','flask','django','nginx','iis','other']
ParserFormat = Literal['apache_combined','flask_json','django_json']

class ServiceBody(BaseModel):
    name: str=Field(min_length=2,max_length=100)
    kind: ServiceKind='other'
    host: str=Field(min_length=1,max_length=255)
    port: int=Field(ge=1,le=65535)
    log_path: str=Field(min_length=1,max_length=500)
    parser_format: ParserFormat
    waf_enabled: bool=False
    waf_log_path: str=Field('',max_length=500)
    enabled: bool=True

def safe_log_path(value: str, required=True):
    if not value and not required: return ''
    path=(store.ROOT/value).resolve() if not __import__('pathlib').Path(value).is_absolute() else __import__('pathlib').Path(value).resolve()
    try: path.relative_to(store.ROOT)
    except ValueError: raise HTTPException(422,'Log 路徑必須位於專案目錄內')
    return str(path.relative_to(store.ROOT)).replace('\\','/')

@router.get('/protected-services')
def protected_services():
    with store.connection() as db:
        return [dict(r) for r in db.execute('SELECT * FROM protected_services ORDER BY id')]

@router.post('/protected-services')
def create_protected_service(body: ServiceBody,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    log_path=safe_log_path(body.log_path)
    waf_path=safe_log_path(body.waf_log_path,False)
    if body.waf_enabled and not waf_path: raise HTTPException(422,'啟用 WAF 時必須指定 WAF audit log')
    with store.connection() as db:
        number=db.execute("SELECT coalesce(max(CAST(substr(service_uid,5) AS INTEGER)),0)+1 FROM protected_services WHERE service_uid LIKE 'SVC-%'").fetchone()[0]
        uid=f'SVC-{number:03d}'
        result=db.execute('''INSERT INTO protected_services(service_uid,name,kind,host,port,log_path,parser_format,waf_enabled,waf_log_path,enabled,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',(uid,body.name,body.kind,body.host,body.port,log_path,body.parser_format,int(body.waf_enabled),waf_path,int(body.enabled),store.now(),store.now()))
        store.audit('service.create',f'{uid}: {body.name}',actor=actor['username'],db=db)
        return {'ok':True,'id':result.lastrowid,'service_uid':uid}

@router.put('/protected-services/{service_id}')
def update_protected_service(service_id: int,body: ServiceBody,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    log_path=safe_log_path(body.log_path);waf_path=safe_log_path(body.waf_log_path,False)
    if body.waf_enabled and not waf_path: raise HTTPException(422,'啟用 WAF 時必須指定 WAF audit log')
    with store.connection() as db:
        if not db.execute('''UPDATE protected_services SET name=?,kind=?,host=?,port=?,log_path=?,parser_format=?,waf_enabled=?,waf_log_path=?,enabled=?,updated_at=? WHERE id=?''',
          (body.name,body.kind,body.host,body.port,log_path,body.parser_format,int(body.waf_enabled),waf_path,int(body.enabled),store.now(),service_id)).rowcount:
            raise HTTPException(404,'找不到受保護服務')
        store.audit('service.update',f'#{service_id}: {body.name}',actor=actor['username'],db=db)
    return {'ok':True}

@router.delete('/protected-services/{service_id}')
def delete_protected_service(service_id: int,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    with store.connection() as db:
        row=db.execute('SELECT service_uid,name FROM protected_services WHERE id=?',(service_id,)).fetchone()
        if not row: raise HTTPException(404,'找不到受保護服務')
        db.execute('DELETE FROM protected_services WHERE id=?',(service_id,))
        store.audit('service.delete',f'{row["service_uid"]}: {row["name"]}',actor=actor['username'],db=db)
    return {'ok':True}


@router.get('/blacklist')
def blacklist():
    from assistant.enforcer import load_blacklist
    return load_blacklist()['ips']


class BanRequest(BaseModel):
    ip: str
    reason: str=Field('儀表板手動封鎖',min_length=1,max_length=500)
    scope: Literal['all','apache','flask','django']='all'


@router.post('/blacklist')
def ban(body: BanRequest,request: Request):
    from siem.auth import current_user
    actor=current_user(request)
    from assistant.enforcer import change_ban
    try:
        return change_ban(body.ip,True,body.reason,actor['username'],body.scope)
    except ValueError as exc:
        raise HTTPException(422,str(exc))


@router.delete('/blacklist/{ip}')
def unban(ip: str,request: Request,scope: Literal['all','apache','flask','django']='all'):
    from siem.auth import current_user
    actor=current_user(request)
    from assistant.enforcer import change_ban
    try:
        return change_ban(ip,False,'儀表板解除封鎖',actor['username'],scope)
    except ValueError as exc:
        raise HTTPException(422,str(exc))


@router.get('/audit')
def audit(request: Request):
    from siem.auth import require_admin
    require_admin(request)
    with store.connection() as db:
        return [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]

@router.get('/intel')
def intel(q: str='',kind: str='',verdict: str='',page: int=Query(1,ge=1),sort: str='last_seen'):
    from siem import intel as repository
    return repository.list_items(q,kind,verdict,page,sort=sort)

@router.get('/intel/feeds')
def intel_feeds(request: Request):
    from siem.auth import current_user
    current_user(request)
    from siem.feeds import status
    return status()

@router.post('/intel/sync')
def intel_sync(request: Request):
    from siem.auth import require_admin
    require_admin(request)
    from siem.feeds import sync_all
    return sync_all()

@router.delete('/intel/feed/{source}')
def delete_intel_feed(source: str,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    if source not in ('Tor Exit Nodes','FireHOL Level 1','manual'): raise HTTPException(422,'不支援的情資來源')
    with store.connection() as db:
        count=db.execute('DELETE FROM intelligence WHERE source=?',(source,)).rowcount
        store.audit('intel.purge',f'{source}: {count} 筆',actor=actor['username'],db=db)
    return {'ok':True,'deleted':count}

@router.post('/intel/sync/{source}')
def intel_sync_source(source: str,request: Request):
    from siem.auth import require_admin
    require_admin(request)
    from siem.feeds import sync_risk_ips
    if source=='all':
        from siem.feeds import sync_phishing, news
        risk_ips=sync_risk_ips()
        phishing_count=sync_phishing()
        news_rows=news(limit=20)
        return {'risk_ips':risk_ips,'phishing':{'ok':True,'count':phishing_count},'news':{'ok':True,'count':len(news_rows)}}
    if source=='risk-ips':
        return sync_risk_ips()
    if source=='phishing':
        from siem.feeds import sync_phishing
        try:
            return {'ok':True,'count': sync_phishing()}
        except Exception as exc:
            return {'ok':False,'count':0,'error':'外部釣魚清單目前無法連線，請檢查網路或稍後重試。'}
    if source in ('cisa','urlhaus'): raise HTTPException(410,'目前已停用 CVE／批次 URL 情資同步')
    raise HTTPException(422,'不支援的情資來源')

@router.get('/intel/summary')
def intel_summary(request: Request):
    from siem.auth import current_user
    current_user(request)
    with store.connection() as db:
        total=db.execute('SELECT count(*) FROM intelligence').fetchone()[0]
        malicious=db.execute("SELECT count(*) FROM intelligence WHERE verdict='malicious'").fetchone()[0]
        by_kind=[dict(r) for r in db.execute('SELECT kind,count(*) count FROM intelligence GROUP BY kind ORDER BY count DESC')]
        by_source=[dict(r) for r in db.execute('SELECT source,count(*) count FROM intelligence GROUP BY source ORDER BY count DESC')]
        recent=[dict(r) for r in db.execute('SELECT * FROM intelligence ORDER BY last_seen DESC LIMIT 8')]
        matched=db.execute('''SELECT count(DISTINCT i.id) FROM intelligence i JOIN events e
          ON i.kind='ip' AND i.value=e.src_ip WHERE i.verdict='malicious' ''').fetchone()[0]
    return {'total':total,'malicious':malicious,'matched_events':matched,'by_kind':by_kind,'by_source':by_source,'recent':recent}

@router.get('/intel/news')
def intel_news(request: Request):
    from siem.auth import current_user
    current_user(request)
    from siem.feeds import news
    page=max(1,int(request.query_params.get('page','1') or 1)); rows=news(limit=100); start=(page-1)*20
    return {'items':rows[start:start+20],'page':page,'total':len(rows),'pages':max(1,(len(rows)+19)//20)}

@router.post('/intel/sync/phishing')
def intel_sync_phishing(request: Request):
    from siem.auth import require_admin
    require_admin(request)
    from siem.feeds import sync_phishing
    return {'count': sync_phishing()}

@router.post('/intel/sync/all')
def intel_sync_all(request: Request):
    from siem.auth import require_admin
    require_admin(request)
    from siem.feeds import sync_risk_ips, sync_phishing, news
    result={'risk_ips':{},'phishing':{},'news':{}}
    try: result['risk_ips']=sync_risk_ips()
    except Exception as exc: result['risk_ips']={'ok':False,'error':str(exc)[:200]}
    try: result['phishing']={'ok':True,'count':sync_phishing()}
    except Exception as exc: result['phishing']={'ok':False,'count':0,'error':str(exc)[:200]}
    try: result['news']={'ok':bool(news(limit=20)),'count':len(news(limit=20))}
    except Exception as exc: result['news']={'ok':False,'count':0,'error':str(exc)[:200]}
    return result

class IntelRequest(BaseModel):
    kind: Literal['ip','domain','url','hash','vulnerability']
    value: str=Field(min_length=1,max_length=2048)
    source: str=Field('manual',max_length=100)
    confidence: int=Field(0,ge=0,le=100)
    verdict: Literal['unknown','benign','suspicious','malicious']='unknown'
    tags: list[str]=Field(default_factory=list)
    notes: str=Field('',max_length=2000)

@router.post('/intel')
def add_intel(body: IntelRequest,request: Request):
    from siem.auth import current_user
    actor=current_user(request)
    from siem import intel as repository
    try: return repository.upsert(**body.model_dump(),actor=actor['username'])
    except ValueError as exc: raise HTTPException(422,str(exc))

@router.delete('/intel/{item_id}')
def delete_intel(item_id: int,request: Request):
    from siem.auth import current_user
    actor=current_user(request)
    from siem import intel as repository
    try: repository.remove(item_id,actor=actor['username']); return {'ok':True}
    except ValueError as exc: raise HTTPException(404,str(exc))

@router.get('/chat/sessions')
def chat_sessions():
    with store.connection() as db:
        return [dict(r) for r in db.execute('SELECT * FROM chat_sessions ORDER BY updated_at DESC LIMIT 30')]

@router.post('/chat/sessions')
def new_chat():
    sid=str(uuid.uuid4()); ts=store.now()
    with store.connection() as db: db.execute('INSERT INTO chat_sessions(id,created_at,updated_at) VALUES (?,?,?)',(sid,ts,ts))
    return {'id':sid,'title':'新的對話','created_at':ts,'updated_at':ts}

@router.get('/ai/context')
def ai_context(hours: float=Query(1,gt=0,le=720)):
    from siem.security_context import suggestions
    return suggestions(hours)

class AISuggestionRequest(BaseModel):
    message: str=Field('',max_length=4000)
    answer: str=Field('',max_length=12000)
    hours: float=Field(1,gt=0,le=720)
    session_id: str=Field('',max_length=100)

@router.post('/ai/suggestions')
def ai_suggestions(body: AISuggestionRequest):
    from siem.security_context import followup_suggestions
    history=[]
    if body.session_id:
        with store.connection() as db:
            history=[dict(r) for r in db.execute('''SELECT role,content FROM chat_messages
                WHERE session_id=? ORDER BY id DESC LIMIT 12''',(body.session_id,)).fetchall()][::-1]
    return followup_suggestions(body.message,body.answer,body.hours,history)

@router.get('/chat/sessions/{session_id}')
def chat_history(session_id: str):
    with store.connection() as db:
        if not db.execute('SELECT 1 FROM chat_sessions WHERE id=?',(session_id,)).fetchone(): raise HTTPException(404,'找不到對話')
        return [dict(r) for r in db.execute('SELECT * FROM chat_messages WHERE session_id=? ORDER BY id',(session_id,))]

class ChatRequest(BaseModel):
    message: str=Field(min_length=1,max_length=4000)

class ChatTitle(BaseModel):
    title: str=Field(min_length=1,max_length=80)

@router.patch('/chat/sessions/{session_id}')
def rename_chat(session_id: str, body: ChatTitle,request: Request):
    from siem.auth import current_user
    actor=current_user(request)
    title=body.title.strip()
    if not title: raise HTTPException(422,'名稱不可空白')
    with store.connection() as db:
        if not db.execute('UPDATE chat_sessions SET title=? WHERE id=?',(title,session_id)).rowcount:
            raise HTTPException(404,'找不到對話')
        store.audit('chat.rename',f'session={session_id}; title={title}',actor=actor['username'],db=db)
    return {'id':session_id,'title':title}

@router.delete('/chat/sessions/{session_id}')
def delete_chat(session_id: str,request: Request):
    from siem.auth import current_user
    actor=current_user(request)
    with store.connection() as db:
        if not db.execute('DELETE FROM chat_sessions WHERE id=?',(session_id,)).rowcount:
            raise HTTPException(404,'找不到對話')
        store.audit('chat.delete',f'session={session_id}',actor=actor['username'],db=db)
    return {'ok':True}

@router.post('/chat/sessions/{session_id}/messages')
async def chat_message(session_id: str,body: ChatRequest,request: Request):
    from siem.auth import current_user
    actor=current_user(request)
    from starlette.concurrency import run_in_threadpool
    with store.connection() as db:
        if not db.execute('SELECT 1 FROM chat_sessions WHERE id=?',(session_id,)).fetchone(): raise HTTPException(404,'找不到對話')
        db.execute('INSERT INTO chat_messages(session_id,role,content,created_at) VALUES (?,?,?,?)',(session_id,'user',body.message,store.now()))
        history=[{'role':r['role'],'content':r['content']} for r in db.execute(
            'SELECT role,content FROM chat_messages WHERE session_id=? ORDER BY id DESC LIMIT 8',(session_id,)).fetchall()][::-1]
    try:
        from ai_gateway import run
        response=await run_in_threadpool(run,body.message,history[:-1])
    except Exception as exc:
        detail=str(exc)
        if '10013' in detail or '10061' in detail or 'Connection' in detail:
            response='AI Provider 目前無法連線，請檢查 Windows 防火牆、Proxy 或網路權限。'
        elif '429' in detail or 'Too Many Requests' in detail:
            response='AI Provider 已達目前 API 配額或速率限制，請稍後再試，或在 Google AI Studio 為此 key 設定計費／提高配額。'
        elif '503' in detail or 'Service Unavailable' in detail or 'UNAVAILABLE' in detail:
            response='Gemini 服務目前暫時忙碌，系統已重試但仍無法完成回覆；這不是 API key 或用量問題，請稍後再送一次。'
        elif '401' in detail or '403' in detail:
            response='AI Provider 拒絕目前的 API key，請重新設定 key。'
        else:
            response='AI 助理暫時無法回應，請檢查 Provider、model ID 與 API key。'
    with store.connection() as db:
        db.execute('INSERT INTO chat_messages(session_id,role,content,created_at) VALUES (?,?,?,?)',(session_id,'assistant',response,store.now()))
        db.execute('UPDATE chat_sessions SET updated_at=? WHERE id=?',(store.now(),session_id))
        store.audit('ai.chat',f'session={session_id}; context response generated',actor=actor['username'],db=db)
    return {'role':'assistant','content':response}

@router.get('/ai/settings')
def ai_settings():
    from ai_gateway import settings
    return settings()

class AISettings(BaseModel):
    provider: Literal['gemini','openai']
    model: str=Field(min_length=1,max_length=150)
    api_key: str=Field('',max_length=500)

@router.put('/ai/settings')
def save_ai_settings(body: AISettings,request: Request):
    from siem.auth import require_admin
    actor=require_admin(request)
    from ai_gateway import save
    try:
        result=save(body.provider,body.model,body.api_key)
        store.audit('settings.ai',f'{body.provider}/{body.model}',actor=actor['username'])
        return result
    except ValueError as exc: raise HTTPException(422,str(exc))

@router.post('/ai/test')
async def test_ai(request: Request):
    from siem.auth import require_admin
    require_admin(request)
    from starlette.concurrency import run_in_threadpool
    from ai_gateway import run
    try: return {'ok':True,'reply':await run_in_threadpool(run,'請用一句話回報目前 SIEM 總事件數。',[])}
    except Exception as exc:
        # Never return provider URLs or API-key-bearing exception text to the UI.
        detail = str(exc)
        if '10013' in detail or '10061' in detail or 'Connection' in detail:
            detail = '本機無法連線到外部 AI Provider，請檢查網路、防火牆或 Proxy 設定。'
        elif '429' in detail or 'Too Many Requests' in detail:
            detail = 'AI Provider 已達目前 API 配額或速率限制，請稍後再試，或在 Google AI Studio 為此 key 設定計費／提高配額。'
        elif '401' in detail or '403' in detail:
            detail = 'AI Provider 拒絕 API key，請重新確認 key 與權限。'
        else:
            detail = 'AI Provider 測試失敗，請檢查 model ID 與 API key。'
        raise HTTPException(502,detail)
