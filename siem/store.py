"""SQLite event repository. Each batch and collector cursor commit together."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABELS = {0: '正常', 1: 'SQL Injection', 2: 'XSS', 3: 'Directory Traversal', 4: 'WAF 規則命中', -1: '解析失敗'}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


@contextmanager
def connection():
    path = Path(os.getenv('SIEM_DB_PATH', str(ROOT / 'runtime' / 'siem.sqlite3')))
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        with db:
            yield db
    finally:
        db.close()


def init_db():
    with connection() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, received_at TEXT NOT NULL,
          src_ip TEXT NOT NULL, target TEXT NOT NULL, method TEXT NOT NULL,
          url TEXT NOT NULL, status INTEGER NOT NULL, attack INTEGER NOT NULL,
          description TEXT NOT NULL, raw TEXT NOT NULL, origin TEXT NOT NULL,
          service_name TEXT NOT NULL DEFAULT 'Apache Web Server', service_host TEXT NOT NULL DEFAULT '127.0.0.1', service_port INTEGER NOT NULL DEFAULT 80,
          src_port INTEGER, dst_ip TEXT NOT NULL DEFAULT '127.0.0.1', transport TEXT NOT NULL DEFAULT 'tcp',
          protocol TEXT NOT NULL DEFAULT 'http', http_version TEXT NOT NULL DEFAULT '', response_bytes INTEGER NOT NULL DEFAULT 0,
          referer TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', parser_name TEXT NOT NULL DEFAULT 'legacy');
        CREATE INDEX IF NOT EXISTS event_time ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS event_source ON events(src_ip,attack,timestamp);
        CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rules (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, attack INTEGER NOT NULL,
          threshold INTEGER NOT NULL, window_sec INTEGER NOT NULL,
          cooldown_sec INTEGER NOT NULL, severity TEXT NOT NULL, enabled INTEGER NOT NULL,
          rule_uid TEXT NOT NULL DEFAULT '', rule_type TEXT NOT NULL DEFAULT 'correlation',
          description TEXT NOT NULL DEFAULT '', metric TEXT NOT NULL DEFAULT 'attack_count',
          settings TEXT NOT NULL DEFAULT '{}', readonly INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS incidents (
          id INTEGER PRIMARY KEY, rule_id INTEGER NOT NULL, rule_name TEXT NOT NULL,
          src_ip TEXT NOT NULL, attack INTEGER NOT NULL, severity TEXT NOT NULL,
          count INTEGER NOT NULL, created_at TEXT NOT NULL, first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new',
          note TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL,
          handled_by TEXT NOT NULL DEFAULT '', handled_at TEXT NOT NULL DEFAULT '');
        CREATE INDEX IF NOT EXISTS incident_source ON incidents(rule_id,src_ip,created_at);
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, actor TEXT NOT NULL,
          action TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notifications (
          incident_id INTEGER NOT NULL, recipient TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          attempts INTEGER NOT NULL DEFAULT 0, retry_at TEXT NOT NULL, error TEXT NOT NULL DEFAULT '',
          PRIMARY KEY(incident_id,recipient));
        CREATE TABLE IF NOT EXISTS intelligence (
          id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL,
          source TEXT NOT NULL, confidence INTEGER NOT NULL DEFAULT 0,
          verdict TEXT NOT NULL DEFAULT 'unknown', tags TEXT NOT NULL DEFAULT '[]',
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
          UNIQUE(kind,value,source));
        CREATE TABLE IF NOT EXISTS chat_sessions (
          id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          title TEXT NOT NULL DEFAULT '新的對話');
        CREATE TABLE IF NOT EXISTS chat_messages (
          id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, role TEXT NOT NULL,
          content TEXT NOT NULL, created_at TEXT NOT NULL,
          FOREIGN KEY(session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS ai_settings (
          id INTEGER PRIMARY KEY CHECK(id=1), provider TEXT NOT NULL,
          model TEXT NOT NULL, api_key TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS geo_ip_cache (
          ip TEXT PRIMARY KEY, country TEXT NOT NULL DEFAULT 'Unknown', country_code TEXT NOT NULL DEFAULT '??',
          city TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '', latitude REAL, longitude REAL,
          org TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS protected_services (
          id INTEGER PRIMARY KEY, service_uid TEXT NOT NULL UNIQUE,
          name TEXT NOT NULL, kind TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
          log_path TEXT NOT NULL, parser_format TEXT NOT NULL,
          waf_enabled INTEGER NOT NULL DEFAULT 0, waf_log_path TEXT NOT NULL DEFAULT '',
          enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('admin','analyst')), enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS user_sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL, user_agent TEXT NOT NULL DEFAULT '',
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE INDEX IF NOT EXISTS session_expiry ON user_sessions(expires_at);
        CREATE TABLE IF NOT EXISTS system_settings (
          key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL,
          updated_by TEXT NOT NULL);
        ''')
        from siem.auth import bootstrap_admin
        bootstrap_admin(db)
        for col, definition in [('service_name',"TEXT NOT NULL DEFAULT 'Apache Web Server'"),('service_host',"TEXT NOT NULL DEFAULT '127.0.0.1'"),('service_port','INTEGER NOT NULL DEFAULT 80'),
                                ('src_port','INTEGER'),('dst_ip',"TEXT NOT NULL DEFAULT '127.0.0.1'"),('transport',"TEXT NOT NULL DEFAULT 'tcp'"),
                                ('protocol',"TEXT NOT NULL DEFAULT 'http'"),('http_version',"TEXT NOT NULL DEFAULT ''"),('response_bytes','INTEGER NOT NULL DEFAULT 0'),
                                ('referer',"TEXT NOT NULL DEFAULT ''"),('user_agent',"TEXT NOT NULL DEFAULT ''"),('parser_name',"TEXT NOT NULL DEFAULT 'legacy'")]:
            try: db.execute(f'ALTER TABLE events ADD COLUMN {col} {definition}')
            except sqlite3.OperationalError:
                pass
        for col, definition in [('rule_uid',"TEXT NOT NULL DEFAULT ''"),('rule_type',"TEXT NOT NULL DEFAULT 'correlation'"),
                                ('description',"TEXT NOT NULL DEFAULT ''"),('metric',"TEXT NOT NULL DEFAULT 'attack_count'"),
                                ('settings',"TEXT NOT NULL DEFAULT '{}'"),('readonly','INTEGER NOT NULL DEFAULT 0')]:
            try: db.execute(f'ALTER TABLE rules ADD COLUMN {col} {definition}')
            except sqlite3.OperationalError:
                pass
        for col, definition in [('handled_by',"TEXT NOT NULL DEFAULT ''"),('handled_at',"TEXT NOT NULL DEFAULT ''")]:
            try: db.execute(f'ALTER TABLE incidents ADD COLUMN {col} {definition}')
            except sqlite3.OperationalError:
                pass
        for code, name, severity in [(1, '重複 SQLi 偵測', 'high'), (2, '重複 XSS 偵測', 'medium'), (3, '重複路徑穿越偵測', 'medium')]:
            db.execute('''INSERT OR IGNORE INTO rules
                (id,name,attack,threshold,window_sec,cooldown_sec,severity,enabled,rule_uid,rule_type,description,metric)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                (code,name,code,5,120,300,severity,0,f'COR-{code:03d}','correlation',
                 f'同一來源 IP 在時間窗內重複命中 {LABELS[code]}。','attack_count'))
            db.execute('''UPDATE rules SET rule_uid=CASE WHEN rule_uid='' THEN ? ELSE rule_uid END,
                rule_type='correlation',description=CASE WHEN description='' THEN ? ELSE description END,
                metric='attack_count' WHERE id=?''',(f'COR-{code:03d}',f'同一來源 IP 在時間窗內重複命中 {LABELS[code]}。',code))
        # ML detections are high-risk per request.  Keep the existing rule IDs
        # for audit continuity while using an English, notification-friendly
        # title and a one-hit trigger; the cooldown bundles subsequent hits.
        ml_names={1:'SQL injection attempt',2:'XSS attempt',3:'Directory Traversal attempt'}
        for code,title in ml_names.items():
            db.execute('''UPDATE rules SET name=?,threshold=1,window_sec=60,severity='high',enabled=1,
                description=? WHERE rule_uid=? AND (name IN (?,?,?))''',
                (title,f'一筆 {title} 即建立高風險告警；同一來源在冷卻時間內的後續命中會綑綁至同一事件。',
                 f'COR-{code:03d}','重複 SQLi 偵測','重複 XSS 偵測','重複路徑穿越偵測'))
        behavior = [
          ('BEH-001','短時間大量連線','同一來源對同一服務 1 分鐘連線至少 50 次。','request_count',50,60,300,'high',{}),
          ('BEH-002','持續大量連線','同一來源對同一服務 5 分鐘連線至少 300 次。','request_count',300,300,600,'high',{}),
          ('BEH-003','極端流量突增','同一來源對同一服務 10 秒連線至少 100 次。','request_count',100,10,300,'critical',{}),
          ('BEH-004','多服務探測','同一來源 1 分鐘內存取至少 3 個受保護服務。','distinct_services',3,60,600,'high',{}),
          ('BEH-005','大量不同路徑','同一來源對同一服務 2 分鐘內存取至少 30 個不同 URL。','distinct_paths',30,120,600,'high',{}),
          ('BEH-006','高比例 404','同一來源 2 分鐘至少 30 次請求，且 404 比例達 70%。','status_404_ratio',70,120,600,'high',{'min_requests':30}),
          ('BEH-007','大量伺服器錯誤','同一來源 2 分鐘內造成至少 10 次 5xx。','server_error_count',10,120,600,'high',{}),
          ('BEH-008','異常 HTTP 方法','偵測 TRACE、CONNECT 或大量 OPTIONS 方法。','suspicious_method',1,60,300,'high',{}),
          ('BEH-009','敏感路徑探測','偵測 .env、.git、wp-admin、phpMyAdmin 與 server-status。','sensitive_path',1,60,300,'high',{}),
          ('BEH-010','攻擊工具 User-Agent','偵測 sqlmap、nikto、nmap、gobuster 等工具特徵。','suspicious_ua',1,60,300,'medium',{}),
          ('BEH-011','多種攻擊類型','同一來源 5 分鐘內命中至少 2 種攻擊分類。','multi_attack_types',2,300,600,'critical',{}),
          ('BEH-012','威脅情資來源命中','來源 IP 命中 malicious 或 suspicious 情資。','intel_match',1,60,600,'high',{}),
          ('BEH-013','WAF 與 ML 同時命中','同一請求於 5 秒內同時被 WAF 與 ML 判定。','detector_correlation',2,5,600,'critical',{})]
        for uid,name,desc,metric,threshold,window,cooldown,severity,settings in behavior:
            db.execute('''INSERT OR IGNORE INTO rules
                (name,attack,threshold,window_sec,cooldown_sec,severity,enabled,rule_uid,rule_type,description,metric,settings)
                SELECT ?,0,?,?,?,?,1,?,'behavior',?,?,? WHERE NOT EXISTS(SELECT 1 FROM rules WHERE rule_uid=?)''',
                (name,threshold,window,cooldown,severity,uid,desc,metric,json.dumps(settings),uid))
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS rule_uid_unique ON rules(rule_uid)')
        services=[
          ('SVC-001','TechMart 購物網站','apache','127.0.0.1',80,'apache-logs/access.log','apache_combined',1,'protected_services/logs/waf/apache/audit.jsonl'),
          ('SVC-002','Northstar 員工服務入口','flask','127.0.0.1',8081,'protected_services/logs/flask/access.jsonl','flask_json',1,'protected_services/logs/waf/flask/audit.jsonl'),
          ('SVC-003','晴川市民服務網','django','127.0.0.1',8082,'protected_services/logs/django/access.jsonl','django_json',1,'protected_services/logs/waf/django/audit.jsonl')]
        for uid,name,kind,host,port,path,fmt,waf,waf_path in services:
            db.execute('''INSERT OR IGNORE INTO protected_services
                (service_uid,name,kind,host,port,log_path,parser_format,waf_enabled,waf_log_path,enabled,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,1,?,?)''',(uid,name,kind,host,port,path,fmt,waf,waf_path,now(),now()))


def get_state(key, default=None):
    with connection() as db:
        row = db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default


def set_state(key, value):
    with connection() as db:
        db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (key, json.dumps(value)))


def audit(action, detail, actor='dashboard', db=None):
    if db is None:
        with connection() as conn:
            audit(action, detail, actor, conn)
    else:
        db.execute('INSERT INTO audit(timestamp,actor,action,detail) VALUES (?,?,?,?)',
                   (now(), actor, action, str(detail)))


def insert_events(events, cursor_key=None, cursor=None, evaluate=False):
    inserted = 0
    with connection() as db:
        for event in events:
            columns=('id','timestamp','received_at','src_ip','target','method','url','status','attack','description','raw','origin','service_name','service_host','service_port','src_port','dst_ip','transport','protocol','http_version','response_bytes','referer','user_agent','parser_name')
            values = [event.get(k) for k in columns]
            added = db.execute('INSERT OR IGNORE INTO events ('+','.join(columns)+') VALUES ('+','.join('?' for _ in columns)+')', values).rowcount
            inserted += added
            # Historical import never triggers notifications. Late replay is also excluded.
            if added and evaluate:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(event['timestamp'])).total_seconds()
                if 0 <= age <= 300:
                    evaluate_rules(db, event)
        if cursor_key:
            db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (cursor_key, json.dumps(cursor)))
    return inserted


def rule_display_name(rule):
    """Build an alert-safe name from the current rule settings."""
    seconds=int(rule['window_sec'])
    window=f'{seconds//60} 分鐘' if seconds%60==0 and seconds>=60 else f'{seconds} 秒'
    threshold=int(rule['threshold'])
    detail={
        'request_count':f'{window} {threshold} 次',
        'distinct_services':f'{window} {threshold} 個服務',
        'distinct_paths':f'{window} {threshold} 個不同 URL',
        'status_404_ratio':f'{window} 404 比例 {threshold}%',
        'server_error_count':f'{window} {threshold} 次 5xx',
        'suspicious_method':'TRACE / CONNECT / OPTIONS',
        'sensitive_path':'.env / .git 等敏感路徑',
        'suspicious_ua':'攻擊工具 User-Agent',
        'multi_attack_types':f'{window} {threshold} 種攻擊',
        'intel_match':'惡意或可疑 IP',
        'detector_correlation':f'{window}內 WAF + ML',
        'attack_count':f'{window} {threshold} 次',
    }.get(rule['metric'],f'{window} 門檻 {threshold}')
    return f"{rule['name']}（{detail}）"


def evaluate_rules(db, event):
    for rule in db.execute("SELECT * FROM rules WHERE enabled=1 AND (rule_type='behavior' OR attack=?)", (event['attack'],)).fetchall():
        end = datetime.fromisoformat(event['timestamp'])
        start = (end - timedelta(seconds=rule['window_sec'])).isoformat(timespec='seconds')
        cooldown = (datetime.now(timezone.utc) - timedelta(seconds=rule['cooldown_sec'])).isoformat(timespec='seconds')
        existing=db.execute('SELECT id FROM incidents WHERE rule_id=? AND src_ip=? AND created_at>=?',
                      (rule['id'], event['src_ip'], cooldown)).fetchone()
        base='src_ip=? AND timestamp BETWEEN ? AND ?'
        params=[event['src_ip'],start,event['timestamp']]
        metric=rule['metric']
        if metric not in ('distinct_services','multi_attack_types','intel_match'):
            base+=' AND service_name=?';params.append(event['service_name'])
        if metric=='attack_count': base+=' AND attack=?';params.append(rule['attack'])
        elif metric=='server_error_count': base+=' AND status BETWEEN 500 AND 599'
        elif metric=='suspicious_method': base+=" AND upper(method) IN ('TRACE','CONNECT','OPTIONS')"
        elif metric=='sensitive_path': base+=" AND (lower(url) LIKE '%.env%' OR lower(url) LIKE '%.git%' OR lower(url) LIKE '%wp-admin%' OR lower(url) LIKE '%phpmyadmin%' OR lower(url) LIKE '%server-status%')"
        elif metric=='suspicious_ua': base+=" AND (lower(user_agent) LIKE '%sqlmap%' OR lower(user_agent) LIKE '%nikto%' OR lower(user_agent) LIKE '%nmap%' OR lower(user_agent) LIKE '%gobuster%' OR lower(user_agent) LIKE '%dirbuster%')"
        elif metric=='multi_attack_types': base+=' AND attack>0'
        hits=db.execute('SELECT id,timestamp,service_name,origin,method,url,status,attack FROM events WHERE '+base+' ORDER BY timestamp',params).fetchall()
        value=len(hits)
        if metric=='distinct_services': value=len({h['service_name'] for h in hits})
        elif metric=='distinct_paths': value=len({h['url'] for h in hits})
        elif metric=='multi_attack_types': value=len({h['attack'] for h in hits})
        elif metric=='status_404_ratio':
            minimum=json.loads(rule['settings'] or '{}').get('min_requests',30)
            value=(sum(h['status']==404 for h in hits)*100/len(hits)) if len(hits)>=minimum else 0
        elif metric=='intel_match':
            hit=db.execute("SELECT 1 FROM intelligence WHERE kind='ip' AND value=? AND verdict IN ('malicious','suspicious') LIMIT 1",(event['src_ip'],)).fetchone()
            value=1 if hit else 0
        elif metric=='detector_correlation':
            origins={('waf' if h['origin']=='modsecurity-crs' else 'ml') for h in hits if h['method']==event['method'] and h['url']==event['url'] and h['attack']>0}
            value=len(origins)
        if value < rule['threshold']:
            continue
        if existing:
            db.execute('UPDATE incidents SET count=?,last_seen=?,evidence=? WHERE id=?',
                       (len(hits),hits[-1]['timestamp'] if hits else event['timestamp'],json.dumps([h['id'] for h in hits]),existing['id']))
            continue
        result = db.execute('''INSERT INTO incidents(rule_id,rule_name,src_ip,attack,severity,count,created_at,first_seen,last_seen,evidence)
            VALUES (?,?,?,?,?,?,?,?,?,?)''', (rule['id'],rule_display_name(rule),event['src_ip'],event['attack'],rule['severity'],len(hits),now(),hits[0]['timestamp'] if hits else event['timestamp'],hits[-1]['timestamp'] if hits else event['timestamp'],json.dumps([h['id'] for h in hits])))
        # Queue per recipient; retry does not resend to successful recipients.
        from config import LINE_USER_IDS
        for recipient in LINE_USER_IDS:
            db.execute('INSERT INTO notifications(incident_id,recipient,retry_at) VALUES (?,?,?)', (result.lastrowid, recipient, now()))


def filters(hours=24, q='', src_ip='', attack=None, status=None, since='', until=''):
    clauses, params = [], []
    if since:
        clauses.append('timestamp>=?'); params.append(since)
    elif hours:
        clauses.append('timestamp>=?')
        params.append((datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat(timespec='seconds'))
    if until:
        clauses.append('timestamp<=?'); params.append(until)
    if q:
        clauses.append('(url LIKE ? ESCAPE CHAR(92) OR raw LIKE ? ESCAPE CHAR(92))')
        escaped = q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        params.extend(['%'+escaped+'%'] * 2)
    if src_ip:
        clauses.append('src_ip=?'); params.append(src_ip)
    if attack is not None:
        clauses.append('attack=?'); params.append(attack)
    if status is not None:
        clauses.append('status=?'); params.append(status)
    return ' AND '.join(clauses) or '1=1', params


def list_events(page=1, page_size=50, **kwargs):
    where, params = filters(**kwargs)
    with connection() as db:
        total = db.execute('SELECT count(*) FROM events WHERE '+where, params).fetchone()[0]
        rows = db.execute('SELECT * FROM events WHERE '+where+' ORDER BY timestamp DESC,id LIMIT ? OFFSET ?',
                          params+[page_size,(page-1)*page_size]).fetchall()
        return {'total':total, 'items':[dict(row) for row in rows], 'page':page, 'page_size':page_size}


def overview(hours=24):
    where, params = filters(hours=hours)
    with connection() as db:
        def rows(sql):
            return [dict(r) for r in db.execute(sql, params).fetchall()]
        counts = rows('SELECT count(*) total,coalesce(sum(attack>0),0) attacks,count(DISTINCT src_ip) sources,coalesce(sum(attack=-1),0) errors FROM events WHERE '+where)[0]
        counts['open_incidents'] = db.execute("SELECT count(*) FROM incidents WHERE status IN ('new','investigating')").fetchone()[0]
        bucket_len = 16 if hours <= 6 else 13 if hours <= 72 else 10
        timeline = rows(f"SELECT substr(timestamp,1,{bucket_len}) bucket,count(*) total,coalesce(sum(attack>0),0) attacks,coalesce(sum(attack=0),0) normal,count(DISTINCT src_ip) sources FROM events WHERE "+where+' GROUP BY bucket ORDER BY bucket')
        top_source = rows('SELECT src_ip,count(*) total,coalesce(sum(attack>0),0) attacks FROM events WHERE '+where+' GROUP BY src_ip ORDER BY total DESC LIMIT 1')
        peak = max((r['total'] for r in timeline),default=0)
        return {'counts': counts,
                'types': rows('SELECT attack,count(*) count FROM events WHERE '+where+' GROUP BY attack'),
                'timeline': timeline,
                'timeline_unit': 'minute' if bucket_len==16 else 'hour' if bucket_len==13 else 'day',
                'ddos': {'peak_per_bucket':peak,'top_source':top_source[0] if top_source else None},
                'sources': rows('SELECT src_ip,count(*) total,sum(attack>0) attacks FROM events WHERE '+where+' GROUP BY src_ip ORDER BY attacks DESC,total DESC LIMIT 12'),
                # WAF is an ingress detector, not an application target. Fold
                # legacy WAF-labelled rows into the backend node in topology.
                'edges': rows("SELECT src_ip,CASE WHEN origin='modsecurity-crs' AND service_name='Apache WAF' THEN 'Apache Web Server' WHEN origin='modsecurity-crs' AND service_name='Flask WAF' THEN 'flask-target' WHEN origin='modsecurity-crs' AND service_name='Django WAF' THEN 'django-target' ELSE coalesce(service_name,target) END||' ('||coalesce(dst_ip,service_host,'127.0.0.1')||':'||coalesce(service_port,80)||')' target,count(*) total,sum(attack>0) attacks FROM events WHERE "+where+" GROUP BY src_ip,CASE WHEN origin='modsecurity-crs' AND service_name='Apache WAF' THEN 'Apache Web Server' WHEN origin='modsecurity-crs' AND service_name='Flask WAF' THEN 'flask-target' WHEN origin='modsecurity-crs' AND service_name='Django WAF' THEN 'django-target' ELSE coalesce(service_name,target) END,dst_ip,service_host,service_port,target ORDER BY attacks DESC,total DESC LIMIT 20"),
                'last_event': db.execute('SELECT max(received_at) FROM events').fetchone()[0]}
