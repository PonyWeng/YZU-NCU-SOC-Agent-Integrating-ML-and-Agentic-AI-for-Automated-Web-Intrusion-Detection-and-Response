"""Optional LINE delivery worker, isolated from ingestion and dashboard requests."""
import time
from datetime import datetime, timezone, timedelta
import requests
import json
from siem import store

def format_alert(row):
    """Build a detailed LINE alert from the incident and its correlated evidence."""
    with store.connection() as db:
        incident=db.execute('SELECT * FROM incidents WHERE id=?',(row['incident_id'],)).fetchone()
        ids=json.loads(incident['evidence'] or '[]') if incident else []
        events=[db.execute('SELECT * FROM events WHERE id=?',(eid,)).fetchone() for eid in ids[:200]]
    events=[e for e in events if e]
    labels={1:'SQL Injection',2:'Cross-Site Scripting (XSS)',3:'Directory Traversal'}
    breakdown={}
    for e in events: breakdown[labels.get(e['attack'],'Other')]=breakdown.get(labels.get(e['attack'],'Other'),0)+1
    first=events[0] if events else None
    ts=(incident['created_at'] if incident else row['created_at'])[:19].replace('T',' ')
    payload=f"{first['method']} {first['url']} HTTP/1.1" if first else '—'
    target=first['service_name'] if first else '未知服務'
    destination=f"{first['dst_ip'] or first['service_host']}:{first['service_port']}" if first else '—'
    with store.connection() as db:
        service=db.execute('''SELECT kind,name FROM protected_services
            WHERE name=? OR (host=? AND port=?) ORDER BY name=? DESC LIMIT 1''',
            (target,first['service_host'] if first else '',first['service_port'] if first else 0,target)).fetchone() if first else None
    kind_names={'apache':'Apache Web Server','flask':'Flask Web Application','django':'Django Web Application',
                'nginx':'Nginx Web Server','iis':'IIS Web Server','other':'Web Service'}
    service_desc=f'{target}（{kind_names.get(service["kind"],service["kind"])}）' if service else target
    risk={'critical':'🔴 Critical','high':'🟠 High','medium':'🟡 Medium','low':'🟢 Low'}.get(row['severity'],row['severity'])
    detail=' + '.join(f'{k} ({v})' for k,v in breakdown.items()) or row['rule_name']
    lines=['🛡️ NCU-PDCLAB mini SIEM 安全警報','', '────────────────────────────────',
           f'[Event Name]     : {row["rule_name"]}',f'                   ({row["count"]} total: {detail})',
           f'[Risk Level]     : {risk}',f'[Timestamp]      : {ts}',f'[Source IP]      : {row["src_ip"]}',
           f'[Destination]    : {destination}',f'[Service]        : {service_desc}',f'[Attack Payload] : {payload}',
           f'[Total Alerts]   : {row["count"]} attack(s) in this batch',
           f'[Breakdown]      : {" | ".join(f"{k}: {v}" for k,v in breakdown.items()) or "—"}',
           '────────────────────────────────','', '⚠️  This event has been flagged as suspicious,','    please investigate.',
           '💡 User sessions and client data may be at risk.']
    return '\n'.join(lines)


def deliver_once():
    from config import LINE_CHANNEL_ACCESS_TOKEN
    if not LINE_CHANNEL_ACCESS_TOKEN:
        return
    with store.connection() as db:
        rows = db.execute("SELECT n.*,i.rule_name,i.src_ip,i.count,i.severity FROM notifications n JOIN incidents i ON i.id=n.incident_id WHERE n.status='pending' AND n.retry_at<=? LIMIT 20",(store.now(),)).fetchall()
    for row in rows:
        try:
            resp = requests.post('https://api.line.me/v2/bot/message/push',
                headers={'Authorization':f'Bearer {LINE_CHANNEL_ACCESS_TOKEN}'},
                json={'to':row['recipient'],'messages':[{'type':'text','text':format_alert(row)}]},timeout=15)
            resp.raise_for_status()
            status,error = 'sent',''
        except Exception as exc:
            status,error = 'pending',str(exc)[:300]
        retry_at = (datetime.now(timezone.utc)+timedelta(seconds=min(3600,30*2**min(row['attempts'],7)))).isoformat(timespec='seconds')
        with store.connection() as db:
            db.execute('UPDATE notifications SET status=?,attempts=attempts+1,retry_at=?,error=? WHERE incident_id=? AND recipient=?',
                       (status,retry_at,error,row['incident_id'],row['recipient']))


def main():
    store.init_db()
    while True:
        try:
            deliver_once()
        except Exception as exc:
            print(f'[notifications] {exc}',flush=True)
        time.sleep(10)


if __name__ == '__main__':
    main()
