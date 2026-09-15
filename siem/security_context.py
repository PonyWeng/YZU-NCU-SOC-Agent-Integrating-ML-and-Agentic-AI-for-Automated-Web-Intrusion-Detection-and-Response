"""Compact, data-grounded context for the external security assistant."""
import hashlib
import re
import json
from datetime import datetime, timedelta, timezone

from siem import store

_CACHE={}


def _window(hours):
    return (datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat(timespec='seconds')


def snapshot(hours=1, refresh=False):
    """Build a bounded snapshot; raw logs stay out of the model prompt."""
    cached=_CACHE.get(hours)
    if cached and not refresh and datetime.now(timezone.utc).timestamp()-cached[0] < 30:
        return cached[1]
    since=_window(hours)
    with store.connection() as db:
        counts=dict(db.execute('''SELECT count(*) total_traffic,
            coalesce(sum(attack>0),0) attack_traffic,count(DISTINCT src_ip) source_count
            FROM events WHERE timestamp>=?''',(since,)).fetchone())
        status_counts={r['status']:r['count'] for r in db.execute(
            'SELECT status,count(*) count FROM incidents GROUP BY status')}
        severity_counts={r['severity']:r['count'] for r in db.execute(
            "SELECT severity,count(*) count FROM incidents WHERE status IN ('new','investigating') GROUP BY severity")}
        detectors=dict(db.execute('''SELECT
            coalesce(sum(CASE WHEN origin='modsecurity-crs' AND attack>0 THEN 1 ELSE 0 END),0) waf,
            coalesce(sum(CASE WHEN origin<>'modsecurity-crs' AND attack>0 THEN 1 ELSE 0 END),0) ml
            FROM events WHERE timestamp>=?''',(since,)).fetchone())
        attacks=[dict(r) for r in db.execute('''SELECT attack,count(*) count FROM events
            WHERE timestamp>=? AND attack>0 GROUP BY attack ORDER BY count DESC LIMIT 5''',(since,))]
        sources=[dict(r) for r in db.execute('''SELECT src_ip,count(*) total,coalesce(sum(attack>0),0) attacks
            FROM events WHERE timestamp>=? GROUP BY src_ip ORDER BY attacks DESC,total DESC LIMIT 5''',(since,))]
        services=[dict(r) for r in db.execute('''SELECT service_name,service_host,service_port,count(*) total,
            coalesce(sum(attack>0),0) attacks FROM events WHERE timestamp>=?
            GROUP BY service_name,service_host,service_port ORDER BY attacks DESC,total DESC LIMIT 8''',(since,))]
        open_items=[dict(r) for r in db.execute('''SELECT id,rule_name,src_ip,severity,count,status,last_seen
            FROM incidents WHERE status IN ('new','investigating') ORDER BY
            CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,
            last_seen DESC LIMIT 8''')]
        enabled_services=db.execute('SELECT count(*) FROM protected_services WHERE enabled=1').fetchone()[0]
        enabled_rules=db.execute('SELECT count(*) FROM rules WHERE enabled=1').fetchone()[0]
    counts['attack_rate']=round(counts['attack_traffic']*100/counts['total_traffic'],1) if counts['total_traffic'] else 0
    payload={'generated_at':store.now(),'time_range_hours':hours,'incident_scope':'所有時間（未結案工作佇列）','counts':counts,
        'incident_status':status_counts,'open_by_severity':severity_counts,'detectors':detectors,
        'top_attacks':[{'type':store.LABELS.get(r['attack'],str(r['attack'])),'count':r['count']} for r in attacks],
        'top_sources':sources,'affected_services':services,'open_incidents':open_items,
        'enabled_services':enabled_services,'enabled_rules':enabled_rules}
    canonical=json.dumps(payload,ensure_ascii=False,sort_keys=True)
    payload['context_version']=hashlib.sha256(canonical.encode()).hexdigest()[:10]
    _CACHE[hours]=(datetime.now(timezone.utc).timestamp(),payload)
    return payload


def suggestions(hours=1):
    data=snapshot(hours); candidates=[]
    def add(kind,title,question,reason,score):
        candidates.append({'id':f'{kind}-{data["context_version"]}','kind':kind,'title':title,
            'question':question,'reason':reason,'priority':score})
    critical=data['open_by_severity'].get('critical',0)
    high=data['open_by_severity'].get('high',0)
    open_count=data['incident_status'].get('new',0)+data['incident_status'].get('investigating',0)
    if critical:
        add('urgent','重大事件待處理',f'目前 {critical} 筆 Critical 事件尚未處理，請依優先順序整理風險與處置建議。',f'{critical} 筆 Critical 事件等待處理',100)
    elif open_count:
        add('urgent','事件工作佇列',f'目前有哪些尚未處理的事件？請整理最需要優先調查的項目。',f'{open_count} 筆事件尚未結案',88+min(high,8))
    if data['top_attacks']:
        top=data['top_attacks'][0]
        add('threat','主要攻擊調查',f'分析最近 {hours:g} 小時的 {top["type"]} 攻擊來源、受影響服務與風險。',f'{top["type"]} 共 {top["count"]} 筆，為當前主要攻擊',82)
    if data['affected_services']:
        svc=data['affected_services'][0]
        add('service','受影響服務',f'為什麼 {svc["service_name"]} 是目前受攻擊最多的服務？請列出證據與建議。',f'{svc["service_name"]} 有 {svc["attacks"]} 筆攻擊流量',76)
    if data['counts']['total_traffic']:
        add('traffic','流量與 DDoS',f'檢查最近 {hours:g} 小時流量是否有 DDoS 或異常集中來源的跡象。',f'目前共 {data["counts"]["total_traffic"]} 筆流量，攻擊比例 {data["counts"]["attack_rate"]}%',70)
    if data['top_sources']:
        src=data['top_sources'][0]
        add('source','高風險來源',f'調查來源 IP {src["src_ip"]} 的活動，並評估是否需要封鎖。',f'該來源命中 {src["attacks"]} 筆攻擊',74)
    if data['detectors']['waf'] and data['detectors']['ml']:
        add('detector','交叉偵測',f'比較最近 {hours:g} 小時 WAF 與 ML 的偵測結果，有哪些值得交叉調查？',f'WAF {data["detectors"]["waf"]} 筆、ML {data["detectors"]["ml"]} 筆',72)
    add('overview','安全總覽',f'請整理最近 {hours:g} 小時的安全總覽與下一步建議。','快速掌握目前監控狀態',40)
    chosen=[]
    for item in sorted(candidates,key=lambda x:x['priority'],reverse=True):
        if item['kind'] not in {x['kind'] for x in chosen}: chosen.append(item)
        if len(chosen)==3: break
    return {'snapshot':data,'items':chosen}


def followup_suggestions(message='', answer='', hours=1, history=None):
    """Advance suggestions through the investigation instead of repeating a template."""
    history=history or []; base=suggestions(hours); data=base['snapshot']
    conversation='\n'.join(x.get('content','') for x in history[-12:])
    text=f'{conversation}\n{message}\n{answer}'.lower()
    asked={x.get('content','').strip() for x in history if x.get('role')=='user'}
    turn=sum(1 for x in history if x.get('role')=='user')
    focused=[]
    def add(kind,title,question,reason,priority=110):
        focused.append({'id':f'{kind}-{data["context_version"]}','kind':kind,'title':title,
            'question':question,'reason':reason,'priority':priority})
    topics=[
        (r'sql\s*injection|sqli|sql 注入','SQL Injection','參數化查詢、輸入驗證與 WAF 規則'),
        (r'cross[ -]?site scripting|\bxss\b|跨站腳本','XSS','輸出編碼、CSP 與輸入清理'),
        (r'directory traversal|path traversal|路徑穿越|目錄遍歷','Directory Traversal','路徑正規化、允許清單與權限隔離'),
        (r'ddos|dos|流量突增|大量連線','DDoS／大量連線','速率限制、來源封鎖與上游流量清洗')]
    for pattern,label,defenses in topics:
        if re.search(pattern,text,re.I):
            stages=[
              [('learn','了解攻擊原理',f'{label} 是什麼？請用目前系統偵測到的情境說明攻擊原理與風險。'),
               ('defend','防禦建議',f'目前的 {label} 應如何防禦？請分成應用程式、WAF 與 SIEM 三層說明。'),
               ('evidence','核對偵測證據',f'哪些日誌與規則支持這次 {label} 判斷？請列出 WAF、ML 與受影響服務。')],
              [('scope','確認影響範圍',f'這次 {label} 影響哪些服務、來源與時間範圍？'),
               ('compare','比較偵測結果',f'比較 WAF 與 ML 對這次 {label} 的判斷差異，是否有漏報或誤報？'),
               ('priority','排定修補順序',f'依目前證據，{label} 的修補工作應如何排序？')],
              [('tune','調整偵測規則',f'如何調整目前的 {label} 偵測規則，兼顧靈敏度與誤報率？'),
               ('validate','驗證防禦效果',f'修補 {label} 後，應設計哪些測試確認 WAF、應用程式與告警都生效？'),
               ('report','產生事件摘要',f'將這次 {label} 整理成可交付的事件摘要、影響與改善事項。')]]
            for kind,title,question in stages[min(max(turn-1,0),2)]:
                add(kind,title,question,f'第 {turn+1} 輪調查 · {defenses}')
            break
    ips=[]
    for ip in re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)',text):
        if ip not in ips: ips.append(ip)
    if ips:
        ip=ips[0]
        add('ip-timeline','來源行為時間軸',f'整理 {ip} 的活動時間軸、攻擊類型與接觸過的受保護服務。',f'本輪聚焦來源 IP {ip}',112)
        add('ip-action','評估封鎖',f'根據目前證據評估是否應封鎖 {ip}，並說明判斷依據與可能影響。',f'對高頻來源提出可執行處置',106)
    if re.search(r'事件|incident|未處理|critical',text,re.I):
        add('incident-next','事件處置順序','依嚴重度、時間與影響範圍，下一筆最應優先處理的事件是哪一筆？',
            '延續事件工作佇列的調查',105)
    merged=[]
    for item in sorted(focused,key=lambda x:x['priority'],reverse=True)+base['items']:
        if item['question'] not in asked and item['question'] not in {x['question'] for x in merged}: merged.append(item)
        if len(merged)==3: break
    return {'snapshot':data,'items':merged,'focus_detected':bool(focused),'investigation_turn':turn}
