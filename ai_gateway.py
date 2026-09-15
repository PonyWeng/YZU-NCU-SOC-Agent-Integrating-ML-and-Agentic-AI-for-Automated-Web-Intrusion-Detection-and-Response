"""One external AI gateway shared by Web Chat and LINE.

The key is kept in the local SQLite settings store and is never returned by
the API. The dashboard is local-only, so configuring it does not expose the
key to a public web page.
"""
import json, re, time, requests
from datetime import datetime, timezone
from siem import store

def settings(mask=True):
    with store.connection() as db:
        row=db.execute('SELECT provider,model,api_key,updated_at FROM ai_settings WHERE id=1').fetchone()
    if not row: return {'configured':False,'provider':'gemini','model':'','api_key_masked':'','updated_at':''}
    key=row['api_key']; return {'configured':bool(key),'provider':row['provider'],'model':row['model'],'api_key_masked':('*'*max(0,len(key)-4)+key[-4:] if mask and key else ''),'updated_at':row['updated_at']}

def save(provider,model,api_key):
    if provider not in ('gemini','openai'): raise ValueError('不支援的 AI Provider')
    if not model.strip() or not api_key.strip(): raise ValueError('Provider、模型與 API key 不可空白')
    with store.connection() as db:
        db.execute('INSERT OR REPLACE INTO ai_settings(id,provider,model,api_key,updated_at) VALUES (1,?,?,?,?)',(provider,model.strip(),api_key.strip(),store.now()))
        store.audit('ai.settings','AI Provider updated',db=db)
    return settings()

def _key():
    with store.connection() as db:
        row=db.execute('SELECT provider,model,api_key FROM ai_settings WHERE id=1').fetchone()
    if not row or not row['api_key']: raise RuntimeError('尚未設定外部 AI Provider，請先到 AI 設定頁保存 API key。')
    return dict(row)

def context(hours=1):
    from siem.security_context import snapshot
    return snapshot(hours)

def _question_context(message):
    """Fetch bounded details for entities explicitly named by the user."""
    match=re.search(r'(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?!\d)',message)
    if not match: return {}
    ip=match.group(1)
    with store.connection() as db:
        events=[dict(r) for r in db.execute('''SELECT timestamp,src_ip,service_name,service_host,
            service_port,attack,description,origin,method,url,status FROM events WHERE src_ip=?
            ORDER BY timestamp DESC LIMIT 50''',(ip,))]
        incidents=[dict(r) for r in db.execute('''SELECT id,rule_name,severity,count,status,first_seen,last_seen
            FROM incidents WHERE src_ip=? ORDER BY last_seen DESC LIMIT 20''',(ip,))]
    return {'queried_ip':ip,'event_count_returned':len(events),'events':events,'incidents':incidents,
            'scope':'該 IP 最新 50 筆日誌與最新 20 筆關聯事件；可能包含目前一小時範圍以前的歷史資料'}

def _prompt(message,history):
    return ('你是 NCU-PDCLAB mini SIEM 內建的資安分析員。只根據提供的 SIEM 資料回答，不要捏造資料。'
            '不要問候、不要自我介紹、不要重述自己的身分，直接承接問題並先說結論。'
            '語氣自然、專業、簡潔，像正在與使用者持續協作的 SOC 分析員。'
            '使用繁體中文，說明數字與時間範圍；若資料不足要明確說明。'
            '請完整回答使用者問題，至少給出結論與必要的數據依據，不要只回半句或截斷句子。回答可包含下一步調查建議。禁止輸出 Markdown 表格。\n\n'
            '摘要中的 generated_at 是資料產生時間，time_range_hours 是統計範圍，context_version 可供追溯。'
            '若問題需要摘要沒有的明細，請說明需進一步查詢，不可自行補造。\n\n'
            f'目前 SIEM 安全快照：{json.dumps(context(),ensure_ascii=False)}\n'
            f'依本輪問題補查的實體資料：{json.dumps(_question_context(message),ensure_ascii=False)}\n\n'
            f'對話：{history[-6:]}\n使用者問題：{message}')

def chat(message,history=None):
    cfg=_key(); prompt=_prompt(message,history or [])
    if cfg['provider']=='gemini':
        url=f"https://generativelanguage.googleapis.com/v1beta/models/{cfg['model']}:generateContent?key={cfg['api_key']}"
        body={'contents':[{'parts':[{'text':prompt}]}],'generationConfig':{'temperature':0.1,'maxOutputTokens':1200}}
        last=None
        for attempt in range(3):
            try:
                response=requests.post(url,json=body,timeout=45)
                response.raise_for_status()
                data=response.json(); candidates=data.get('candidates') or []
                text=''.join(p.get('text','') for p in candidates[0].get('content',{}).get('parts',[])).strip() if candidates else ''
                if text: return text
                raise RuntimeError('AI Provider returned an empty response')
            except (requests.RequestException, RuntimeError) as exc:
                last=exc
                if attempt<2: time.sleep(1.5*(attempt+1))
        raise last
    from openai import OpenAI
    response=OpenAI(api_key=cfg['api_key']).chat.completions.create(model=cfg['model'],messages=[{'role':'system','content':'你是 NCU-PDCLAB mini SIEM 內建資安分析員。不要問候或自我介紹，直接用繁體中文回答重點，只根據提供的 SIEM 資料回答。'},{'role':'user','content':prompt}],temperature=0.1,max_tokens=1200)
    return response.choices[0].message.content.strip()

def run(message,history=None):
    """Route operational requests through the existing NIDS tools, then use AI for analysis."""
    text=message.strip()
    # Keep operational actions deterministic and auditable. The external model is
    # used for explanation, never as the authority for a firewall mutation.
    from assistant import tools as nids_tools
    if re.fullmatch(r'/help',text,re.I):
        return nids_tools.HELP_TEXT
    match=re.fullmatch(r'(?:請|幫我)?\s*(?:/ban|封鎖|ban|block)\s*(\d{1,3}(?:\.\d{1,3}){3})[。！!]?',text,re.I)
    if match:
        return nids_tools.ban_ip_address.invoke({'ip':match.group(1)})
    match=re.fullmatch(r'(?:請|幫我)?\s*(?:/unban|解除封鎖|解封|unban|unblock)\s*(\d{1,3}(?:\.\d{1,3}){3})[。！!]?',text,re.I)
    if match:
        return nids_tools.unban_ip_address.invoke({'ip':match.group(1)})
    if re.search(r'(?:黑名單|黑名单|封鎖清單|封鎖名單|封鎖列表|封鎖的?\s*IP|被封鎖|blocked ips|blacklist)',text,re.I):
        return nids_tools.list_blocked_ips.invoke({})
    match=re.search(r'(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?!\d)',text)
    if match and re.search(r'(?:查|看|查詢|情資|reputation|lookup|check|IP)',text,re.I):
        return nids_tools.check_ip_reputation.invoke({'ip':match.group(1)})
    if re.fullmatch(r'(?:/logs(?:\s+recent)?|recent attacks?)',text,re.I):
        return nids_tools.get_recent_attack_logs.invoke({})
    if re.fullmatch(r'(?:/status|系統狀態|平台狀態|system status|health)',text,re.I):
        return nids_tools.get_system_status.invoke({})
    return chat(text,history)
