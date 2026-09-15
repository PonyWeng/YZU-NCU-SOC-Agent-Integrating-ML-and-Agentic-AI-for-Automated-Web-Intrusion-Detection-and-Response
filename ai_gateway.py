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
    if not model.strip(): raise ValueError('模型不可空白')
    if not api_key.strip():
        with store.connection() as db:
            row=db.execute('SELECT api_key FROM ai_settings WHERE id=1').fetchone()
        api_key=row['api_key'] if row else ''
    if not api_key.strip(): raise ValueError('尚未設定 API key')
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

def _prompt(message,history,tool_context=None):
    tool_context=tool_context or {}
    internal_requested=bool(re.search(r'(?:我們|本機|內部|SIEM|日誌|告警|受保護服務|有沒有攻擊|是否命中|交叉|關聯)',message,re.I))
    siem_context=context() if internal_requested or not any(k in tool_context for k in ('list_security_news','read_security_news')) else {'omitted':True,'reason':'本輪只詢問外部新聞，避免與內部 SIEM 事件混淆'}
    return ('你是 NCU SOC AI 防禦小精靈，是 NCU-PDCLAB mini SIEM 內建的 SOC Agent。只根據提供的 SIEM 資料回答，不要捏造資料。'
            '不要問候、不要自我介紹、不要重述自己的身分，直接承接問題並先說結論。'
            '語氣自然、專業、簡潔，像正在與使用者持續協作的 SOC 分析員。'
            '使用繁體中文，說明數字與時間範圍；若資料不足要明確說明。'
            '請完整回答使用者問題，至少給出結論與必要的數據依據，不要只回半句或截斷句子。回答可包含下一步調查建議。禁止輸出 Markdown 表格。\n\n'
            '外部新聞描述的是新聞中的組織與事件，不代表本機 SIEM 或受保護服務已受影響。'
            '除非工具結果存在相同 IP、網域、服務或事件證據，否則不得把外部新聞和內部告警建立因果或命中關係。'
            '若同時提供兩類資料，請分成「外部情資」與「本機 SIEM 證據」，並明確寫出目前是否有關聯證據。\n\n'
            '若安全快照標示 omitted，回答只能處理外部新聞，不要提到本機 SIEM、內部事件、關聯證據或建議使用者調整時間範圍。\n\n'
            '摘要中的 generated_at 是資料產生時間，time_range_hours 是統計範圍，context_version 可供追溯。'
            '若問題需要摘要沒有的明細，請說明需進一步查詢，不可自行補造。\n\n'
            f'目前 SIEM 安全快照：{json.dumps(siem_context,ensure_ascii=False)}\n'
            f'依本輪問題補查的實體資料：{json.dumps(_question_context(message),ensure_ascii=False)}\n\n'
            f'本輪唯讀情資工具結果：{json.dumps(tool_context or {},ensure_ascii=False)}\n'
            '工具結果有筆數與內容上限；只能根據回傳資料回答，並標明分類屬於外部情資或本機特徵初判。\n\n'
            '若使用 list_security_news，列出每則新聞時必須保留工具提供的新聞 ID，格式為「#ID 標題」，'
            '並提醒使用者可用「查看新聞 #ID」繼續追問，不得省略或自行重編 ID。\n\n'
            f'對話：{history[-6:]}\n使用者問題：{message}')

def _ensure_news_ids(text,tool_context):
    raw=(tool_context or {}).get('list_security_news')
    if not raw: return text
    try: items=json.loads(raw).get('items',[])
    except Exception: return text
    missing=[item for item in items if f"#{item.get('id')}" not in text]
    if not missing: return text
    index='\n'.join(f"#{item['id']} {item.get('title','')}（{item.get('source','')}，{item.get('published','')}）" for item in items)
    return text.rstrip()+"\n\n新聞索引：\n"+index+"\n\n可接著輸入「查看新聞 #ID」。"

def chat(message,history=None,tool_context=None):
    cfg=_key(); prompt=_prompt(message,history or [],tool_context)
    if cfg['provider']=='gemini':
        body={'contents':[{'parts':[{'text':prompt}]}],'generationConfig':{'temperature':0.1,'maxOutputTokens':1200}}
        models=list(dict.fromkeys([cfg['model'],'gemini-3.5-flash-lite']))
        last=None
        for model_index,model in enumerate(models):
            url=f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={cfg['api_key']}"
            attempts=2 if model_index==0 else 1
            for attempt in range(attempts):
                try:
                    response=requests.post(url,json=body,timeout=45)
                    if not response.ok:
                        try: provider_message=response.json().get('error',{}).get('message','')
                        except Exception: provider_message=''
                        raise RuntimeError(f'Gemini HTTP {response.status_code}: {provider_message[:180]}')
                    data=response.json(); candidates=data.get('candidates') or []
                    text=''.join(p.get('text','') for p in candidates[0].get('content',{}).get('parts',[])).strip() if candidates else ''
                    if text: return _ensure_news_ids(text,tool_context)
                    raise RuntimeError('AI Provider returned an empty response')
                except (requests.RequestException, RuntimeError) as exc:
                    last=exc
                    if attempt+1<attempts: time.sleep(1.5*(attempt+1))
        raise last
    from openai import OpenAI
    response=OpenAI(api_key=cfg['api_key']).chat.completions.create(model=cfg['model'],messages=[{'role':'system','content':'你是 NCU SOC AI 防禦小精靈，是 NCU-PDCLAB mini SIEM 內建的 SOC Agent。不要問候或自我介紹，直接用繁體中文回答重點，只根據提供的 SIEM 資料回答。'},{'role':'user','content':prompt}],temperature=0.1,max_tokens=1200)
    return _ensure_news_ids(response.choices[0].message.content.strip(),tool_context)

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
    tool_context={}
    news_id=re.search(r'(?:新聞|news)\s*#?\s*(\d+)',text,re.I)
    if news_id and re.search(r'(?:查看|讀|內容|摘要|說明|分析|詳細|read)',text,re.I):
        tool_context['read_security_news']=nids_tools.read_security_news.invoke({'news_id':int(news_id.group(1))})
    elif re.search(r'(?:新聞|資安動態|security news)',text,re.I):
        topics=re.findall(r'勒索(?:軟體)?|資料外洩|個資外洩|供應鏈|零時差|漏洞|釣魚|惡意軟體|DDoS|SQL\s*Injection|XSS|雲端|AI',text,re.I)
        keyword=' '.join(dict.fromkeys(topics))[:80]
        tool_context['list_security_news']=nids_tools.list_security_news.invoke({'query':keyword})
    if re.search(r'(?:釣魚|phishing)',text,re.I):
        tool_context['list_phishing_sites']=nids_tools.list_phishing_sites.invoke({'query':''})
    if re.search(r'(?:風險\s*IP|可疑\s*IP|Tor|FireHOL)',text,re.I):
        tool_context['list_risk_ips']=nids_tools.list_risk_ips.invoke({'query':match.group(1) if match else ''})
    if re.search(r'(?:交叉|關聯|命中.*(?:日誌|事件)|情資.*(?:日誌|事件)|有沒有攻擊)',text,re.I):
        tool_context['correlate_intel_with_siem']=nids_tools.correlate_intel_with_siem.invoke({'query':text[:80]})
    return chat(text,history,tool_context)
