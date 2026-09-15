"""
assistant/tools.py
LangChain tool definitions for the NIDS agent.
Each tool wraps existing logic — no duplicate implementation.
"""

import json
import re
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool


IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _valid_ip(ip: str) -> bool:
    return bool(IP_RE.match(ip.strip()))


@tool
def check_ip_reputation(ip: str) -> str:
    """
    Check the reputation and threat intelligence of an IP address.
    Returns abuse confidence score, geolocation, ISP, and local blacklist status.
    Use when the user asks to investigate, look up, or check an IP.
    """
    ip = ip.strip()
    if not _valid_ip(ip):
        return f"Invalid IP address: {ip}"
    from assistant.command_handler import _cmd_check
    return _cmd_check(ip)


@tool
def ban_ip_address(ip: str) -> str:
    """
    Add an IP address to the blacklist and enforce the ban via Apache .htaccess.
    The banned IP will immediately receive HTTP 403 Forbidden on all requests.
    Use when the user asks to ban, block, or blacklist an IP.
    """
    ip = ip.strip()
    if not _valid_ip(ip):
        return f"Invalid IP address: {ip}"
    from assistant.enforcer import change_ban
    try:
        change_ban(ip, True, 'Agent tool ban', 'agent')
        return f'IP {ip} blocked. Apache rules updated.'
    except Exception as exc:
        return f'Ban failed: {exc}'


@tool
def unban_ip_address(ip: str) -> str:
    """
    Remove an IP address from the blacklist, restoring its access to the server.
    Use when the user asks to unban, unblock, or remove an IP from the blacklist.
    """
    ip = ip.strip()
    if not _valid_ip(ip):
        return f"Invalid IP address: {ip}"
    from assistant.enforcer import change_ban
    try:
        change_ban(ip, False, 'Agent tool unban', 'agent')
        return f'IP {ip} unblocked. Apache rules updated.'
    except Exception as exc:
        return f'Unban failed: {exc}'


@tool
def list_blocked_ips() -> str:
    """
    List all currently blocked/blacklisted IP addresses with their ban date and reason.
    Use when the user asks to see the blacklist, blocked IPs, or banned addresses.
    """
    from assistant.command_handler import _cmd_blacklist_list
    return _cmd_blacklist_list()


@tool
def get_recent_attack_logs() -> str:
    """
    Retrieve the 5 most recent attack detections from the local SIEM event store.
    Shows attack type, timestamp, source IP, and payload URL for each event.
    Use when the user asks about recent attacks, latest logs, or recent detections.
    """
    from assistant.command_handler import _cmd_logs_recent
    return _cmd_logs_recent()


@tool
def get_system_status() -> str:
    """
    Get the current NIDS platform status: local SIEM storage health,
    total log records, attack event count, blacklist size, and log file size.
    Use when the user asks about system health, status, or platform statistics.
    """
    from assistant.command_handler import _cmd_status
    return _cmd_status()


@tool
def search_security_knowledge(query: str) -> str:
    """
    Search the local RAG knowledge base for cybersecurity information.
    Covers attack techniques, CVEs, OWASP Top 10, defense strategies,
    and incident response procedures.
    Use to answer general cybersecurity questions with grounded knowledge.
    """
    return "本機 RAG/Ollama 已移除；請先在 AI 設定中配置外部 AI Provider。"


@tool
def list_security_news(query: str = "") -> str:
    """List at most 10 cached security-news items, optionally filtered by keyword."""
    from siem import store
    cached=store.get_state('intel_news_cache',{'items':[]}).get('items',[])
    q=query.strip().lower()
    tokens=[x for x in re.findall(r'[\w\u4e00-\u9fff]{2,}',q) if x not in {'新聞','資安','最近','近期','查看','細節','企業','事件','目前'}]
    ranked=[]
    for index,item in enumerate(cached):
        haystack=(item.get('title','')+' '+item.get('source','')).lower()
        score=sum(1 for token in tokens if token in haystack)
        if not q or score: ranked.append((score,-index,item))
    rows=[x[2] for x in sorted(ranked,reverse=True)[:10]]
    return json.dumps({'count':len(rows),'items':[{'id':cached.index(x)+1,'title':x.get('title'),'source':x.get('source'),'published':x.get('published')} for x in rows]},ensure_ascii=False)


@tool
def read_security_news(news_id: int) -> str:
    """Read one cached news item by ID and fetch a bounded plain-text excerpt from its known URL."""
    from siem import store
    rows=store.get_state('intel_news_cache',{'items':[]}).get('items',[])
    if news_id<1 or news_id>len(rows): return '找不到指定新聞 ID。'
    item=rows[news_id-1]; result={'id':news_id,'title':item.get('title'),'source':item.get('source'),'published':item.get('published'),'url':item.get('url'),'excerpt':item.get('summary','')}
    host=(urlparse(item.get('url','')).hostname or '').lower()
    if host and host!='news.google.com':
        try:
            response=requests.get(item.get('url',''),headers={'User-Agent':'NCU-PDCLAB-mini-SIEM/1.0'},timeout=12,allow_redirects=True)
            response.raise_for_status(); text=re.sub(r'(?is)<(script|style|svg).*?>.*?</\1>',' ',response.text[:250000]); text=re.sub(r'(?s)<[^>]+>',' ',text); text=re.sub(r'\s+',' ',text).strip()
            if text and not re.search(r'body\s*\{|font-family|--[a-z-]+:',text[:500],re.I): result['excerpt']=text[:2500]
        except Exception:
            pass
    if not result['excerpt']: result['excerpt']='目前只有新聞標題、來源與日期，尚未取得可用正文。'
    return json.dumps(result,ensure_ascii=False)


@tool
def list_risk_ips(query: str = "") -> str:
    """List at most 20 locally cached Tor/FireHOL risk IPs, optionally matching an IP fragment."""
    from siem import store
    q=query.strip(); params=[]; where="kind='ip' AND source IN ('Tor Exit Nodes','FireHOL Level 1')"
    if q: where+=' AND value LIKE ?'; params.append('%'+q+'%')
    with store.connection() as db: rows=[dict(r) for r in db.execute(f'SELECT value,source,confidence,notes,last_seen FROM intelligence WHERE {where} ORDER BY last_seen DESC LIMIT 20',params)]
    return json.dumps({'count':len(rows),'items':rows},ensure_ascii=False)


@tool
def list_phishing_sites(query: str = "") -> str:
    """List at most 20 cached OpenPhish URLs with a local heuristic category; never visits the URLs."""
    from siem import store
    q=query.strip(); params=[]; where="kind='url' AND source='OpenPhish'"
    if q: where+=' AND (value LIKE ? OR notes LIKE ?)'; params.extend(['%'+q+'%','%'+q+'%'])
    with store.connection() as db: rows=[dict(r) for r in db.execute(f'SELECT value,source,confidence,notes,last_seen FROM intelligence WHERE {where} ORDER BY last_seen DESC LIMIT 20',params)]
    def category(url):
        s=url.lower()
        if any(x in s for x in ('microsoft','office','outlook','login','signin')): return '帳號／憑證竊取'
        if any(x in s for x in ('bank','pay','wallet','invoice')): return '金融／付款詐騙'
        if any(x in s for x in ('dhl','fedex','post','delivery')): return '物流冒用'
        return '未分類釣魚網站'
    items=[{'masked_url':r['value'].replace('://','[://]').replace('/','／'),'host':urlparse(r['value']).hostname,'category':category(r['value']),'source':r['source'],'confidence':r['confidence'],'last_seen':r['last_seen']} for r in rows]
    return json.dumps({'count':len(items),'items':items,'notice':'分類為本機 URL 特徵初判，未連線至釣魚網站。'},ensure_ascii=False)


@tool
def correlate_intel_with_siem(query: str = "") -> str:
    """Correlate local risk-IP intelligence with SIEM events and incidents; returns at most 20 matches."""
    from siem import store
    with store.connection() as db:
        rows=[dict(r) for r in db.execute('''SELECT i.value src_ip,i.source,i.confidence,count(e.id) event_count,
          max(e.timestamp) last_event,group_concat(DISTINCT e.service_name) services
          FROM intelligence i JOIN events e ON i.kind='ip' AND i.value=e.src_ip
          WHERE i.verdict IN ('malicious','suspicious') GROUP BY i.value,i.source,i.confidence
          ORDER BY event_count DESC,last_event DESC LIMIT 20''')]
    return json.dumps({'count':len(rows),'items':rows},ensure_ascii=False)


NIDS_TOOLS = [
    check_ip_reputation,
    ban_ip_address,
    unban_ip_address,
    list_blocked_ips,
    get_recent_attack_logs,
    get_system_status,
    search_security_knowledge,
    list_security_news,
    read_security_news,
    list_risk_ips,
    list_phishing_sites,
    correlate_intel_with_siem,
]

SEP = "─" * 34

HELP_TEXT = "\n".join([
    "NIDS Security Assistant",
    "直接用自然語言描述需求，AI 會自動選擇工具",
    SEP,
    "",
    "[1] check_ip_reputation",
    "    查詢 IP 威脅情報（AbuseIPDB + IPinfo）",
    "    例：「查一下 1.2.3.4」",
    "        \"check ip 45.142.212.100\"",
    "",
    "[2] ban_ip_address",
    "    封鎖 IP（加入黑名單，Apache 立即 403）",
    "    例：「封鎖 192.168.1.1」",
    "        \"ban 1.2.3.4\"",
    "",
    "[3] unban_ip_address",
    "    解除封鎖 IP",
    "    例：「解除封鎖 1.2.3.4」",
    "        \"unban 192.168.1.1\"",
    "",
    "[4] list_blocked_ips",
    "    列出目前所有封鎖的 IP",
    "    例：「黑名單有哪些 IP？」",
    "        \"show blacklist\"",
    "",
    "[5] get_recent_attack_logs",
    "    查詢最近 5 筆攻擊紀錄（本機 SIEM）",
    "    例：「最近的攻擊紀錄」",
    "        \"recent attacks\"",
    "",
    "[6] get_system_status",
    "    查詢系統狀態（收集器狀態、封鎖數、日誌大小）",
    "    例：「系統狀態」",
    "        \"system status\"",
    "",
    "[7] search_security_knowledge",
    "    查詢本地資安知識庫（OWASP / 攻擊手法）",
    "    例：「什麼是 XSS？」",
    "        \"how to prevent SQL injection?\"",
    "",
    "[8] list_security_news / read_security_news",
    "    查詢近期資安新聞，或依新聞 ID 讀取指定內容",
    "",
    "[9] list_risk_ips / list_phishing_sites",
    "    查詢本機風險 IP 與近期釣魚網站情資",
    "",
    "[10] correlate_intel_with_siem",
    "    將外部情資與本機日誌、事件及受保護服務交叉比對",
    "",
    SEP,
    "也可複合描述，例：",
    "「封鎖 1.2.3.4 並查詢他的 IP 情報」",
])
