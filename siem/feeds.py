"""Small, free threat-intelligence feed adapters for the mini SIEM."""
import csv
import html
import io
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse

from siem import store

CISA_KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
NEWS_FEEDS = [('Google News 台灣資安','https://news.google.com/rss/search?q=%E8%B3%87%E5%AE%89&hl=zh-TW&gl=TW&ceid=TW:zh-Hant'),('iThome 資安','https://www.ithome.com.tw/rss')]
TOR_EXIT_NODES = 'https://check.torproject.org/torbulkexitlist'
FIREHOL_LEVEL1 = 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset'
URLHAUS_RECENT = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
OPENPHISH_FEED = 'https://openphish.com/feed.txt'


def _fetch(url, timeout=20):
    request=urllib.request.Request(url,headers={'User-Agent':'NCU-PDCLAB-mini-SIEM/1.0'})
    with urllib.request.urlopen(request,timeout=timeout) as response:
        return response.read()


def sync_cisa():
    raise RuntimeError('CISA KEV／CVE 匯入目前已停用，情資範圍改為來源 IP 風險清單')
    data=json.loads(_fetch(CISA_KEV).decode('utf-8'))
    count=0
    with store.connection() as db:
        for item in data.get('vulnerabilities',[]):
            cve=item.get('cveID','').strip()
            if not cve: continue
            notes='；'.join(filter(None,[item.get('shortDescription',''),f"產品：{item.get('product','')}",f"廠商：{item.get('vendorProject','')}",f"截止：{item.get('dueDate','')}"]))
            now=store.now()
            db.execute('''INSERT INTO intelligence(kind,value,source,confidence,verdict,tags,first_seen,last_seen,notes)
              VALUES ('vulnerability',?,'CISA KEV',95,'malicious',?,?,?,?)
              ON CONFLICT(kind,value,source) DO UPDATE SET last_seen=excluded.last_seen,notes=excluded.notes,confidence=excluded.confidence''',
              (cve, json.dumps(['kev','exploited'],ensure_ascii=False),now,now,notes))
            count+=1
        store.audit('intel.sync','CISA KEV 更新 '+str(count)+' 筆',actor='system',db=db)
    store.set_state('intel_feed:cisa_kev',{'status':'ok','count':count,'updated_at':store.now(),'url':CISA_KEV})
    return count


def sync_urlhaus():
    raise RuntimeError('URLhaus 批次匯入目前已停用，待改為小型來源風險清單')

def _risk_ip_feed(url, source, confidence, tags, limit=1000):
    text=_fetch(url).decode('utf-8','replace'); ips=[]
    for line in text.splitlines():
        value=line.strip().split('#',1)[0].strip()
        if not value or '/' in value: continue
        try:
            import ipaddress
            ipaddress.ip_address(value)
        except ValueError: continue
        ips.append(value)
    ips=list(dict.fromkeys(ips))[:limit]; now=store.now()
    with store.connection() as db:
        for ip in ips:
            notes=f'{source} 公開風險清單；同步時間：{now}'
            db.execute('''INSERT INTO intelligence(kind,value,source,confidence,verdict,tags,first_seen,last_seen,notes)
              VALUES ('ip',?,?,?,?,?,?,?,?)
              ON CONFLICT(kind,value,source) DO UPDATE SET confidence=excluded.confidence,tags=excluded.tags,last_seen=excluded.last_seen,notes=excluded.notes''',
              (ip,source,confidence,'suspicious',json.dumps(tags,ensure_ascii=False),now,now,notes))
        store.audit('intel.sync',f'{source} 更新 {len(ips)} 筆',actor='system',db=db)
    store.set_state('intel_feed:'+source,{'status':'ok','count':len(ips),'updated_at':now,'url':url})
    return len(ips)

def sync_risk_ips():
    result={}
    for name,url,confidence,tags in [('Tor Exit Nodes',TOR_EXIT_NODES,55,['tor_exit','anonymous_proxy']),('FireHOL Level 1',FIREHOL_LEVEL1,80,['malicious_ip','aggregated_feed'])]:
        try: result[name]={'ok':True,'count':_risk_ip_feed(url,name,confidence,tags)}
        except Exception as exc: result[name]={'ok':False,'error':str(exc)[:300]}
    return result

def sync_phishing(limit=300):
    """Import a small OpenPhish URL set for analyst education."""
    raw=_fetch(OPENPHISH_FEED).decode('utf-8','replace'); rows=[]
    for value in raw.splitlines():
        value=value.strip()
        if value.startswith(('http://','https://')): rows.append(value)
    count=0; now=store.now()
    with store.connection() as db:
        for url in rows[:limit]:
            status='active'; threat='phishing'; tags='openphish,phishing'
            if not url.startswith(('http://','https://')): continue
            description=f'近期惡意／釣魚網址；威脅類型：{threat or "未分類"}；狀態：{status or "unknown"}'
            db.execute('''INSERT INTO intelligence(kind,value,source,confidence,verdict,tags,first_seen,last_seen,notes)
              VALUES ('url',?,'OpenPhish',90,'malicious',?,?,?,?)
              ON CONFLICT(kind,value,source) DO UPDATE SET last_seen=excluded.last_seen,notes=excluded.notes''',
              (url,json.dumps([x for x in tags.split(',') if x],ensure_ascii=False),now,now,description))
            count+=1
        store.audit('intel.sync',f'URLhaus 釣魚清單更新 {count} 筆',actor='system',db=db)
    store.set_state('intel_feed:phishing',{'status':'ok','count':count,'updated_at':now,'url':OPENPHISH_FEED})
    return count
    raw=_fetch(URLHAUS_RECENT).decode('utf-8','replace')
    rows=[]
    for row in csv.reader(line for line in raw.splitlines() if line and not line.startswith('#')):
        if len(row)>=7: rows.append(row)
    count=0
    with store.connection() as db:
        for row in rows[:300]:
            url=row[2].strip(); status=row[3].strip(); threat=row[5].strip(); tags=row[6].strip()
            if not url or not url.startswith(('http://','https://')): continue
            host=urlparse(url).hostname or ''
            if not host: continue
            now=store.now(); notes=f'URLhaus：{threat or "malicious URL"}；狀態：{status or "unknown"}；原始網址：{url}'
            db.execute('''INSERT INTO intelligence(kind,value,source,confidence,verdict,tags,first_seen,last_seen,notes)
              VALUES ('url',?,'URLhaus',90,'malicious',?,?,?,?)
              ON CONFLICT(kind,value,source) DO UPDATE SET last_seen=excluded.last_seen,notes=excluded.notes''',
              (url,json.dumps([x for x in tags.split(',') if x],ensure_ascii=False),now,now,notes))
            count+=1
            if host:
                db.execute('''INSERT OR IGNORE INTO intelligence(kind,value,source,confidence,verdict,tags,first_seen,last_seen,notes)
                  VALUES ('domain',?,'URLhaus',85,'malicious',?,?,?,?)''',
                  (host,json.dumps(['urlhaus','host'],ensure_ascii=False),now,now,notes))
        store.audit('intel.sync','URLhaus 更新 '+str(count)+' 筆',actor='system',db=db)
    store.set_state('intel_feed:urlhaus',{'status':'ok','count':count,'updated_at':store.now(),'url':URLHAUS_RECENT})
    return count


def sync_all():
    return sync_risk_ips()


def status():
    return {name:store.get_state('intel_feed:'+name,{'status':'not_synced'}) for name in ('Tor Exit Nodes','FireHOL Level 1')}

def sync_news(limit=100):
    items=[]
    for source,url in NEWS_FEEDS:
        try:
            root=ET.fromstring(_fetch(url))
            for entry in root.findall('.//item')[:50]:
                title=(entry.findtext('title') or '').strip(); link=(entry.findtext('link') or '').strip(); published=(entry.findtext('pubDate') or '').strip()
                description=(entry.findtext('description') or '').strip()
                description=html.unescape(re.sub(r'(?s)<[^>]+>',' ',description)); description=re.sub(r'\s+',' ',description).strip()[:1200]
                if title and link and 'CISA' not in source.upper(): items.append({'source':source,'title':title,'url':link,'published':published,'summary':description})
        except Exception:
            continue
    items=sorted(items,key=lambda x:x['published'],reverse=True)[:limit]
    if items:
        store.set_state('intel_news_cache',{'items':items,'updated_at':store.now()})
    return items

def news(limit=20):
    try:
        items=sync_news(max(limit,100))
        if items: return items[:limit]
    except Exception:
        pass
    cached=store.get_state('intel_news_cache',{'items':[]})
    return cached.get('items',[])[:limit]
