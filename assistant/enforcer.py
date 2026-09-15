"""Shared, locked IP enforcement for dashboard and LINE."""
import ipaddress
import json
import os
import tempfile
from pathlib import Path
from filelock import FileLock

ROOT = Path(__file__).resolve().parents[1]
BLACKLIST_FILE = ROOT / 'blacklist.json'
HTACCESS_PATH = ROOT / 'htdocs' / '.htaccess'

def _load():
    if not BLACKLIST_FILE.exists():
        return {'ips': []}
    data = json.loads(BLACKLIST_FILE.read_text(encoding='utf-8'))
    entries = data if isinstance(data,list) else data.get('ips',[])
    return {'ips': [{'ip': e, 'reason':'Legacy entry'} if isinstance(e,str) else e for e in entries]}

def _validate(ip):
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise ValueError('Invalid IP address')
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise ValueError('Loopback, unspecified and multicast addresses cannot be blocked')
    return str(addr)

def _rules(data):
    ips = [_validate(e['ip']) for e in data['ips']]
    text = '# Managed by NCU-PDCLAB mini SIEM - DO NOT EDIT MANUALLY\n\nRewriteEngine On\nRewriteRule ^search$ /search.html [QSA,L]\n\n'
    if ips:
        text += '<RequireAll>\n    Require all granted\n'
        text += ''.join(f'    Require not ip {ip}\n' for ip in ips)
        text += '</RequireAll>\n'
    return text

def _atomic(path, text):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent,suffix='.tmp')
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def apply_blacklist():
    with FileLock(str(BLACKLIST_FILE)+'.lock'):
        data = _load()
        _atomic(HTACCESS_PATH,_rules(data))
        return [e['ip'] for e in data['ips']]

def change_ban(ip, blocked, reason, actor='line'):
    from siem import store
    ip = _validate(ip)
    store.init_db()
    with FileLock(str(BLACKLIST_FILE)+'.lock'):
        data = _load()
        exists = any(e['ip']==ip for e in data['ips'])
        if blocked and not exists:
            data['ips'].append({'ip':ip,'added_at':store.now(),'reason':reason})
        elif not blocked:
            data['ips'] = [e for e in data['ips'] if e['ip']!=ip]
        original = HTACCESS_PATH.read_text(encoding='utf-8') if HTACCESS_PATH.exists() else None
        _atomic(HTACCESS_PATH,_rules(data))
        try:
            _atomic(BLACKLIST_FILE,json.dumps(data,ensure_ascii=False,indent=2))
        except Exception:
            if original is not None:
                _atomic(HTACCESS_PATH,original)
            else:
                HTACCESS_PATH.unlink(missing_ok=True)
            raise
    store.audit('ip.ban' if blocked else 'ip.unban',f'{ip}: {reason}',actor)
    return {'ok':True,'ip':ip,'blocked':blocked,'enforcement':'Apache rules written'}

def ban_ips(new_ips, reason='Manual ban'):
    added=[]
    for ip in new_ips:
        if ip not in [e['ip'] for e in _load()['ips']]:
            change_ban(ip,True,reason,'system')
            added.append(ip)
    return added
