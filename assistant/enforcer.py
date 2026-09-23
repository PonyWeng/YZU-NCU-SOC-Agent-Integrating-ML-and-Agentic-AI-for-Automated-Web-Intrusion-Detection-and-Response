"""Shared, locked IP enforcement for dashboard and LINE."""
import ipaddress
import json
import os
import tempfile
from pathlib import Path
from filelock import FileLock

ROOT = Path(__file__).resolve().parents[1]
BLACKLIST_FILE = Path(os.getenv('SIEM_BLACKLIST_PATH',str(ROOT / 'blacklist.json')))
HTACCESS_PATH = Path(os.getenv('SIEM_HTACCESS_PATH',str(ROOT / 'htdocs' / '.htaccess')))
SCOPES = {'all', 'apache', 'flask', 'django'}

def _load():
    if not BLACKLIST_FILE.exists():
        return {'ips': []}
    data = json.loads(BLACKLIST_FILE.read_text(encoding='utf-8'))
    entries = data if isinstance(data,list) else data.get('ips',[])
    normalized=[]
    for entry in entries:
        item={'ip':entry,'reason':'Legacy entry'} if isinstance(entry,str) else dict(entry)
        item['scope'] = item.get('scope') if item.get('scope') in SCOPES else 'all'
        normalized.append(item)
    return {'ips': normalized}

def load_blacklist():
    """Return the canonical blacklist configured by SIEM_BLACKLIST_PATH."""
    return _load()

def _scope(value):
    value=(value or 'all').strip().lower()
    if value not in SCOPES:
        raise ValueError('Invalid service scope')
    return value

def _validate(ip):
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise ValueError('Invalid IP address')
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise ValueError('Loopback, unspecified and multicast addresses cannot be blocked')
    return str(addr)

def _rules(data):
    ips = [_validate(e['ip']) for e in data['ips'] if e.get('scope','all') in ('all','apache')]
    text = '# Managed by NCU-PDCLAB mini SIEM - DO NOT EDIT MANUALLY\n\nRewriteEngine On\nRewriteRule ^search$ /search.html [QSA,L]\n\n'
    if ips:
        text += '<RequireAll>\n    Require all granted\n'
        text += ''.join(f'    Require not ip {ip}\n' for ip in ips)
        text += '</RequireAll>\n'
    return text

def _atomic(path, text, mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent,suffix='.tmp')
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp,mode)
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def apply_blacklist():
    with FileLock(str(BLACKLIST_FILE)+'.lock'):
        data = _load()
        _atomic(HTACCESS_PATH,_rules(data),0o644)
        return [e['ip'] for e in data['ips']]

def change_ban(ip, blocked, reason, actor='line', scope='all'):
    from siem import store
    ip = _validate(ip)
    scope = _scope(scope)
    store.init_db()
    with FileLock(str(BLACKLIST_FILE)+'.lock'):
        data = _load()
        exists = any(e['ip']==ip and e.get('scope','all')==scope for e in data['ips'])
        if blocked and not exists:
            data['ips'].append({'ip':ip,'scope':scope,'added_at':store.now(),'reason':reason})
        elif not blocked:
            data['ips'] = [e for e in data['ips'] if not (e['ip']==ip and e.get('scope','all')==scope)]
        original = HTACCESS_PATH.read_text(encoding='utf-8') if HTACCESS_PATH.exists() else None
        _atomic(HTACCESS_PATH,_rules(data),0o644)
        try:
            _atomic(BLACKLIST_FILE,json.dumps(data,ensure_ascii=False,indent=2),0o644)
        except Exception:
            if original is not None:
                _atomic(HTACCESS_PATH,original,0o644)
            else:
                HTACCESS_PATH.unlink(missing_ok=True)
            raise
    store.audit('ip.ban' if blocked else 'ip.unban',f'{ip} [{scope}]: {reason}',actor)
    return {'ok':True,'ip':ip,'scope':scope,'blocked':blocked,'enforcement':'Service rules updated'}

def ban_ips(new_ips, reason='Manual ban'):
    added=[]
    for ip in new_ips:
        if ip not in [e['ip'] for e in _load()['ips']]:
            change_ban(ip,True,reason,'system')
            added.append(ip)
    return added
