"""Request-time IP blocking shared by the Flask and Django demo targets."""
import ipaddress
import json
import os
from pathlib import Path

BLACKLIST_FILE = Path(os.getenv('SIEM_BLACKLIST_PATH', '/runtime/blacklist.json'))


def client_ip(headers, remote_addr=''):
    values = (
        headers.get('CF-Connecting-IP'),
        headers.get('X-Real-IP'),
        (headers.get('X-Forwarded-For') or '').split(',')[0].strip(),
        headers.get('X-Demo-Source-IP'),
        remote_addr,
    )
    for value in values:
        try:
            return str(ipaddress.ip_address((value or '').strip()))
        except ValueError:
            continue
    return ''


def is_blocked(ip, service):
    if not ip or not BLACKLIST_FILE.exists():
        return False
    try:
        data=json.loads(BLACKLIST_FILE.read_text(encoding='utf-8'))
        entries=data if isinstance(data,list) else data.get('ips',[])
    except (OSError, ValueError, TypeError):
        return False
    for entry in entries:
        if isinstance(entry,str):
            entry={'ip':entry,'scope':'all'}
        if entry.get('ip') == ip and entry.get('scope','all') in ('all',service):
            return True
    return False
