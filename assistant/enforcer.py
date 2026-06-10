"""
assistant/enforcer.py
Syncs blacklist.json → htdocs/.htaccess to block banned IPs at the Apache layer.

Apache 2.4 reads .htaccess on every request (AllowOverride All is set in
docker-compose.yml), so no container restart or reload is required.
Banned IPs receive HTTP 403 Forbidden.
"""

import json
import os
import re

_BASE = os.path.dirname(os.path.dirname(__file__))
HTDOCS_DIR     = os.path.join(_BASE, "htdocs")
HTACCESS_PATH  = os.path.join(HTDOCS_DIR, ".htaccess")
BLACKLIST_FILE = os.path.join(_BASE, "blacklist.json")

# Never block these — would lock out the server itself
_PROTECTED = {"127.0.0.1", "::1", "0.0.0.0"}
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _load_banned_ips() -> list[str]:
    if not os.path.exists(BLACKLIST_FILE):
        return []
    with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        entries = data
    else:
        entries = [e["ip"] for e in data.get("ips", [])]
    return [ip for ip in entries if _IP_RE.match(ip) and ip not in _PROTECTED]


def _write_htaccess(banned_ips: list[str]) -> None:
    os.makedirs(HTDOCS_DIR, exist_ok=True)
    lines = [
        "# Managed by YZU NIDS Platform - DO NOT EDIT MANUALLY",
        "",
        "# Clean URL: /search -> /search.html (preserves ?q= params)",
        "RewriteEngine On",
        "RewriteRule ^search$ /search.html [QSA,L]",
        "",
        "# IP Blacklist - banned IPs receive 403 Forbidden",
    ]
    if banned_ips:
        lines += ["<RequireAll>", "    Require all granted"]
        for ip in banned_ips:
            lines.append(f"    Require not ip {ip}")
        lines.append("</RequireAll>")
    else:
        lines.append("# No IPs currently blacklisted - all traffic allowed.")
    lines.append("")
    with open(HTACCESS_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))


def apply_blacklist() -> list[str]:
    """
    Read blacklist.json, write .htaccess, return the list of currently blocked IPs.
    Call this after any ban/unban operation.
    """
    banned = _load_banned_ips()
    _write_htaccess(banned)
    return banned


def ban_ips(new_ips: list[str], reason: str = "Auto-ban by NIDS") -> list[str]:
    """
    Add new_ips to blacklist.json (skipping duplicates and protected IPs),
    then sync .htaccess.  Returns only the IPs that were newly added.
    """
    from datetime import datetime, timezone

    valid = [ip for ip in new_ips if _IP_RE.match(ip) and ip not in _PROTECTED]
    if not valid:
        return []

    if not os.path.exists(BLACKLIST_FILE):
        data = {"ips": []}
    else:
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        data = raw if isinstance(raw, dict) else {"ips": raw}

    existing = {e["ip"] for e in data["ips"]}
    newly_added = []
    for ip in valid:
        if ip not in existing:
            data["ips"].append({
                "ip": ip,
                "added_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
            })
            newly_added.append(ip)

    with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    _write_htaccess(_load_banned_ips())
    return newly_added
