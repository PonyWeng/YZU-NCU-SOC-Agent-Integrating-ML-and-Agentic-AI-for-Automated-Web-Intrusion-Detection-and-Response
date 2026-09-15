"""
assistant/command_handler.py
Rule-based command handler. Never calls OpenAI.

Supported commands:
  /help
  /status
  /logs recent
  /check <IP>
  /blacklist list
  /ban <IP>
  /unban <IP>
"""

import json
import os
import re
from datetime import datetime, timezone

BLACKLIST_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "blacklist.json")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

HELP_TEXT = (
    "NIDS Security Assistant — Commands\n"
    "------------------------------------\n"
    "/help              Show this help\n"
    "/status            System & alert status\n"
    "/logs recent       Last 5 attack detections\n"
    "/check <IP>        IP reputation lookup\n"
    "/blacklist list    Show blacklisted IPs\n"
    "/ban <IP>          Add IP to blacklist\n"
    "/unban <IP>        Remove IP from blacklist\n"
    "------------------------------------\n"
    "Or ask any cybersecurity question."
)


# ── Blacklist helpers ──────────────────────────────────────────

def _load_blacklist() -> dict:
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Handle both formats: {"ips": [...]} and legacy [...]
        if isinstance(data, list):
            return {"ips": [{"ip": e, "reason": "Legacy entry"} if isinstance(e, str) else e for e in data]}
        return data
    return {"ips": []}


def _save_blacklist(data: dict) -> None:
    with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_blacklisted_ips() -> list[str]:
    """Public interface for other modules (e.g., firewall integration)."""
    return [e["ip"] for e in _load_blacklist().get("ips", [])]


# ── Commands ───────────────────────────────────────────────────

def handle_command(text: str) -> str:
    parts = text.strip().split()
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd == "/help":
        return HELP_TEXT

    if cmd == "/status":
        return _cmd_status()

    if cmd == "/logs":
        if args and args[0] == "recent":
            return _cmd_logs_recent()
        return "Usage: /logs recent"

    if cmd == "/check":
        if not args:
            return "Usage: /check <IP>"
        return _cmd_check(args[0])

    if cmd == "/blacklist":
        if args and args[0] == "list":
            return _cmd_blacklist_list()
        return "Usage: /blacklist list"

    if cmd == "/ban":
        if not args:
            return "Usage: /ban <IP>"
        return _cmd_ban(args[0])

    if cmd == "/unban":
        if not args:
            return "Usage: /unban <IP>"
        return _cmd_unban(args[0])

    return f"Unknown command: {cmd}\nType /help for available commands."


def _cmd_status() -> str:
    from siem import store
    store.init_db()
    data = store.overview(hours=0)
    collector = store.get_state('collector', {'status': 'not_started'})
    return (f"SIEM Status\nStorage: SQLite\nCollector: {collector['status']}"
            f"\nTotal records: {data['counts']['total']}\nAttack records: {data['counts']['attacks']}"
            f"\nOpen incidents: {data['counts']['open_incidents']}"
            f"\nBlocked IPs: {len(get_blacklisted_ips())}")


def _cmd_logs_recent() -> str:
    from siem import store
    store.init_db()
    with store.connection() as db:
        rows = db.execute('SELECT * FROM events WHERE attack>0 ORDER BY timestamp DESC LIMIT 5').fetchall()
    if not rows:
        return '目前資料庫沒有攻擊偵測紀錄。收到新的 Web 請求後，系統會持續進行分類。'
    from collections import Counter
    counts=Counter(store.LABELS.get(r['attack'],'未知') for r in rows)
    summary='、'.join(f'{name} {count} 筆' for name,count in counts.items())
    lines=[f'查到最近 {len(rows)} 筆攻擊偵測，包含{summary}。',
           f'以下是全部歷史資料中最新的紀錄，時間範圍：{rows[-1]["timestamp"]} 至 {rows[0]["timestamp"]}。','']
    for i,r in enumerate(rows,1):
        lines.extend([f'{i}. {store.LABELS.get(r["attack"])}｜來源 {r["src_ip"]}',
                      f'目標：{r["service_name"]} ({r["service_host"]}:{r["service_port"]})',
                      f'時間：{r["timestamp"]}｜HTTP {r["status"]}', f'請求：{r["method"]} {r["url"]}',''])
    lines.append('這些是模型偵測結果，不代表攻擊已成功。建議先核對原始日誌與目標服務回應，再決定是否封鎖來源。')
    return '\n'.join(lines)


def _cmd_check(ip: str) -> str:
    if not IP_RE.match(ip):
        return f"Invalid IP address: {ip}\nUsage: /check <IP>  (e.g. /check 1.2.3.4)"

    from assistant.threat_intel import check_ip
    try:
        result = check_ip(ip)
    except Exception as e:
        return f"IP lookup failed: {e}"

    if not result:
        return f"IP Report: {ip}\nNo data returned from threat intel providers."

    lines = [f"IP Reputation Report: {ip}", "-" * 28]
    for key, val in result.items():
        lines.append(f"{key:14}: {val}")

    if ip in get_blacklisted_ips():
        lines.append("-" * 28)
        lines.append("* This IP is in your local blacklist")

    return "\n".join(lines)


def _cmd_blacklist_list() -> str:
    bl = _load_blacklist()
    if not bl["ips"]:
        return '目前封鎖清單是空的，沒有已列入的 IP。可使用 /ban IP 新增封鎖。'
    lines = [f"目前封鎖清單共有 {len(bl['ips'])} 個 IP，以下是實際儲存的清單：", "目前封鎖執行範圍是 Apache；Flask、Django 尚未接上封鎖執行器。", ""]
    for i, entry in enumerate(bl["ips"], 1):
        added = str(entry.get("added_at", "?"))[:10]
        reason = entry.get("reason", "Manual ban")
        lines.append(f"{i}. {entry['ip']}")
        lines.append(f"   加入時間：{added}｜原因：{reason}")
    return "\n".join(lines)


def _cmd_ban(ip: str) -> str:
    from assistant.enforcer import change_ban
    try:
        change_ban(ip, True, 'Manual ban via LINE', 'line')
        return f'IP {ip} blocked. Apache rules updated.'
    except Exception as exc:
        return f'Ban failed: {exc}'


def _cmd_unban(ip: str) -> str:
    from assistant.enforcer import change_ban
    try:
        change_ban(ip, False, 'Manual unban via LINE', 'line')
        return f'IP {ip} unblocked. Apache rules updated.'
    except Exception as exc:
        return f'Unban failed: {exc}'


def _tw_now() -> str:
    from datetime import timedelta
    return (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
