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
            return {"ips": data}
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
    from config import ES_HOST, ES_USER, ES_PASSWORD
    from elasticsearch import Elasticsearch

    lines = ["System Status", "-" * 24]

    # Elasticsearch
    try:
        es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
        health = es.cluster.health()
        lines.append(f"Elasticsearch : {health['status'].upper()}")

        total = es.count(index="prediction-logs-*")["count"]
        attacks = es.count(
            index="prediction-logs-*",
            query={"range": {"attack_prediction": {"gt": 0}}},
        )["count"]
        lines.append(f"Total records : {total}")
        lines.append(f"Attack records: {attacks}")
    except Exception:
        lines.append("Elasticsearch : OFFLINE")

    # Blacklist
    bl = _load_blacklist()
    lines.append(f"Blacklisted   : {len(bl['ips'])} IP(s)")

    # Apache log size
    log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "apache-logs", "access.log")
    if os.path.exists(log_path):
        size_kb = os.path.getsize(log_path) // 1024
        lines.append(f"Access log    : {size_kb} KB")

    lines.append(f"Time (TW)     : {_tw_now()}")
    return "\n".join(lines)


def _cmd_logs_recent() -> str:
    from config import ES_HOST, ES_USER, ES_PASSWORD
    from elasticsearch import Elasticsearch

    LABELS = {1: "SQLi", 2: "XSS", 3: "DirTraversal"}

    try:
        es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
        result = es.search(
            index="prediction-logs-*",
            query={"range": {"attack_prediction": {"gt": 0}}},
            size=5,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
        hits = result["hits"]["hits"]
        if not hits:
            return "No attack records found."

        lines = ["Recent Attacks (last 5)", "-" * 24]
        for i, hit in enumerate(hits, 1):
            src = hit["_source"]
            ts = str(src.get("@timestamp", "?"))[:19].replace("T", " ")
            attack = LABELS.get(int(src.get("attack_prediction", 0)), "Unknown")
            url = str(src.get("URL", "?"))[:55]
            lines.append(f"{i}. [{attack}] {ts}")
            lines.append(f"   {url}")
        return "\n".join(lines)

    except Exception as e:
        return f"Error fetching logs: {e}"


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
        return "Blacklist is currently empty.\nUse /ban <IP> to add an IP."
    lines = [f"Blacklisted IPs ({len(bl['ips'])} total)", "-" * 28]
    for i, entry in enumerate(bl["ips"], 1):
        added = str(entry.get("added_at", "?"))[:10]
        reason = entry.get("reason", "Manual ban")
        lines.append(f"{i}. {entry['ip']}")
        lines.append(f"   Added: {added}  Reason: {reason}")
    return "\n".join(lines)


def _cmd_ban(ip: str) -> str:
    if not IP_RE.match(ip):
        return f"Invalid IP address: {ip}\nUsage: /ban <IP>  (e.g. /ban 192.168.1.1)"

    bl = _load_blacklist()
    if any(e["ip"] == ip for e in bl["ips"]):
        return f"IP {ip} is already in the blacklist."

    bl["ips"].append({
        "ip": ip,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "reason": "Manual ban via LINE",
    })
    _save_blacklist(bl)
    total = len(bl["ips"])

    # Sync .htaccess so Apache enforces the ban immediately
    try:
        from assistant.enforcer import apply_blacklist
        apply_blacklist()
        enforce_msg = "Apache enforcement: active (403 Forbidden)"
    except Exception as e:
        enforce_msg = f"Apache enforcement: failed ({e})"

    return (
        f"IP {ip} has been added to the blacklist.\n"
        f"Total blacklisted IPs: {total}\n"
        f"{enforce_msg}"
    )


def _cmd_unban(ip: str) -> str:
    bl = _load_blacklist()
    before = len(bl["ips"])
    bl["ips"] = [e for e in bl["ips"] if e["ip"] != ip]
    if len(bl["ips"]) == before:
        return f"IP {ip} was not found in the blacklist."
    _save_blacklist(bl)
    remaining = len(bl["ips"])

    # Sync .htaccess to remove the ban
    try:
        from assistant.enforcer import apply_blacklist
        apply_blacklist()
        enforce_msg = "Apache enforcement: updated"
    except Exception as e:
        enforce_msg = f"Apache enforcement: failed ({e})"

    return (
        f"IP {ip} has been removed from the blacklist.\n"
        f"Total blacklisted IPs: {remaining}\n"
        f"{enforce_msg}"
    )


def _tw_now() -> str:
    from datetime import timedelta
    return (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
