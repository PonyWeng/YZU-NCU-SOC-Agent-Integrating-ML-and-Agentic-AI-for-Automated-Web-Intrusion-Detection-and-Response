"""
assistant/tools.py
LangChain tool definitions for the NIDS agent.
Each tool wraps existing logic — no duplicate implementation.
"""

import re

import requests
from langchain_core.tools import tool

from config import RAG_API_URL

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
    from assistant.command_handler import _cmd_ban
    return _cmd_ban(ip)


@tool
def unban_ip_address(ip: str) -> str:
    """
    Remove an IP address from the blacklist, restoring its access to the server.
    Use when the user asks to unban, unblock, or remove an IP from the blacklist.
    """
    ip = ip.strip()
    if not _valid_ip(ip):
        return f"Invalid IP address: {ip}"
    from assistant.command_handler import _cmd_unban
    return _cmd_unban(ip)


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
    Retrieve the 5 most recent attack detections from Elasticsearch.
    Shows attack type, timestamp, source IP, and payload URL for each event.
    Use when the user asks about recent attacks, latest logs, or recent detections.
    """
    from assistant.command_handler import _cmd_logs_recent
    return _cmd_logs_recent()


@tool
def get_system_status() -> str:
    """
    Get the current NIDS platform status: Elasticsearch cluster health,
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
    try:
        resp = requests.post(RAG_API_URL, json={"text": query}, timeout=60)
        if resp.status_code == 200:
            result = resp.json().get("summary", "").strip()
            if result and "don't know" not in result.lower():
                return result
        return "No relevant information found in knowledge base."
    except Exception as e:
        return f"Knowledge base unavailable: {e}"


NIDS_TOOLS = [
    check_ip_reputation,
    ban_ip_address,
    unban_ip_address,
    list_blocked_ips,
    get_recent_attack_logs,
    get_system_status,
    search_security_knowledge,
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
    "    查詢最近 5 筆攻擊紀錄（ES）",
    "    例：「最近的攻擊紀錄」",
    "        \"recent attacks\"",
    "",
    "[6] get_system_status",
    "    查詢系統狀態（ES 健康、封鎖數、日誌大小）",
    "    例：「系統狀態」",
    "        \"system status\"",
    "",
    "[7] search_security_knowledge",
    "    查詢本地資安知識庫（OWASP / 攻擊手法）",
    "    例：「什麼是 XSS？」",
    "        \"how to prevent SQL injection?\"",
    "",
    SEP,
    "也可複合描述，例：",
    "「封鎖 1.2.3.4 並查詢他的 IP 情報」",
])
