"""
assistant/ai_handler.py
Handles AI-based question answering via OpenAI + RAG.

Scope: cybersecurity topics only.
Output: plain text — no Markdown (LINE does not render it).
"""

import requests
import openai

from config import OPENAI_API_KEY, RAG_API_URL

_client = openai.OpenAI(api_key=OPENAI_API_KEY)

# ── Scope filter ──────────────────────────────────────────────
# Question must contain at least one of these keywords to be answered.
SECURITY_KEYWORDS = {
    "attack", "malware", "virus", "trojan", "ransomware", "phishing",
    "vulnerability", "exploit", "cve", "sql injection", "xss", "csrf",
    "firewall", "intrusion", "nids", "ids", "ips", "ddos", "dos",
    "port scan", "brute force", "penetration", "pentest", "zero day",
    "injection", "authentication", "encryption", "ssl", "tls", "vpn",
    "cybersecurity", "security", "hacker", "breach", "incident",
    "log", "alert", "threat", "risk", "patch", "backdoor",
    "payload", "reverse shell", "privilege escalation",
    "ip address", "blacklist", "whitelist", "blocklist", "ban",
    "access control", "password", "credential", "token",
    "network", "packet", "protocol", "http", "https", "ssh", "ftp",
    "server", "apache", "nginx", "web application",
    "protect", "defend", "block", "monitor", "detect",
}

OUT_OF_SCOPE_MSG = (
    "I can only answer cybersecurity questions or questions about "
    "your protected systems. Please ask about security topics, "
    "attack types, or system alerts."
)

SYSTEM_PROMPT = (
    "You are a cybersecurity assistant for a network intrusion detection system (NIDS). "
    "Answer ONLY cybersecurity-related questions. "
    "Be concise — keep answers under 200 words. "
    "Output plain text only. "
    "Do NOT use Markdown: no ** bold **, no * bullets *, no # headers. "
    "Use plain numbered lists (1. 2. 3.) or dashes (- item) if needed."
)


def _is_security_related(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in SECURITY_KEYWORDS)


def _query_rag(question: str) -> str:
    """Call the existing RAG service for context. Returns empty string on failure."""
    try:
        resp = requests.post(
            RAG_API_URL,
            json={"text": question},
            timeout=12,
        )
        if resp.status_code == 200:
            summary = resp.json().get("summary", "").strip()
            # Skip if RAG returned its default "I don't know"
            if summary and "don't know" not in summary.lower():
                return summary
    except Exception:
        pass
    return ""


def handle_question(text: str) -> str:
    """
    Main entry point for non-command LINE messages.
    1. Scope check
    2. RAG context retrieval
    3. OpenAI completion
    """
    if not _is_security_related(text):
        return OUT_OF_SCOPE_MSG

    rag_context = _query_rag(text)

    user_content = text
    if rag_context:
        user_content = (
            f"Context from knowledge base:\n{rag_context}\n\n"
            f"Question: {text}"
        )

    try:
        resp = _client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_content},
            ],
            max_tokens=300,
            timeout=20,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"AI unavailable: {e}"
