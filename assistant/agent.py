"""
assistant/agent.py
LangGraph ReAct agent — replaces hard-coded slash-command routing.

The LLM (Ollama llama3) acts as orchestrator:
  1. Reads the user's natural-language message
  2. Decides which tool(s) to call
  3. Receives tool results
  4. Synthesises a plain-text reply for LINE
"""

from assistant.tools import NIDS_TOOLS

SYSTEM_PROMPT = """\
You are a cybersecurity assistant for a Network Intrusion Detection System (NIDS) platform.
You help security analysts manage IP bans, investigate threats, and query attack logs.

You have tools for:
- Checking IP reputation (threat intelligence lookup)
- Banning / unbanning IP addresses (Apache .htaccess enforcement)
- Listing currently blocked IPs
- Querying recent attack detections
- Checking system / local SIEM status
- Searching the local security knowledge base

CRITICAL LANGUAGE RULE:
- Look at the user's original message language, NOT the tool output language.
- If the user's message contains ANY Chinese characters, your ENTIRE reply MUST be in Traditional Chinese (繁體中文). The tool outputs may be in English — translate them.
- If the user writes in English only, reply in English.
- Never switch languages mid-response.

CRITICAL FORMAT RULES:
- Output PLAIN TEXT only. Absolutely NO Markdown.
- No **bold**, no *italic*, no # headers, no ``` code blocks.
- Use plain numbered lists (1. 2. 3.) or dashes (- item) when listing.
- Keep replies concise, under 200 words.

Other rules:
- Always call a tool to get real data. Never fabricate results or IP details.
- For ban/unban actions, confirm the result and enforcement status.
- If a tool fails, explain the failure clearly and suggest a next step.
"""

_agent_instance = None


def _build_agent():
    raise RuntimeError('外部 AI Provider 尚未設定。請到儀表板的 AI 設定頁設定 Gemini 或 OpenAI API key。')


def _clean_response(text: str) -> str:
    """
    1. Remove leaked internal reasoning (tool-call JSON, 'I'll call the tool...' lines).
    2. Strip Markdown symbols LINE cannot render.
    """
    import re, json

    # ── Strip leaked tool-call JSON blocks ────────────────────
    # Matches {"name": "...", "parameters": {...}} anywhere in the text.
    text = re.sub(
        r'\{[^{}]*"name"\s*:\s*"[^"]+"\s*,[^{}]*"parameters"\s*:\s*\{[^{}]*\}[^{}]*\}',
        "",
        text,
        flags=re.DOTALL,
    )

    # ── Strip common internal-monologue prefixes ───────────────
    # Handles: "I'll call the tool...", "Let me call...", "I will use..."
    text = re.sub(
        r"(?im)^(I('ll| will| am going to)|Let me)\s+(call|use|invoke|search|query)\s+the\s+\w.*?[\.\n]",
        "",
        text,
    )

    # ── Strip Markdown ─────────────────────────────────────────
    text = re.sub(r"\*{1,3}(.+?)\*{1,3}", r"\1", text)
    text = re.sub(r"`{1,3}[^`]*`{1,3}", lambda m: m.group().strip("`"), text)
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*\*\s+", "- ", text, flags=re.MULTILINE)

    # ── Collapse extra blank lines left after removals ─────────
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def run_agent(user_message: str) -> str:
    """
    Invoke the NIDS agent with a user message.
    Returns a plain-text response suitable for LINE.
    """
    try:
        from ai_gateway import run
        return _clean_response(run(user_message, []))
    except Exception as e:
        # Ollama model runner crash (status 500 / process terminated):
        # reset the instance so the next message triggers a clean rebuild.
        _agent_instance = None
        err = str(e)
        if "10061" in err or "Connection refused" in err or "拒絕連線" in err:
            return "外部 AI Provider 無法連線，請到儀表板 AI 設定檢查 Provider 與 API key。"
        if "500" in err or "terminated" in err or "runner" in err:
            return (
                "AI Provider 發生錯誤，已自動重置。\n"
                "請再傳一次您的問題。\n"
                f"(原因：{err[:120]})"
            )
        return f"Agent error: {err}"
