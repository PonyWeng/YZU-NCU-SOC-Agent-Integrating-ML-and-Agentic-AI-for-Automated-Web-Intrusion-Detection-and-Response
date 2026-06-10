"""
assistant/line_handler.py
Handles LINE webhook signature verification and event routing.
"""

import base64
import hashlib
import hmac

import requests

from config import LINE_CHANNEL_ACCESS_TOKEN, LINE_CHANNEL_SECRET

LINE_REPLY_URL = "https://api.line.me/v2/bot/message/reply"
MAX_LINE_LENGTH = 4999   # LINE hard limit per message


def verify_signature(body: bytes, signature: str) -> bool:
    """Verify X-Line-Signature using LINE_CHANNEL_SECRET."""
    digest = hmac.new(
        LINE_CHANNEL_SECRET.encode("utf-8"), body, hashlib.sha256
    ).digest()
    expected = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(expected, signature)


def reply(reply_token: str, text: str) -> None:
    """Send a reply message back to LINE."""
    text = text[:MAX_LINE_LENGTH]
    requests.post(
        LINE_REPLY_URL,
        headers={
            "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
            "Content-Type": "application/json",
        },
        json={
            "replyToken": reply_token,
            "messages": [{"type": "text", "text": text}],
        },
        timeout=10,
    )


def handle_events(events: list) -> None:
    """Route each LINE message event to the NIDS agent."""
    from assistant.agent import run_agent
    from assistant.tools import HELP_TEXT

    for event in events:
        if event.get("type") != "message":
            continue
        if event.get("message", {}).get("type") != "text":
            continue

        text = event["message"]["text"].strip()
        reply_token = event.get("replyToken", "")
        if not reply_token:
            continue

        try:
            if text.lower() in ("/help", "help", "幫助", "說明"):
                response = HELP_TEXT
            else:
                response = run_agent(text)
        except Exception as exc:
            response = f"[Error] {exc}"

        try:
            reply(reply_token, response)
        except Exception as exc:
            print(f"[line_handler] Reply failed: {exc}")
