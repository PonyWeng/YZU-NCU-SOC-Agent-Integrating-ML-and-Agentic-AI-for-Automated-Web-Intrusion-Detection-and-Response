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
    for event in events:
        from config import LINE_USER_IDS
        if event.get("type") != "message":
            continue
        if event.get("message", {}).get("type") != "text":
            continue

        text = event["message"]["text"].strip()
        reply_token = event.get("replyToken", "")
        if not reply_token:
            continue

        user_id = event.get("source", {}).get("userId", "").strip()
        if text.lower() == "/register":
            if not user_id:
                response = "無法從這次 LINE Webhook 取得使用者 ID，請改用一對一聊天室再試一次。"
            elif user_id in LINE_USER_IDS:
                response = (
                    "此 LINE 帳號已完成授權。\n"
                    f"你的 LINE User ID：{user_id}\n"
                    "你可以使用 AI 查詢及已授權的 SIEM 功能。"
                )
            else:
                print(f"[line_handler] Registration requested by {user_id}", flush=True)
                response = (
                    "已收到授權申請。\n"
                    f"你的 LINE User ID：{user_id}\n"
                    "請將這組 ID 提供給系統管理員加入授權清單。授權前無法查詢內部日誌或操作 SIEM。"
                )
            try:
                reply(reply_token, response)
            except Exception as exc:
                print(f"[line_handler] Registration reply failed: {exc}", flush=True)
            continue

        # LINE signature authenticates delivery, not permission to administer SIEM.
        if user_id not in LINE_USER_IDS:
            print(f"[line_handler] Rejected unauthorized user {user_id or 'unknown'}", flush=True)
            try:
                reply(reply_token, "此 LINE 帳號尚未授權。請輸入 /register 取得你的 User ID，並交由系統管理員加入授權清單。")
            except Exception as exc:
                print(f"[line_handler] Unauthorized reply failed: {exc}", flush=True)
            continue

        try:
            from assistant.agent import run_agent
            from assistant.tools import HELP_TEXT
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
