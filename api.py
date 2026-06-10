# Start: python -m uvicorn api:app --reload --host 0.0.0.0 --port 8000

import json
import os
import re
import socket
import time
from datetime import datetime, timedelta

import openai
import requests as http_requests
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware

from config import LINE_CHANNEL_ACCESS_TOKEN, LINE_USER_IDS, OPENAI_API_KEY

PREDICTION_FILE = "prediction_output.json"
LINE_PUSH_URL   = "https://api.line.me/v2/bot/message/push"
AUTHOR          = "Pony Weng / 翁浩宇"

# ── Rate-limit: suppress repeated alerts within this window ──
ALERT_COOLDOWN_SEC = 60          # minimum seconds between LINE pushes
_last_alert_time: float = 0.0   # module-level state

ATTACK_LABELS = {
    1: "SQL Injection",
    2: "Cross-Site Scripting (XSS)",
    3: "Directory Traversal",
}
RISK_LEVELS = {
    1: ("🔴 Critical", "Database compromise possible — act immediately."),
    2: ("🟠 High",     "User sessions and client data at risk."),
    3: ("🟡 Medium",   "Sensitive server files may be exposed."),
}

_openai_client = openai.OpenAI(api_key=OPENAI_API_KEY)


# ── Helpers ───────────────────────────────────────────────────

def _server_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _extract_src_ip(log_record: str) -> str:
    m = re.match(r"^([\d.]+)", (log_record or "").strip())
    return m.group(1) if m else "Unknown"


def _tw_now() -> str:
    return (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


def _openai_suggestions(attack_name: str, payload: str, count: int) -> str:
    """Call OpenAI and return 3 actionable security suggestions."""
    prompt = (
        f"A {attack_name} attack was detected {count} time(s) on a web server.\n"
        f"Sample payload: {payload}\n\n"
        "You are a professional cybersecurity analyst. "
        "Reply in English with:\n"
        "1. One sentence summarising the risk.\n"
        "2. Exactly 3 short, actionable remediation steps (numbered 1-3).\n"
        "Keep the total response under 80 words."
    )
    try:
        resp = _openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a concise cybersecurity expert."},
                {"role": "user",   "content": prompt},
            ],
            timeout=20,
            max_tokens=150,
        )
        return resp.choices[0].message.content.strip()
    except Exception as exc:
        return f"(AI analysis unavailable: {exc})"


def _format_alert(hits: list[dict], rule_name: str = "NIDS Attack Alert") -> str:
    """Build a professional IDS alert message (with OpenAI suggestions)."""
    SEP = "─" * 32
    server_ip = _server_ip()
    timestamp = _tw_now()

    # ── Aggregate attack types ────────────────────────────────
    attack_counts: dict[int, int] = {}
    for hit in hits:
        src  = hit.get("_source", hit)
        code = int(src.get("attack_prediction", 0))
        if code > 0:
            attack_counts[code] = attack_counts.get(code, 0) + 1
    if not attack_counts:
        attack_counts = {1: 1}

    primary_code  = max(attack_counts, key=attack_counts.get)
    primary_name  = ATTACK_LABELS.get(primary_code, "Unknown Attack")
    primary_count = attack_counts[primary_code]
    risk_label, risk_advice = RISK_LEVELS.get(primary_code, ("🔴 Critical", "Investigate immediately."))
    total_attacks = sum(attack_counts.values())

    breakdown = "  |  ".join(
        f"{ATTACK_LABELS.get(c, str(c))}: {n}"
        for c, n in sorted(attack_counts.items())
    )

    # ── Primary hit details ───────────────────────────────────
    first_src = hits[0].get("_source", hits[0]) if hits else {}
    source_ip = _extract_src_ip(first_src.get("log_record", "")) or "Unknown"
    payload   = first_src.get("URL", "N/A")
    pred_code = int(first_src.get("attack_prediction", primary_code))

    # ── OpenAI enrichment ─────────────────────────────────────
    ai_analysis = _openai_suggestions(primary_name, payload[:120], primary_count)

    # ── Build message ─────────────────────────────────────────
    lines = [
        "🛡️ NIDS 網路攻擊警報",
        f"建立 by {AUTHOR}",
        "",
        SEP,
        f"[Event Name]     : {primary_name} Detected",
        f"                   ({primary_count} times within 1 minute)",
        f"[Risk Level]     : {risk_label}",
        f"[Timestamp]      : {timestamp}",
        f"[Source IP]      : {source_ip}",
        f"[Destination IP] : {server_ip}",
        f"[Attack Payload] : {payload[:72]}",
        f"[Prediction Code]: {pred_code} — {ATTACK_LABELS.get(pred_code, 'Unknown')}",
        f"[Total Alerts]   : {total_attacks} attack(s) in this batch",
        f"[Breakdown]      : {breakdown}",
        SEP,
        "",
        f"⚠️  This event has been flagged as suspicious,",
        f"    please investigate.",
        f"💡 {risk_advice}",
        "",
        "【AI Security Analysis】",
        ai_analysis,
    ]

    # ── Top individual detections (up to 5) ──────────────────
    if hits:
        lines += ["", f"[ Top {min(len(hits),5)} Detections ]"]
        for i, hit in enumerate(hits[:5], 1):
            src   = hit.get("_source", hit)
            code  = int(src.get("attack_prediction", 0))
            label = ATTACK_LABELS.get(code, f"Type-{code}")
            url   = src.get("URL", "N/A")
            ip    = _extract_src_ip(src.get("log_record", ""))
            rc    = src.get("return_code", "?")
            lines += [
                f"  {i}. [{label}]",
                f"     Src: {ip}  HTTP: {rc}",
                f"     {url[:65]}",
            ]

    lines += [
        "",
        SEP,
        "🔒 YZU NIDS Platform | Auto-generated Alert",
        f"   {timestamp}",
    ]
    return "\n".join(lines)


def _send_line(text: str) -> None:
    headers = {
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    for uid in LINE_USER_IDS:
        resp = http_requests.post(
            LINE_PUSH_URL,
            headers=headers,
            json={"to": uid, "messages": [{"type": "text", "text": text}]},
        )
        print(f"[{_tw_now()}] LINE -> {uid}  status={resp.status_code}")


# ── FastAPI app ───────────────────────────────────────────────

app = FastAPI(title="NIDS Prediction API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/predict")
async def predict():
    if not os.path.exists(PREDICTION_FILE):
        raise HTTPException(status_code=503, detail="No prediction data available yet.")
    with open(PREDICTION_FILE, "r") as fh:
        return json.load(fh)


@app.post("/webhook")
async def line_webhook(
    request: Request,
    x_line_signature: str = Header(default=""),
):
    """
    LINE Messaging API webhook.
    Receives messages from LINE users and routes to the security assistant.
    """
    from assistant.line_handler import verify_signature, handle_events

    body = await request.body()

    if not verify_signature(body, x_line_signature):
        raise HTTPException(status_code=400, detail="Invalid LINE signature")

    payload = await request.json()
    # Run synchronously — LINE gives 30s; all handlers are fast enough.
    # Running in executor would silently swallow exceptions.
    handle_events(payload.get("events", []))
    return {"status": "ok"}


@app.post("/alert")
async def line_alert(request: Request):
    """
    Kibana webhook → format alert → call OpenAI → send LINE.
    Rate-limited to once per ALERT_COOLDOWN_SEC seconds.
    """
    global _last_alert_time

    now = time.time()
    if now - _last_alert_time < ALERT_COOLDOWN_SEC:
        remaining = int(ALERT_COOLDOWN_SEC - (now - _last_alert_time))
        print(f"[{_tw_now()}] Alert suppressed — cooldown {remaining}s remaining.")
        return {"status": "suppressed", "cooldown_remaining_sec": remaining}

    _last_alert_time = now

    payload   = await request.json()
    hits      = payload.get("hits", [])
    rule_name = payload.get("rule", "NIDS Attack Alert")
    message   = _format_alert(hits, rule_name)

    _send_line(message)
    print(message)
    return {"status": "sent", "notified": len(LINE_USER_IDS)}
