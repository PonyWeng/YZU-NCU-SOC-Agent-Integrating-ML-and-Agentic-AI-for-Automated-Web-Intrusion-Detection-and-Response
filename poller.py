"""
poller.py — Polls a Kibana-written trigger index for new alerts,
fetches recent attack records from ES, and pushes a formatted
IDS alert to LINE via OpenAI enrichment.

Start: python poller.py
"""

import re
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import openai
import requests as http_requests
from elasticsearch import Elasticsearch

from config import (
    ES_HOST, ES_USER, ES_PASSWORD,
    LINE_CHANNEL_ACCESS_TOKEN, LINE_USER_IDS, OPENAI_API_KEY,
    PROTECTED_SERVER_PORT, PROTECTED_SERVER_SERVICE,
)

# ── Config ────────────────────────────────────────────────────
KIBANA_ALERT_INDEX = "nids-kibana-alerts"   # Index connector writes here
PREDICTION_INDEX   = "prediction-logs-*"    # Where predict records live
POLL_INTERVAL_SEC  = 15
LOOKBACK_MINUTES   = 2                      # Window for "recent attacks"
ALERT_COOLDOWN_SEC = 60
AUTHOR             = "Pony Weng / 翁浩宇"

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

_openai_client    = openai.OpenAI(api_key=OPENAI_API_KEY)
_last_alert_time: float = 0.0
_processed_ids: set[str] = set()

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))


# ── Helpers ───────────────────────────────────────────────────

def _tw_now() -> str:
    return (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


def _server_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _protected_target() -> str:
    """Return formatted destination string: IP:port (Service)."""
    ip = _server_ip()
    return f"{ip}:{PROTECTED_SERVER_PORT} ({PROTECTED_SERVER_SERVICE})"


def _extract_src_ip(log_record: str) -> str:
    m = re.match(r"^([\d.]+)", (log_record or "").strip())
    return m.group(1) if m else "Unknown"


def _openai_suggestions(attack_name: str, payload: str, count: int) -> str:
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


def _primary_risk_code(hits: list[dict]) -> int:
    """Return the attack code (1/2/3) with the highest hit count, or 0 if none."""
    counts: dict[int, int] = {}
    for hit in hits:
        code = int(hit.get("_source", hit).get("attack_prediction", 0))
        if code > 0:
            counts[code] = counts.get(code, 0) + 1
    return max(counts, key=counts.get) if counts else 0



def _auto_ban_attackers(hits: list[dict]) -> list[str]:
    """
    Extract unique source IPs from attack hits, add to blacklist.json,
    and sync htdocs/.htaccess so Apache blocks them immediately.
    Same behaviour as /ban — no IP exclusions.
    Returns list of newly banned IPs.
    """
    from assistant.enforcer import ban_ips

    ips = list({
        _extract_src_ip(hit.get("_source", hit).get("log_record", ""))
        for hit in hits
    } - {"Unknown", ""})

    if not ips:
        return []

    newly_banned = ban_ips(ips, reason="Auto-ban: Critical attack detected by NIDS")
    if newly_banned:
        print(f"[{_tw_now()}] Auto-banned {len(newly_banned)} IP(s): {', '.join(newly_banned)}")
    return newly_banned


def _format_alert(hits: list[dict]) -> str:
    SEP = "─" * 32
    destination = _protected_target()
    timestamp = _tw_now()

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
    risk_label, risk_advice = RISK_LEVELS.get(
        primary_code, ("🔴 Critical", "Investigate immediately.")
    )
    total_attacks = sum(attack_counts.values())
    breakdown = "  |  ".join(
        f"{ATTACK_LABELS.get(c, str(c))}: {n}"
        for c, n in sorted(attack_counts.items())
    )

    # Event name: single type or combined
    if len(attack_counts) == 1:
        event_name = f"{primary_name} Detected"
        event_count = f"({primary_count} times within {LOOKBACK_MINUTES} min)"
    else:
        type_names = " + ".join(
            ATTACK_LABELS.get(c, str(c)) for c in sorted(attack_counts.keys())
        )
        event_name = f"Multiple Attack Types Detected"
        event_count = f"({total_attacks} total: {type_names})"

    first_src = hits[0].get("_source", hits[0]) if hits else {}
    source_ip = _extract_src_ip(first_src.get("log_record", "")) or "Unknown"
    payload   = first_src.get("URL", "N/A")
    pred_code = int(first_src.get("attack_prediction", primary_code))

    ai_analysis = _openai_suggestions(primary_name, payload[:120], primary_count)

    lines = [
        "🛡️ NIDS 網路攻擊警報",
        f"建立 by {AUTHOR}",
        "",
        SEP,
        f"[Event Name]     : {event_name}",
        f"                   {event_count}",
        f"[Risk Level]     : {risk_label}",
        f"[Timestamp]      : {timestamp}",
        f"[Source IP]      : {source_ip}",
        f"[Destination]    : {destination}",
        f"[Attack Payload] : {payload[:72]}",
        f"[Prediction Code]: {pred_code} — {ATTACK_LABELS.get(pred_code, 'Unknown')}",
        f"[Total Alerts]   : {total_attacks} attack(s) in this batch",
        f"[Breakdown]      : {breakdown}",
        SEP,
        "",
        "⚠️  This event has been flagged as suspicious,",
        "    please investigate.",
        f"💡 {risk_advice}",
        "",
        "【AI Security Analysis】",
        ai_analysis,
    ]

    if hits:
        lines += ["", f"[ Top {min(len(hits), 5)} Detections ]"]
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


def _append_ban_notice(message: str, newly_banned: list[str]) -> str:
    """Append auto-ban summary to an existing alert message."""
    if not newly_banned:
        return message
    SEP = "─" * 32
    ban_lines = ["", SEP, "🚫 Auto-Ban Activated"]
    for ip in newly_banned:
        ban_lines.append(f"   {ip} was banned automatically.")
    ban_lines.append("   Server access blocked — HTTP 403 Forbidden.")
    return message + "\n" + "\n".join(ban_lines)


def _send_line(text: str) -> None:
    headers = {
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    for uid in LINE_USER_IDS:
        resp = http_requests.post(
            "https://api.line.me/v2/bot/message/push",
            headers=headers,
            json={"to": uid, "messages": [{"type": "text", "text": text}]},
        )
        print(f"[{_tw_now()}] LINE -> {uid}  status={resp.status_code}")


def _ensure_alert_index() -> None:
    """Create the trigger index if it doesn't exist yet."""
    if not es.indices.exists(index=KIBANA_ALERT_INDEX):
        es.indices.create(
            index=KIBANA_ALERT_INDEX,
            mappings={
                "properties": {
                    "rule":         {"type": "keyword"},
                    "triggered_at": {"type": "date"},
                }
            },
        )
        print(f"[{_tw_now()}] Created index: {KIBANA_ALERT_INDEX}")


def _fetch_new_trigger_ids() -> list[str]:
    """Return IDs of unprocessed docs in the Kibana alert trigger index."""
    try:
        result = es.search(
            index=KIBANA_ALERT_INDEX,
            query={"match_all": {}},
            size=20,
            sort=[{"triggered_at": {"order": "desc"}}],
        )
        return [
            hit["_id"]
            for hit in result["hits"]["hits"]
            if hit["_id"] not in _processed_ids
        ]
    except Exception as exc:
        print(f"[{_tw_now()}] Alert index query error: {exc}")
        return []


def _fetch_recent_attacks() -> list[dict]:
    """Query ES for attack records from the last LOOKBACK_MINUTES."""
    since = (
        datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MINUTES)
    ).isoformat()
    try:
        result = es.search(
            index=PREDICTION_INDEX,
            query={
                "bool": {
                    "must": [
                        {"range": {"attack_prediction": {"gt": 0}}},
                        {"range": {"@timestamp":        {"gte": since}}},
                    ]
                }
            },
            size=50,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
        return result["hits"]["hits"]
    except Exception as exc:
        print(f"[{_tw_now()}] Prediction index query error: {exc}")
        return []


# ── Main loop ─────────────────────────────────────────────────

def main() -> None:
    global _last_alert_time

    _ensure_alert_index()
    print(f"[{_tw_now()}] poller started — checking every {POLL_INTERVAL_SEC}s")
    print(f"[{_tw_now()}] Watching: {KIBANA_ALERT_INDEX}")

    # Re-apply any existing blacklist to .htaccess on startup
    try:
        from assistant.enforcer import apply_blacklist
        blocked = apply_blacklist()
        print(f"[{_tw_now()}] Blacklist enforced on startup: {len(blocked)} IP(s) blocked")
    except Exception as e:
        print(f"[{_tw_now()}] Blacklist enforcement error on startup: {e}")

    while True:
        try:
            new_ids = _fetch_new_trigger_ids()

            if new_ids:
                now = time.time()
                if now - _last_alert_time < ALERT_COOLDOWN_SEC:
                    remaining = int(ALERT_COOLDOWN_SEC - (now - _last_alert_time))
                    print(f"[{_tw_now()}] Alert suppressed — cooldown {remaining}s remaining.")
                else:
                    hits = _fetch_recent_attacks()
                    if hits:
                        _last_alert_time = now
                        risk_code = _primary_risk_code(hits)
                        # Auto-ban only on Critical risk (SQL Injection, code 1)
                        if risk_code == 1:
                            newly_banned = _auto_ban_attackers(hits)
                            print(f"[{_tw_now()}] Critical alert — auto-ban triggered")
                        else:
                            newly_banned = []
                            risk_label = RISK_LEVELS.get(risk_code, ("Unknown",))[0]
                            print(f"[{_tw_now()}] Alert risk: {risk_label} — auto-ban skipped (Critical only)")
                        message = _format_alert(hits)
                        message = _append_ban_notice(message, newly_banned)
                        _send_line(message)
                        print(message)
                    else:
                        print(f"[{_tw_now()}] Kibana trigger received but no recent attacks in ES.")

                for aid in new_ids:
                    _processed_ids.add(aid)
            else:
                print(f"[{_tw_now()}] No new Kibana alerts.")

        except Exception as exc:
            print(f"[{_tw_now()}] poller error: {exc}")

        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()
