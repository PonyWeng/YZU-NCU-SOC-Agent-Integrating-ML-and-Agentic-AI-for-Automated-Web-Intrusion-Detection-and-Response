"""
start.py — YZU NIDS Alert Platform startup script
Usage: python start.py

Checks all components, then starts monitor / send_to_logstash / poller / api.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime

import requests

# ── Config ────────────────────────────────────────────────────
PYTHON     = sys.executable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ES_URL     = "http://localhost:9200"
ES_AUTH    = ("elastic", "vEo4PSW2yMiHIMMTxAHk")
KIBANA_URL = "http://localhost:5601"
APACHE_URL = "http://localhost"
LOGSTASH_URL = "http://localhost:5044"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Helpers ───────────────────────────────────────────────────

def ok(msg):  print(f"  {GREEN}[OK]{RESET}  {msg}")
def fail(msg): print(f"  {RED}[!!]{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}[--]{RESET}  {msg}")
def info(msg): print(f"  {CYAN}[..]{RESET}  {msg}")

def check(label, fn):
    try:
        result = fn()
        if result is True or result is None:
            ok(label)
            return True
        else:
            fail(f"{label}  →  {result}")
            return False
    except Exception as e:
        fail(f"{label}  →  {e}")
        return False


# ── Health checks ─────────────────────────────────────────────

def check_docker():
    r = subprocess.run(["docker", "ps", "--format", "{{.Names}}\\t{{.Status}}"],
                       capture_output=True, text=True)
    containers = r.stdout.strip().splitlines()
    required = {"elasticsearch": False, "logstash": False, "kibana": False, "apache": False}
    for line in containers:
        for name in required:
            if name in line.lower() and "Up" in line:
                required[name] = True
    missing = [k for k, v in required.items() if not v]
    if missing:
        return f"Containers not running: {', '.join(missing)}"
    return True

def check_elasticsearch():
    r = requests.get(f"{ES_URL}/_cluster/health", auth=ES_AUTH, timeout=5)
    status = r.json().get("status")
    if status in ("green", "yellow"):
        return True
    return f"cluster status: {status}"

def check_kibana():
    r = requests.get(f"{KIBANA_URL}/api/status", auth=ES_AUTH, timeout=8)
    level = r.json().get("status", {}).get("overall", {}).get("level", "unknown")
    if level == "available":
        return True
    return f"level: {level}"

def check_logstash():
    r = requests.get(LOGSTASH_URL, timeout=5)
    if r.status_code in (200, 405):
        return True
    return f"HTTP {r.status_code}"

def check_apache():
    r = requests.get(APACHE_URL, timeout=5)
    # Any HTTP response (200, 403, 301…) means Apache is running.
    # 403 is normal when directory listing is disabled and no index exists.
    if r.status_code < 500:
        return True
    return f"HTTP {r.status_code}"

def check_ollama():
    r = requests.get("http://localhost:11434/api/tags", timeout=5)
    models = [m["name"] for m in r.json().get("models", [])]
    missing = [m for m in ("llama3.1", "nomic-embed-text") if not any(m in x for x in models)]
    if missing:
        return f"Models not pulled: {', '.join(missing)} — run: ollama pull <model>"
    return True

def check_rag():
    # RAG runs module-level init (ChromaDB load) before Uvicorn starts;
    # retry for up to ~32s to avoid false failures on container restart.
    last_err = "not started"
    for _ in range(4):
        try:
            r = requests.get("http://localhost:8001/docs", timeout=8)
            if r.status_code == 200:
                return True
            return f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
            time.sleep(8)
    return last_err

def check_models():
    path = os.path.join(SCRIPT_DIR, "MODELS", "model_RandomForestClassifier.pkl")
    if os.path.exists(path):
        return True
    return "model_RandomForestClassifier.pkl not found"

def check_access_log():
    log = os.path.join(SCRIPT_DIR, "apache-logs", "access.log")
    if os.path.exists(log):
        size = os.path.getsize(log)
        return True if size >= 0 else "file missing"
    return "apache-logs/access.log not found"

def check_env():
    env = os.path.join(SCRIPT_DIR, ".env")
    if not os.path.exists(env):
        return ".env file missing"
    with open(env, encoding="utf-8", errors="replace") as f:
        content = f.read()
    missing = []
    for key in ("LINE_CHANNEL_ACCESS_TOKEN", "OPENAI_API_KEY", "ES_PASSWORD"):
        if key + "=" not in content:
            missing.append(key)
    if missing:
        return f"Missing keys: {', '.join(missing)}"
    return True

def check_kibana_rule():
    r = requests.get(
        f"{KIBANA_URL}/api/alerting/rules/_find?search=NIDS&search_fields=name",
        auth=ES_AUTH, timeout=8,
        headers={"kbn-xsrf": "true"},
    )
    rules = r.json().get("data", [])
    if any("NIDS" in rule.get("name", "") for rule in rules):
        return True
    return "No NIDS rule found — create it in Kibana Stack Management → Rules"

def archive_and_reset_offset():
    """
    Archive access.log to apache-logs/archive/ on every startup to preserve history.
    If the saved offset is beyond the current file size (log was cleared/rotated),
    reset offset to 0 so all current log lines get processed.
    """
    import shutil

    log        = os.path.join(SCRIPT_DIR, "apache-logs", "access.log")
    archive_dir = os.path.join(SCRIPT_DIR, "apache-logs", "archive")
    offset_file = os.path.join(SCRIPT_DIR, "last_offset.txt")

    os.makedirs(archive_dir, exist_ok=True)

    if not os.path.exists(log):
        warn("apache-logs/access.log not found — Apache may still be starting")
        return

    size = os.path.getsize(log)
    saved = 0
    if os.path.exists(offset_file):
        try:
            saved = int(open(offset_file).read().strip())
        except Exception:
            saved = 0

    # Archive current log with timestamp (preserves full history across restarts)
    if size > 0:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_path = os.path.join(archive_dir, f"access_{ts}.log")
        shutil.copy2(log, archive_path)
        ok(f"Log archived → apache-logs/archive/access_{ts}.log")

    if saved > size:
        # File was cleared/truncated since last run — process from beginning
        with open(offset_file, "w") as f:
            f.write("0")
        warn(f"Log was cleared (offset {saved} > size {size}). Processing from start.")
    else:
        ok(f"Log offset OK ({saved} / {size} bytes)")


# ── Port cleanup ──────────────────────────────────────────────

def _free_port(port: int) -> None:
    """Kill any process already listening on the given port."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"(Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue"
             f" | Where-Object State -eq 'Listen').OwningProcess"],
            capture_output=True, text=True,
        )
        pid_str = result.stdout.strip()
        if pid_str and pid_str.isdigit():
            subprocess.run(["powershell", "-Command", f"Stop-Process -Id {pid_str} -Force"],
                           capture_output=True)
            warn(f"Freed port {port} (killed PID {pid_str})")
    except Exception:
        pass


# ── Process launcher ──────────────────────────────────────────

processes = []

def start_service(name, cmd, log_name=None):
    """
    cmd  : list of args (e.g. [PYTHON, '-u', 'monitor.py'])
    log_name : stem for the _out.txt file; defaults to cmd[last].replace('.py','')
    """
    if log_name is None:
        log_name = cmd[-1].replace(".py", "").replace(":", "_")
    log_file = open(os.path.join(SCRIPT_DIR, f"{log_name}_out.txt"), "w")
    proc = subprocess.Popen(
        cmd,
        cwd=SCRIPT_DIR,
        stdout=log_file,
        stderr=log_file,
    )
    processes.append((name, proc, log_file))
    time.sleep(1.5)
    if proc.poll() is None:
        ok(f"{name} started  (PID {proc.pid})")
        return True
    else:
        fail(f"{name} crashed immediately — check {log_name}_out.txt")
        return False


def _update_line_webhook(webhook_url: str) -> None:
    """Push the new webhook URL to LINE Developers Console automatically."""
    import requests as _req
    from config import LINE_CHANNEL_ACCESS_TOKEN

    if not LINE_CHANNEL_ACCESS_TOKEN:
        warn("LINE_CHANNEL_ACCESS_TOKEN missing — update webhook URL manually")
        return
    try:
        resp = _req.put(
            "https://api.line.me/v2/bot/channel/webhook/endpoint",
            headers={
                "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
                "Content-Type": "application/json",
            },
            json={"endpoint": webhook_url},
            timeout=10,
        )
        if resp.status_code == 200:
            ok(f"LINE webhook auto-updated → {webhook_url}")
        else:
            warn(f"LINE webhook update failed ({resp.status_code}) — set manually:")
            print(f"  {webhook_url}")
    except Exception as e:
        warn(f"LINE webhook update error: {e}")
        print(f"  Set manually: {webhook_url}")


def start_ngrok(port: int) -> str:
    """
    Return the ngrok HTTPS URL for the given port.
    If an ngrok agent is already running (previous start.py), reuse its tunnel
    rather than trying to open a second session (free tier = 1 session limit).
    """
    import requests as _req

    # ── Try to reuse an existing ngrok agent via its local API ────
    try:
        resp = _req.get("http://127.0.0.1:4040/api/tunnels", timeout=2)
        if resp.status_code == 200:
            tunnels = resp.json().get("tunnels", [])
            for t in tunnels:
                addr = t.get("config", {}).get("addr", "")
                if str(port) in addr:
                    url = t.get("public_url", "")
                    if url.startswith("http://"):
                        url = "https://" + url[7:]
                    ok(f"Reusing existing ngrok tunnel")
                    return url
    except Exception:
        pass  # no existing agent — start fresh

    # ── No existing agent: start a new one ────────────────────────
    try:
        from pyngrok import ngrok
        from config import NGROK_AUTHTOKEN
        if NGROK_AUTHTOKEN:
            ngrok.set_auth_token(NGROK_AUTHTOKEN)
        tunnel = ngrok.connect(port, "http")
        public_url = tunnel.public_url
        if public_url.startswith("http://"):
            public_url = "https://" + public_url[7:]
        return public_url
    except ImportError:
        warn("pyngrok not installed — run: pip install pyngrok")
        return ""
    except Exception as e:
        warn(f"ngrok failed: {e}")
        return ""


# ── Main ──────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}{CYAN}{'='*52}")
    print("  YZU NIDS Alert Platform — Startup")
    print(f"{'='*52}{RESET}\n")

    # ── Step 1: Infrastructure checks ─────────────────────────
    print(f"{BOLD}[1/4] Infrastructure checks{RESET}")
    infra_ok = True
    infra_ok &= check("Docker containers",   check_docker)
    infra_ok &= check("Elasticsearch",       check_elasticsearch)
    check("Kibana",                          check_kibana)   # warning only
    infra_ok &= check("Logstash",            check_logstash)
    infra_ok &= check("Apache (port 80)",    check_apache)
    check("Ollama (local LLM)",              check_ollama)   # warning only
    check("RAG service (port 8001)",         check_rag)      # warning only

    if not infra_ok:
        print(f"\n{RED}Infrastructure not ready. Run: docker compose up -d{RESET}\n")
        sys.exit(1)

    # ── Step 2: Config & file checks ──────────────────────────
    print(f"\n{BOLD}[2/4] Config & file checks{RESET}")
    check(".env credentials",        check_env)
    check("ML model (RandomForest)", check_models)
    check("Apache access.log",       check_access_log)
    check("Kibana NIDS rule",        check_kibana_rule)
    archive_and_reset_offset()

    # ── Step 3: Start Python services ─────────────────────────
    print(f"\n{BOLD}[3/4] Starting Python services{RESET}")
    # Free port 8000 if a stale api.py is already running
    _free_port(8000)
    start_service("monitor.py         ", [PYTHON, "-u", "monitor.py"])
    start_service("send_to_logstash.py", [PYTHON, "-u", "send_to_logstash.py"])
    start_service("poller.py          ", [PYTHON, "-u", "poller.py"])
    start_service(
        "api.py (webhook)   ",
        [PYTHON, "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"],
        log_name="api",
    )

    # ── Step 4: ngrok tunnel ───────────────────────────────────
    print(f"\n{BOLD}[4/4] Starting ngrok tunnel (LINE webhook){RESET}")
    webhook_url = ""
    ngrok_public = start_ngrok(8000)
    if ngrok_public:
        webhook_url = f"{ngrok_public}/webhook"
        ok(f"ngrok tunnel active")
        # Auto-register the new URL with LINE so commands work immediately
        _update_line_webhook(webhook_url)
    else:
        warn("ngrok not started — set NGROK_AUTHTOKEN in .env and install pyngrok")

    # ── Summary ───────────────────────────────────────────────
    alive = [(n, p) for n, p, _ in processes if p.poll() is None]
    total = len(processes)
    print(f"\n{BOLD}{'='*52}")
    print(f"  All systems {'GO' if len(alive)==total else 'CHECK ERRORS'}")
    print(f"{'='*52}{RESET}")
    print(f"\n  Services running: {len(alive)}/{total}")
    print(f"  Kibana:           {KIBANA_URL}")
    print(f"  Elasticsearch:    {ES_URL}")
    print(f"  API (webhook):    http://localhost:8000")
    print(f"  RAG service:      http://localhost:8001")
    print(f"  Ollama:           http://localhost:11434")
    print(f"  Apache (target):  {APACHE_URL}")
    if webhook_url:
        print(f"  LINE Webhook:     {webhook_url}")
    print(f"\n  Attack demo:      python attack_scripts.py")
    print(f"  Stop all:         Ctrl+C\n")

    try:
        while True:
            time.sleep(5)
            for name, proc, _ in processes:
                if proc.poll() is not None:
                    fail(f"{name.strip()} died unexpectedly (exit {proc.returncode})")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Shutting down...{RESET}")
        for name, proc, fh in processes:
            proc.terminate()
            fh.close()
        print("All services stopped.\n")


if __name__ == "__main__":
    main()
