# YZU-NCU-SOC Agent: Integrating Machine Learning and Agentic LLM for Automated Web Intrusion Detection and Response

A Security Operations Center (SOC) platform that monitors Apache web server logs, classifies attacks using Machine Learning, visualises results in an ELK Stack, and provides an Agentic LLM assistant (LangGraph + Ollama) for natural-language-driven incident response — including real-time LINE alerts and automated IP banning.

**Author:** Pony Weng / 翁浩宇 — Yuan Ze University / National Central University

---

## System Architecture

```
Browser / Attack Script
        │
        ▼
  Apache (Docker)          ← target website: TechMart (htdocs/)
        │ access.log
        ▼
  monitor.py               ← tails log, triggers predict.py on new lines
        │
        ▼
  predict.py               ← RandomForest ML model (98.86% accuracy)
        │ prediction_output.json
        ▼
  send_to_logstash.py      ← forwards new records to Logstash via HTTP
        │
        ▼
  Logstash (Docker)        ← parses & indexes into Elasticsearch
        │
        ▼
  Elasticsearch (Docker)   ← stores prediction-logs-* index
        │
        ▼
  Kibana (Docker)          ← dashboards + alerting rule
        │ fires rule → writes to nids-kibana-alerts index
        ▼
  poller.py                ← detects new Kibana trigger
        │ Critical alert?
        ├─ YES → auto-ban source IPs → htdocs/.htaccess (HTTP 403)
        │
        ▼
  OpenAI GPT-3.5           ← generates remediation suggestions
        │
        ▼
  LINE Messaging API       ← push alert + ban notice to user
        │
        ▼
  api.py (FastAPI)         ← LINE webhook: receives user messages
        │
        ▼
  LangGraph ReAct Agent    ← LLM orchestrator (Ollama llama3.1, local GPU)
        │  understands natural language, decides which tool to call
        │
        ├── check_ip_reputation  →  threat_intel.py  (AbuseIPDB + IPinfo)
        ├── ban_ip_address       →  enforcer.py      (htdocs/.htaccess)
        ├── unban_ip_address     →  enforcer.py
        ├── list_blocked_ips     →  blacklist.json
        ├── get_recent_attacks   →  Elasticsearch
        ├── get_system_status    →  Elasticsearch + system
        └── search_knowledge     →  RAG service (port 8001)
```

**Attack types detected:** SQL Injection (1) · XSS (2) · Directory Traversal (3)
**ML model accuracy:** RandomForest 98.86%

---

## Features

### Core Pipeline
- Real-time Apache log monitoring and ML-based attack classification
- ELK Stack integration for log storage, search, and dashboards
- Kibana alerting rule triggers LINE push notification on attack detection

### LINE Alerts
- Structured alert with risk level, source IP, payload, and attack breakdown
- AI-generated remediation steps via OpenAI GPT-3.5
- RAG knowledge base (LangChain + Ollama) for additional context

### Auto IP Banning (Critical alerts only)
- When a **Critical** (SQL Injection) alert fires, source IPs are automatically banned
- Ban is enforced by writing `Require not ip` rules to `htdocs/.htaccess`
- Apache reads `.htaccess` per-request — no container restart needed
- Banned IPs receive **HTTP 403 Forbidden** immediately
- LINE alert includes: `x.x.x.x was banned automatically.`

### Security Assistant (LINE Chatbot — LangGraph Agent)

Interact with the NIDS via LINE using **natural language** — no fixed commands required.
A LangGraph ReAct agent (Ollama llama3.1, local GPU) reads your message, selects the appropriate tool, and synthesises a plain-text reply.

#### Available Tools

| Tool | What it does | Example queries |
|---|---|---|
| `check_ip_reputation` | AbuseIPDB abuse score + IPinfo geolocation/ASN + local blacklist status | "幫我查 1.2.3.4 的 IP 資料" · "check ip 45.142.212.100" |
| `ban_ip_address` | Adds IP to `blacklist.json`, writes `Require not ip` to `.htaccess` (immediate HTTP 403) | "封鎖 1.2.3.4" · "ban this ip 192.168.1.50" |
| `unban_ip_address` | Removes IP from blacklist, updates `.htaccess` | "解除封鎖 1.2.3.4" · "unban 192.168.1.50" |
| `list_blocked_ips` | Lists all currently blacklisted IPs with ban date and reason | "目前封鎖了哪些 IP？" · "show blacklist" |
| `get_recent_attack_logs` | Last 5 attack detections from Elasticsearch (type, timestamp, payload) | "最近的攻擊紀錄" · "show recent attacks" |
| `get_system_status` | ES cluster health, total records, attack count, blacklist size, log file size | "系統狀態" · "system status" |
| `search_security_knowledge` | Queries local RAG knowledge base (OWASP, CVEs, incident response) | "什麼是 XSS？" · "how to prevent SQL injection?" |

#### Example Conversations

```
User:   目前系統狀態？
Agent:  Elasticsearch 狀態正常，共有 7,373 筆紀錄，其中 4,672 筆為攻擊事件。
        目前封鎖 5 個 IP，日誌大小 423 KB。

User:   幫我查 45.142.212.100
Agent:  IP 聲譽報告：45.142.212.100
        - 濫用分數：100/100（惡意）
        - 國家：DE（德國）
        - ISP：Contabo GmbH
        - 此 IP 已列入本地封鎖名單

User:   ban 192.168.1.100
Agent:  IP 192.168.1.100 has been added to the blacklist.
        Total blacklisted IPs: 6
        Apache enforcement: active (403 Forbidden)

User:   What is a Directory Traversal attack?
Agent:  Directory Traversal (also called Path Traversal) is an attack that
        exploits insufficient input validation to access files outside the
        web root. Attackers use sequences like ../../../etc/passwd to
        read sensitive system files...
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Windows 10/11 | — |
| Docker Desktop | Latest |
| Anaconda | Latest |
| Python (conda env) | 3.10.13 |
| Ollama | Latest (for RAG) |

---

## Installation

### 1. Clone the repository

```bash
git clone <repo-url>
cd YZU_NIDS_Alert_Platform_claude
```

### 2. Create conda environment

```bash
conda create -n PonyNIDS python=3.10.13
conda activate PonyNIDS
pip install -r requirements.txt
```

### 3. Configure credentials

Edit `.env` and fill in your keys:

```env
# Elasticsearch
ES_HOST=http://localhost:9200
ES_USER=elastic
ES_PASSWORD=<your-password>

# LINE Bot — https://developers.line.biz/console/
LINE_CHANNEL_ACCESS_TOKEN=<your-token>
LINE_CHANNEL_SECRET=<your-secret>
LINE_USER_IDS=<your-user-id>

# OpenAI — https://platform.openai.com/
OPENAI_API_KEY=<your-key>

# AbuseIPDB (free) — https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=<your-key>

# ngrok (free) — https://dashboard.ngrok.com/signup
NGROK_AUTHTOKEN=<your-token>

# Protected server info (shown in alert messages)
PROTECTED_SERVER_PORT=80
PROTECTED_SERVER_SERVICE=Apache Web Server (TechMart)

# Ollama (local LLM agent) — defaults shown, change if needed
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```

**Getting LINE credentials:**
1. Go to [LINE Developers Console](https://developers.line.biz/console/)
2. Create a Messaging API channel
3. Issue a Channel Access Token
4. Add the bot and get your User ID by sending it a message

### 4. Start Docker services

```bash
docker compose up -d
```

Wait ~60 seconds for Elasticsearch to become healthy, then verify:

```bash
docker ps
# Should show: elasticsearch, logstash, kibana, apache, rag — all Up
```

### 5. Set up Kibana (one-time)

**a. Create Data View**
- Kibana → Stack Management → Data Views → Create
- Index pattern: `prediction-logs-*`
- Timestamp: `@timestamp`

**b. Create Index Connector**
- Stack Management → Connectors → Create connector → **Index**
- Name: `NIDS Alert Index`
- Index: `nids-kibana-alerts`

**c. Create Alerting Rule**
- Stack Management → Rules → Create rule
- Name: `NIDS Attack Detection`
- Type: `Elasticsearch query`
- Data view: `NIDS Predictions`
- KQL: `attack_prediction > 0`
- Threshold: `IS ABOVE 0` · For the last: `3 minutes`
- Check every: `1 minute` · Notify: `On check intervals`
- Action: `NIDS Alert Index` → Document body:
  ```json
  {"rule":"{{rule.name}}","triggered_at":"{{date}}"}
  ```

### 6. Set up LINE webhook

After starting the platform (step 7), copy the ngrok URL printed in the console:

```
>>> LINE Webhook URL: https://xxxx.ngrok-free.app/webhook
```

Then in LINE Developers Console → your channel → **Messaging API**:
- Paste the URL into **Webhook URL**
- Click **Verify**
- Toggle **Use webhook** ON

> The ngrok URL changes on every restart (free tier). Re-paste after each `python start.py`.
> If ngrok is already running from a previous session, `start.py` reuses the existing tunnel automatically.

### 7. Start the platform

```bash
conda activate PonyNIDS
python start.py
```

---

## Usage

### start.py output

```
====================================================
  YZU NIDS Alert Platform — Startup
====================================================

[1/4] Infrastructure checks
  [OK]  Docker containers
  [OK]  Elasticsearch
  [OK]  Kibana
  [OK]  Logstash
  [OK]  Apache (port 80)

[2/4] Config & file checks
  [OK]  .env credentials
  [OK]  ML model (RandomForest)
  [OK]  Apache access.log
  [OK]  Kibana NIDS rule
  [OK]  Log archived → apache-logs/archive/access_20260329_060000.log
  [OK]  Log offset OK (0 / 34391 bytes)

[3/4] Starting Python services
  [OK]  monitor.py          started  (PID ...)
  [OK]  send_to_logstash.py started  (PID ...)
  [OK]  poller.py           started  (PID ...)
  [OK]  api.py (webhook)    started  (PID ...)

[4/4] Starting ngrok tunnel (LINE webhook)
  [OK]  Reusing existing ngrok tunnel

  >>> LINE Webhook URL:
  https://xxxx.ngrok-free.app/webhook
```

### Run attack simulation

```bash
python attack_scripts.py
```

Sends SQL Injection, XSS, and Directory Traversal payloads to `http://localhost`.

### LINE alert format (Critical)

```
🛡️ NIDS 網路攻擊警報
────────────────────────────────
[Event Name]     : SQL Injection Detected
                   (3 times within 2 min)
[Risk Level]     : 🔴 Critical
[Timestamp]      : 2026-03-29 06:07:53
[Source IP]      : 203.0.113.42
[Destination]    : 192.168.0.125:80 (Apache Web Server (TechMart))
[Attack Payload] : GET /search?q=admin'+OR+1=1-- HTTP/1.1
[Prediction Code]: 1 — SQL Injection
[Total Alerts]   : 3 attack(s) in this batch
[Breakdown]      : SQL Injection: 3
────────────────────────────────
⚠️  This event has been flagged as suspicious,
    please investigate.
💡 Database compromise possible — act immediately.

【AI Security Analysis】
...remediation steps from GPT-3.5...

[ Top 3 Detections ]
  1. [SQL Injection]
     Src: 203.0.113.42  HTTP: 200
     /search?q=admin'+OR+1=1--

────────────────────────────────
🚫 Auto-Ban Activated
   203.0.113.42 was banned automatically.
   Server access blocked — HTTP 403 Forbidden.
────────────────────────────────
🔒 YZU NIDS Platform | Auto-generated Alert
```

### Auto-ban behaviour

| Risk Level | Attack Type | Auto-ban |
|---|---|---|
| 🔴 Critical | SQL Injection | Yes — source IP banned, Apache returns 403 |
| 🟠 High | XSS | No — alert only |
| 🟡 Medium | Directory Traversal | No — alert only |

To unban after testing:
```
/unban <IP>    ← send via LINE chatbot
```

### IP reputation check

The agent understands natural language — just describe what you want:

```
User:  查一下 203.0.113.42
```
```
Agent: IP 聲譽報告：203.0.113.42
       ────────────────────────────
       濫用分數   : 87/100（惡意）
       回報次數   : 142
       最後回報   : 2026-03-28
       國家       : CN
       ISP        : Some ISP
       位置       : Beijing, Beijing, CN
       ASN        : AS12345 Some Network
       * 此 IP 已列入本地封鎖名單
```

Data sources (same as before):
- **AbuseIPDB** (`api.abuseipdb.com/api/v2/check`) — abuse confidence score, report history
- **IPinfo** (`ipinfo.io/{ip}/json`) — geolocation, ASN, hostname (no key required)

---

## Project Structure

```
YZU_NIDS_Alert_Platform_claude/
│
├── start.py                  # One-command startup + health checks
├── config.py                 # Centralised config — reads from .env
├── .env                      # Credentials (not committed)
│
├── Core pipeline
│   ├── monitor.py            # Tails access.log → triggers predict.py
│   ├── predict.py            # ML inference on log lines
│   ├── send_to_logstash.py   # Forwards predictions to Logstash
│   └── poller.py             # Kibana alert → auto-ban → OpenAI → LINE
│
├── Security Assistant
│   ├── api.py                # FastAPI server — LINE webhook endpoint
│   └── assistant/
│       ├── line_handler.py   # Signature verification → routes to agent
│       ├── agent.py          # LangGraph ReAct agent (Ollama llama3.1)
│       ├── tools.py          # LangChain tool definitions (7 tools)
│       ├── command_handler.py# Internal helpers called by tools
│       ├── ai_handler.py     # OpenAI + RAG (legacy, still available)
│       ├── threat_intel.py   # AbuseIPDB + IPinfo IP reputation
│       └── enforcer.py       # Writes htdocs/.htaccess ban rules
│
├── IP Blacklist
│   └── blacklist.json        # Persistent banned IP list
│
├── ML
│   ├── train.py              # Train classifiers on labeled data
│   ├── retrain.py            # Quick retrain script
│   ├── utilities.py          # Feature extraction / log parsing
│   ├── regex_4_labels.csv    # Attack regex rules for labeling
│   ├── MODELS/               # Trained .pkl model files
│   └── DATA/                 # Raw and labeled training data
│
├── Infrastructure
│   ├── docker-compose.yml    # ELK Stack + Apache + RAG containers
│   ├── logstash.conf         # Logstash HTTP input pipeline
│   └── kibana.yml            # Kibana authentication config
│
├── Target website
│   └── htdocs/               # TechMart e-commerce site (Apache root)
│       ├── index.html        # Homepage with search
│       ├── search.html       # Search results page
│       └── .htaccess         # Auto-managed: IP bans + URL rewrites
│
├── RAG/                      # LangChain + Ollama RAG service (port 8001)
│
├── Testing
│   └── attack_scripts.py     # Automated attack traffic generator
│
└── Runtime state (auto-generated)
    ├── apache-logs/          # Apache access.log (Docker bind mount)
    │   └── archive/          # Timestamped log archives per restart
    ├── prediction_output.json
    ├── last_offset.txt
    └── *_out.txt             # Per-service stdout logs
```

---

## Docker Commands

```bash
# Start all containers
docker compose up -d

# Check status
docker compose ps

# View Logstash logs
docker compose logs logstash

# Stop all
docker compose down

# Stop and delete volumes (resets Elasticsearch data)
docker compose down -v
```

---

## RAG Knowledge Base

The Security Assistant uses Retrieval-Augmented Generation (RAG) to answer questions. When you ask a question via LINE, the system:
1. Queries the RAG service (port 8001) with your question
2. RAG retrieves the most relevant chunks from the knowledge base using Ollama embeddings
3. Retrieved context is prepended to the OpenAI GPT-3.5 prompt
4. If RAG returns nothing useful, falls back to plain GPT-3.5

### Knowledge Base Files (`RAG/knowledge/`)

| File | Language | Coverage |
|---|---|---|
| `OWASP_Top10_2021.txt` | English | OWASP Top 10 (2021) — A01 to A10 with attack examples and defenses |
| `Web_Attack_Defense.txt` | English | SQLi, XSS, Directory Traversal, CSRF, Brute Force — detailed payloads and mitigations |
| `NIDS_Incident_Response.txt` | English | IDS/IPS concepts, incident response (NIST), IP blocking, SIEM, MITRE ATT&CK |
| `作業系統與應用程式安全.txt` | Chinese | OS & application security |
| `新興科技安全.txt` | Chinese | Emerging technology security |
| `網路與通訊安全.txt` | Chinese | Network & communication security |
| `資安維運技術.txt` | Chinese | Security operations & techniques |

### Adding New Knowledge

Drop any `.txt` file into `RAG/knowledge/` and restart the RAG container:

```bash
docker compose restart rag
```

The RAG service re-indexes all files on startup. Ollama must be running for embeddings to work.

### RAG Service Requirements

- **Ollama** must be running on the host (`ollama serve`) with the required models pulled
- RAG container connects to Ollama at `host.docker.internal:11434`
- If Ollama is not running, the RAG container will restart-loop — the assistant falls back to plain GPT-3.5

```bash
# Start Ollama (if not running)
ollama serve

# Pull models (first time only)
ollama pull nomic-embed-text   # embeddings for RAG
ollama pull llama3.1           # LINE chatbot agent (tool calling)
ollama pull llama3             # kept for RAG summarisation (optional)
```

> **Note:** The LINE chatbot agent requires `llama3.1` (or later) because it uses
> Ollama's native tool-calling API. The base `llama3` model does not support tools.

---

## Retrain the ML Model

```bash
python retrain.py
```

Results (current models, sklearn 1.3.2):

| Model | Accuracy |
|---|---|
| RandomForest | 98.86% |
| DecisionTree | 98.76% |
| ExtraTree | 98.56% |
| MLP | 93.14% |
| KNN | 86.96% |

---

## Troubleshooting

**No LINE notification received**
- Check `poller_out.txt` for errors
- Verify Kibana rule has the Index connector action saved
- Ensure `nids-kibana-alerts` index exists:
  ```bash
  curl -u elastic:<pw> http://localhost:9200/nids-kibana-alerts/_count
  ```

**LINE chatbot not responding**
- Check `api_out.txt` for errors
- Verify ngrok URL is set in LINE Developers Console → Webhook URL
- Run `start.py` and copy the new `>>> LINE Webhook URL`

**api.py crashes immediately (exit 1)**
- Port 8000 is already occupied — `start.py` kills it automatically on next run
- Manual fix: `powershell -Command "Stop-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess -Force"`

**ngrok ERR_NGROK_108 (session limit)**
- `start.py` reuses an existing ngrok session automatically
- If the error persists, kill all ngrok processes and restart

**Attacks not appearing in Kibana**
- Check `monitor_out.txt` — should show `[monitor] Predicting N new lines...`
- Check `logstash_out.txt` — should show `Sent N new record(s) to Logstash`

**Website shows 403 after attack**
- Source IP was auto-banned (Critical attack detected)
- Send `/unban <IP>` via LINE chatbot to restore access
- Check current blacklist: `/blacklist list`

**Website shows 404 on /search**
- `.htaccess` rewrite rule may be missing — run:
  ```bash
  python -c "import sys; sys.path.insert(0,'.'); from assistant.enforcer import apply_blacklist; apply_blacklist()"
  ```

**Elasticsearch connection refused**
- Wait 60s after `docker compose up -d`
- Check: `curl -u elastic:<pw> http://localhost:9200/_cluster/health`

**Stale log offset after restart**
- `start.py` detects and resets this automatically
