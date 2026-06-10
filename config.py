"""
Centralised configuration — reads from .env (or environment variables).
All other modules should import constants from here instead of hardcoding values.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Elasticsearch ────────────────────────────────────────────
ES_HOST: str = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER: str = os.getenv("ES_USER", "elastic")
ES_PASSWORD: str = os.getenv("ES_PASSWORD", "")

# ── LINE Bot ─────────────────────────────────────────────────
LINE_CHANNEL_ACCESS_TOKEN: str = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
LINE_CHANNEL_SECRET: str = os.getenv("LINE_CHANNEL_SECRET", "")
LINE_USER_IDS: list[str] = [
    uid.strip()
    for uid in os.getenv("LINE_USER_IDS", "").split(",")
    if uid.strip()
]

# ── OpenAI ───────────────────────────────────────────────────
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

# ── RAG service ──────────────────────────────────────────────
RAG_API_URL: str = os.getenv("RAG_API_URL", "http://localhost:8001/summary")

# ── Apache log paths ─────────────────────────────────────────
ACCESS_LOG: str = os.getenv("ACCESS_LOG", r"C:/xampp/apache/logs/access.log")
ACCESS2_LOG: str = os.getenv("ACCESS2_LOG", r"C:/xampp/apache/logs/store-logs/access2.log")
ACCESS3_LOG: str = os.getenv("ACCESS3_LOG", r"C:/xampp/apache/logs/store-logs/access3.log")

# ── ML model ─────────────────────────────────────────────────
MODEL_PATH: str = os.getenv("MODEL_PATH", "MODELS/model_RandomForestClassifier.pkl")

# ── Protected server ─────────────────────────────────────────
PROTECTED_SERVER_PORT:    str = os.getenv("PROTECTED_SERVER_PORT", "80")
PROTECTED_SERVER_SERVICE: str = os.getenv("PROTECTED_SERVER_SERVICE", "Apache Web Server")

# ── Threat Intelligence ───────────────────────────────────────
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

# ── ngrok ────────────────────────────────────────────────────
NGROK_AUTHTOKEN: str = os.getenv("NGROK_AUTHTOKEN", "")

# ── Ollama (local LLM agent) ─────────────────────────────────
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str    = os.getenv("OLLAMA_MODEL", "llama3.1")
