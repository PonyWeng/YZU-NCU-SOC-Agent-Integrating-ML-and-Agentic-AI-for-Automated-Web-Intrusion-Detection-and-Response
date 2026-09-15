#!/usr/bin/env bash
# One-click launcher for the complete local NCU-PDCLAB mini SIEM stack.
# Run from Git Bash / WSL: ./start.sh
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
PYTHON_BIN="${PYTHON_BIN:-python}"
PORT="${SIEM_PORT:-8000}"

say() { printf '\n[SIEM] %s\n' "$*"; }
die() { printf '\n[SIEM] ERROR: %s\n' "$*" >&2; exit 1; }
command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "找不到 Python：$PYTHON_BIN"

command -v docker >/dev/null 2>&1 || die "找不到 Docker；請先啟動 Docker Desktop。"
say "啟動 WAF、三個受保護服務、儀表板、日誌收集器、LINE webhook 與通知服務"
exec "$PYTHON_BIN" start.py --demo --line --ngrok --port "$PORT"
