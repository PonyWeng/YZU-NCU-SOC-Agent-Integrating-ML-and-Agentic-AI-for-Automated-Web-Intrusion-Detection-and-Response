#!/usr/bin/env bash
# Stop Docker services used by start.sh.
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
if command -v docker >/dev/null 2>&1; then docker compose down || true; fi
printf '[SIEM] Docker services stopped. Press Ctrl+C in the start terminal to stop Python services.\n'
