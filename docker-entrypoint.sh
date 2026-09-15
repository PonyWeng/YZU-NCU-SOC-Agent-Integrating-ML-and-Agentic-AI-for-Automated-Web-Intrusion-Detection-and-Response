#!/usr/bin/env bash
set -Eeuo pipefail

mkdir -p runtime apache-logs protected_services/logs/{flask,django,waf/apache,waf/flask,waf/django}
touch apache-logs/access.log \
  protected_services/logs/flask/access.jsonl \
  protected_services/logs/django/access.jsonl \
  protected_services/logs/waf/apache/audit.jsonl \
  protected_services/logs/waf/flask/audit.jsonl \
  protected_services/logs/waf/django/audit.jsonl

# Complete the first-run schema and admin bootstrap before workers open SQLite.
python -c "from siem import store; store.init_db()"

pids=()
start() { "$@" & pids+=("$!"); }
shutdown() {
  trap - TERM INT EXIT
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait || true
}
trap shutdown TERM INT EXIT

start python -m uvicorn api:app --host 0.0.0.0 --port 8000 --no-proxy-headers
start python -u -m siem.collector
start python -u -m siem.geo

if [[ "${ENABLE_LINE:-false}" == "true" ]]; then
  start python -m uvicorn api:webhook_app --host 0.0.0.0 --port 8002 --no-proxy-headers
  start python -u -m siem.notifications
  if [[ "${ENABLE_NGROK:-false}" == "true" ]]; then
    start python -u docker_ngrok.py
  fi
fi

wait -n
exit 1
