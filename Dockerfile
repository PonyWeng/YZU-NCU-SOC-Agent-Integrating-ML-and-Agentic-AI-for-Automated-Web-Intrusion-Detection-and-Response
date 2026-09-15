FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/docker-entrypoint.sh \
    && mkdir -p /app/runtime /app/apache-logs \
       /app/protected_services/logs/flask /app/protected_services/logs/django \
       /app/protected_services/logs/waf/apache /app/protected_services/logs/waf/flask \
       /app/protected_services/logs/waf/django

EXPOSE 8000 8002
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=4 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
