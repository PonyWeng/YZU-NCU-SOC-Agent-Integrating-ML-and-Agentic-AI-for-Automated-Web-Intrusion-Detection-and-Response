from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone
import json
import os
from blocking import client_ip, is_blocked

app = Flask(__name__)
LOG = os.environ.get('ACCESS_LOG', '/logs/access.jsonl')

@app.before_request
def enforce_blacklist():
    ip=client_ip(request.headers,request.remote_addr)
    if is_blocked(ip,'flask'):
        return jsonify(error='Forbidden',detail='來源 IP 已被此服務封鎖'),403

def log_request(response):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    forwarded = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
    record = {'timestamp': datetime.now(timezone.utc).isoformat(),
              'src_ip': request.headers.get('X-Demo-Source-IP') or request.headers.get('X-Real-IP') or forwarded or request.remote_addr,
              'dst_ip': request.host.split(':')[0], 'method': request.method, 'path': request.full_path,
              'status': response.status_code, 'service': 'flask-target', 'port': 8081,
              'http_version': request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1'),
              'response_bytes': response.calculate_content_length() or 0,
              'referer': request.referrer or '', 'user_agent': request.user_agent.string or ''}
    with open(LOG, 'a', encoding='utf-8') as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + '\n')
    return response

app.after_request(log_request)

def page(notice, query=''):
    return render_template('index.html', query=query, notice=notice)

@app.get('/')
def index(): return page('今日有 8 項員工申請等待處理')

@app.get('/search')
def search():
    query = request.args.get('q', '')
    return page(f'已搜尋員工入口內容：{query}' if query else '請輸入搜尋內容', query)

@app.route('/login', methods=['GET', 'POST'])
def login(): return page(f'{request.values.get("user") or "Demo 使用者"} 的登入請求已收到')

@app.get('/product')
@app.get('/cart')
@app.get('/about')
@app.get('/file')
@app.get('/redirect')
def demo_page(): return page(f'Demo 路徑：{request.path}')

@app.get('/api/data')
def data(): return jsonify(service='employee-hub', id=request.args.get('id'), status='ok')

@app.get('/health')
def health(): return jsonify(service='flask-target', status='healthy')

@app.get('/demo-error')
def demo_error(): return page('Demo：模擬應用程式內部錯誤'), 500

if __name__ == '__main__': app.run(host='0.0.0.0', port=8081)
