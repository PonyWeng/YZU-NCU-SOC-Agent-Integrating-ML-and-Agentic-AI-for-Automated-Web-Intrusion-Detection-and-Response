"""Start the local SIEM. LINE/ngrok are opt-in and use a separate port."""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import requests

ROOT=Path(__file__).resolve().parent


def update_line_webhook(webhook_url):
    """Register the active tunnel with LINE; credentials never enter logs."""
    from config import LINE_CHANNEL_ACCESS_TOKEN
    if not LINE_CHANNEL_ACCESS_TOKEN:
        print('LINE token missing; set webhook URL manually.', flush=True)
        return False
    response = requests.put(
        'https://api.line.me/v2/bot/channel/webhook/endpoint',
        headers={'Authorization': f'Bearer {LINE_CHANNEL_ACCESS_TOKEN}', 'Content-Type': 'application/json'},
        json={'endpoint': webhook_url}, timeout=15,
    )
    if response.status_code != 200:
        print(f'LINE webhook registration failed: HTTP {response.status_code}', flush=True)
        return False
    print(f'LINE webhook registered: {webhook_url}', flush=True)
    return True


def existing_ngrok_url(port):
    try:
        data = requests.get('http://127.0.0.1:4040/api/tunnels', timeout=2).json()
        for tunnel in data.get('tunnels', []):
            if str(port) in tunnel.get('config', {}).get('addr', ''):
                url = tunnel.get('public_url', '')
                return url.replace('http://', 'https://', 1)
    except Exception:
        return ''
    return ''


def webhook_is_running(port=8002):
    """Detect our LINE ASGI app even when ngrok is unavailable."""
    try:
        response = requests.get(f'http://127.0.0.1:{port}/webhook', timeout=1.5)
        return response.status_code in (404, 405)
    except requests.RequestException:
        return False

def dashboard_is_running(port):
    """Return True only when the existing listener is our local SIEM app."""
    try:
        response = requests.get(f'http://127.0.0.1:{port}/health', timeout=1.5)
        return response.status_code == 200 and response.json().get('storage') == 'sqlite'
    except Exception:
        return False


def check_port(port, allow_existing_dashboard=False):
    if allow_existing_dashboard and dashboard_is_running(port):
        return False
    with socket.socket() as s:
        try:
            s.bind(('127.0.0.1',port))
        except OSError:
            raise RuntimeError(f'Port {port} is occupied. Stop the previous service or choose --port. No process was killed.')
    return True

def main():
    parser=argparse.ArgumentParser(description='NCU-PDCLAB mini SIEM')
    parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--dashboard-only',action='store_true',help='Run dashboard without collector')
    parser.add_argument('--import-legacy',type=Path,help='Import prediction_output.json once; no notifications')
    parser.add_argument('--line',action='store_true',help='Start LINE delivery and webhook on 8002')
    parser.add_argument('--ngrok',action='store_true',help='Expose LINE-only port 8002; requires --line')
    parser.add_argument('--demo',action='store_true',help='Start the three Docker targets behind OWASP CRS WAF gateways')
    args=parser.parse_args()
    if args.ngrok and not args.line:
        parser.error('--ngrok requires --line')
    os.chdir(ROOT)
    if args.demo:
        for name in ('apache','flask','django'):
            path=ROOT/'protected_services'/'logs'/'waf'/name
            path.mkdir(parents=True,exist_ok=True)
            try:
                (path/'audit.jsonl').touch(exist_ok=True)
            except PermissionError:
                # WAF containers may own the mounted file; the collector only
                # needs read access, so do not abort startup when it exists.
                if not (path/'audit.jsonl').exists():
                    raise
        print('Starting Apache, Flask and Django behind OWASP CRS (Detection Only)...',flush=True)
        # Compose also contains a containerized SIEM. The local launcher owns
        # the Python SIEM processes, so bring up only demo targets and WAFs.
        demo_services=['apache','flask-target','django-target','waf-apache','waf-flask','waf-django']
        result=subprocess.run(['docker','compose','up','-d',*demo_services],cwd=ROOT)
        if result.returncode:
            parser.error('Docker WAF startup failed. Check Docker Desktop and runtime logs.')
    from siem import store
    from config import ACCESS_LOG,MODEL_PATH,LINE_CHANNEL_ACCESS_TOKEN,LINE_CHANNEL_SECRET,LINE_USER_IDS
    store.init_db()
    dashboard_to_start = check_port(args.port, allow_existing_dashboard=True)
    if args.line:
        if args.port==8002:
            parser.error('Dashboard and LINE must use different ports')
        if not webhook_is_running(8002):
            check_port(8002)
        if not all((LINE_CHANNEL_ACCESS_TOKEN,LINE_CHANNEL_SECRET,LINE_USER_IDS)):
            parser.error('LINE requires access token, channel secret and allowed LINE_USER_IDS')
    if args.import_legacy:
        from siem.collector import import_legacy
        print(f'Imported {import_legacy(args.import_legacy)} new historical events.')
    if not args.dashboard_only:
        if not Path(MODEL_PATH).is_file():
            parser.error(f'Model missing: {MODEL_PATH}')
        if not Path(ACCESS_LOG).is_file():
            parser.error(f'Apache log missing: {ACCESS_LOG}. Start Apache or use --dashboard-only.')
    children=[]
    tunnel=None
    def launch(name,command):
        log=(ROOT/'runtime'/f'{name}.log').open('a',encoding='utf-8')
        child=subprocess.Popen([sys.executable,*command],cwd=ROOT,stdout=log,stderr=log)
        children.append((name,child,log))
    try:
        if dashboard_to_start:
            launch('dashboard',['-m','uvicorn','api:app','--host','127.0.0.1','--port',str(args.port),'--no-proxy-headers'])
        else:
            print(f'Dashboard already running at http://127.0.0.1:{args.port}; reusing it.', flush=True)
        if not args.dashboard_only:
            launch('collector',['-u','-m','siem.collector'])
            launch('geo',['-u','-m','siem.geo'])
        if args.line:
            if not webhook_is_running(8002):
                launch('line',['-m','uvicorn','api:webhook_app','--host','127.0.0.1','--port','8002'])
            else:
                print('LINE webhook already running on port 8002; reusing it.', flush=True)
            launch('notifications',['-u','-m','siem.notifications'])
        if args.ngrok:
            from pyngrok import ngrok
            from config import NGROK_AUTHTOKEN
            if NGROK_AUTHTOKEN:
                ngrok.set_auth_token(NGROK_AUTHTOKEN)
            current = existing_ngrok_url(8002)
            if current:
                webhook = f'{current}/webhook'
                print(f'Reusing LINE tunnel: {webhook}', flush=True)
            else:
                tunnel=ngrok.connect(8002,'http')
                webhook = f'{tunnel.public_url}/webhook'
                print(f'LINE webhook URL: {webhook}', flush=True)
            update_line_webhook(webhook)
            store.set_state('line_webhook',{'url':webhook,'status':'registered','updated_at':store.now()})
        print(f'NCU-PDCLAB mini SIEM: http://127.0.0.1:{args.port}',flush=True)
        if args.demo:
            print('WAF targets: Apache http://127.0.0.1:80 | Flask :8081 | Django :8082',flush=True)
            print('OWASP CRS: PL1 / Detection Only (records attacks without blocking)',flush=True)
        print('Logs: runtime/  |  Ctrl+C stops only services launched here.',flush=True)
        while True:
            time.sleep(2)
            for name,child,_ in children:
                if child.poll() is not None:
                    raise RuntimeError(f'{name} stopped ({child.returncode}); see runtime/{name}.log')
    except KeyboardInterrupt:
        pass
    finally:
        for _,child,log in children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            log.close()
        if tunnel:
            ngrok.disconnect(tunnel.public_url)

if __name__=='__main__':
    main()
