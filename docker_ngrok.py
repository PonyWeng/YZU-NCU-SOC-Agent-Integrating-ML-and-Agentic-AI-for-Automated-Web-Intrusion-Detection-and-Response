"""Create the optional LINE tunnel and register its webhook endpoint."""
import os
import time
from pyngrok import ngrok
from start import update_line_webhook
from siem import store

token=os.getenv('NGROK_AUTHTOKEN','').strip()
if not token:
    raise SystemExit('ENABLE_NGROK=true but NGROK_AUTHTOKEN is empty')
ngrok.set_auth_token(token)
time.sleep(3)
tunnel=ngrok.connect(8002,'http')
webhook=f'{tunnel.public_url.replace("http://","https://",1)}/webhook'
if not update_line_webhook(webhook):
    ngrok.disconnect(tunnel.public_url)
    raise SystemExit('LINE webhook registration failed')
store.init_db()
store.set_state('line_webhook',{'url':webhook,'status':'registered','updated_at':store.now()})
print(f'LINE webhook registered through ngrok: {webhook}',flush=True)
try:
    while True: time.sleep(3600)
finally:
    ngrok.disconnect(tunnel.public_url)
