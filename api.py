"""Local SIEM dashboard and separate LINE-only ASGI app."""
from contextlib import asynccontextmanager
from pathlib import Path
import os
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.concurrency import run_in_threadpool
from siem import store
from siem.routes import router

@asynccontextmanager
async def lifespan(app):
    store.init_db()
    # The runtime blacklist volume and the host-mounted Apache rules can have
    # different lifetimes. Rebuild .htaccess from the canonical JSON state on
    # every start so a stale rule cannot keep an IP blocked after it vanished
    # from the dashboard list.
    from assistant.enforcer import apply_blacklist
    apply_blacklist()
    yield

app = FastAPI(title='NCU-PDCLAB mini SIEM',lifespan=lifespan)
allow_remote = os.getenv('SIEM_ALLOW_REMOTE','').lower() in ('1','true','yes')
allowed_hosts = [h.strip() for h in os.getenv('SIEM_ALLOWED_HOSTS','localhost,127.0.0.1,[::1],testserver').split(',') if h.strip()]
app.add_middleware(TrustedHostMiddleware,allowed_hosts=allowed_hosts)

@app.middleware('http')
async def local_access(request: Request,call_next):
    if not allow_remote and request.client and request.client.host not in ('127.0.0.1','::1','testclient'):
        return JSONResponse({'detail':'Local access only'},status_code=403)
    if not allow_remote and (request.headers.get('x-forwarded-for') or request.headers.get('forwarded')):
        return JSONResponse({'detail':'Open the dashboard locally'},status_code=403)
    if request.method not in ('GET','HEAD','OPTIONS'):
        origin = request.headers.get('origin')
        public_origin=os.getenv('SIEM_PUBLIC_ORIGIN','').rstrip('/')
        expected_origin=public_origin or str(request.base_url).rstrip('/')
        if origin and origin != expected_origin:
            return JSONResponse({'detail':'Cross-origin operation rejected'},status_code=403)
        if request.headers.get('x-siem-request') != 'dashboard':
            return JSONResponse({'detail':'Missing operation header'},status_code=403)
    if request.url.path.startswith('/api/'):
        from siem.auth import SESSION_COOKIE, session_from_token
        public = request.url.path in ('/api/auth/login',)
        request.state.user,session_reason = session_from_token(request.cookies.get(SESSION_COOKIE))
        if not public and not request.state.user:
            response=JSONResponse({'detail':'登入已逾期' if session_reason in ('idle','absolute') else '請先登入'},status_code=401)
            response.delete_cookie(SESSION_COOKIE,path='/')
            return response
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
    response.headers['Cache-Control'] = 'no-store'
    return response

app.include_router(router)
web = Path(__file__).parent/'dashboard'
app.mount('/static',StaticFiles(directory=web),name='static')

@app.get('/')
def index():
    return FileResponse(web/'index.html')

@app.get('/health')
def health():
    return {'status':'ok','storage':'sqlite'}

webhook_app = FastAPI(title='NCU-PDCLAB mini SIEM LINE webhook',docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)

@webhook_app.post('/webhook')
async def webhook(request: Request,x_line_signature: str=Header(default='')):
    from assistant.line_handler import verify_signature,handle_events
    from config import LINE_CHANNEL_SECRET
    body = await request.body()
    if not LINE_CHANNEL_SECRET or not verify_signature(body,x_line_signature):
        raise HTTPException(400,'Invalid LINE signature')
    data = await request.json()
    await run_in_threadpool(handle_events,data.get('events',[]))
    return {'status':'ok'}
