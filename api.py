"""Local SIEM dashboard and separate LINE-only ASGI app."""
from contextlib import asynccontextmanager
from pathlib import Path
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
    yield

app = FastAPI(title='NCU-PDCLAB mini SIEM',lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware,allowed_hosts=['localhost','127.0.0.1','[::1]','testserver'])

@app.middleware('http')
async def local_access(request: Request,call_next):
    if request.client and request.client.host not in ('127.0.0.1','::1','testclient'):
        return JSONResponse({'detail':'Local access only'},status_code=403)
    if request.headers.get('x-forwarded-for') or request.headers.get('forwarded'):
        return JSONResponse({'detail':'Open the dashboard locally'},status_code=403)
    if request.method not in ('GET','HEAD','OPTIONS'):
        origin = request.headers.get('origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse({'detail':'Cross-origin operation rejected'},status_code=403)
        if request.headers.get('x-siem-request') != 'dashboard':
            return JSONResponse({'detail':'Missing operation header'},status_code=403)
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
