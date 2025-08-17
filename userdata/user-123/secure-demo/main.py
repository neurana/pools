import os, logging
from fastapi import FastAPI, Request, HTTPException

log = logging.getLogger('secure-demo')
app = FastAPI(title='Secure Demo', openapi_url='/openapi.json')

@app.on_event('startup')
def _announce():
    try:
        paths = [getattr(r, 'path', str(r)) for r in app.routes]
        log.warning('ROUTES_LOADED: ' + ','.join(paths))
    except Exception as e:
        log.warning(f'ROUTES_LIST_ERROR: {e}')

@app.get('/')
def root():
    return {'ok': True}

@app.post('/needs-secret')
async def needs_secret(r: Request):
    tok = os.getenv('API_TOKEN', '')
    if r.headers.get('x-api-token') != tok:
        raise HTTPException(status_code=401, detail='nope')
    return {'ok': True}
