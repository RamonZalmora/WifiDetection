import csv
import hmac
import html
import io
import json
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .crypto import LabData, generate, password_advice, valid_password, valid_ssid
from .engine import Engine, Store
from .wifi import NativeWifi


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class ProjectInput(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    authorized: Literal[True]
    ssid: str
    password: str
    _ssid = field_validator('ssid')(valid_ssid)
    _password = field_validator('password')(valid_password)


class ImportInput(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    authorized: Literal[True]
    data: LabData


class TestInput(StrictModel):
    project_id: str = Field(max_length=36)
    candidates: list[str] = Field(min_length=1, max_length=10000)
    limit: int = Field(ge=1, le=10000, default=1000)

    @field_validator('candidates')
    @classmethod
    def candidates_valid(cls, values):
        for value in values:
            valid_password(value)
        return values


class PasswordInput(StrictModel):
    password: str
    _password = field_validator('password')(valid_password)


class ReportInput(StrictModel):
    job_id: str = Field(max_length=36)
    format: Literal['json', 'csv', 'html']
    include_password: bool = False
    confirm_sensitive: bool = False


def create_app(directory: Path, token: str | None = None, scanner=None, shutdown=None):
    token = token or secrets.token_urlsafe(32)
    engine = Engine(Store(directory))
    scanner = scanner or NativeWifi()
    scan_lock = threading.Lock()
    last_scan = {'status': 'not scanned', 'adapters': [], 'networks': [], 'errors': [], 'timestamp': None}

    @asynccontextmanager
    async def lifespan(app):
        yield
        engine.close()

    app = FastAPI(title='WPA2 Recovery Lab Pro', docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.engine = engine
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1'])

    @app.middleware('http')
    async def security(request: Request, call_next):
        origin = request.headers.get('origin')
        if origin and origin != 'http://127.0.0.1:8765':
            return JSONResponse({'detail': 'Origin rejected'}, status_code=403)
        if request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'detail': 'Cross-site request rejected'}, status_code=403)
        if request.url.path.startswith('/api/'):
            supplied = request.headers.get('x-lab-token', '')
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return JSONResponse({'detail': 'Session token required. Launch using START.bat.'}, status_code=401)
        if request.method in ('POST', 'PUT', 'PATCH'):
            # Read a bounded stream; do not trust Content-Length or buffer unbounded uploads.
            size = 0
            body = bytearray()
            async for chunk in request.stream():
                size += len(chunk)
                if size > 1_048_576:
                    return JSONResponse({'detail': 'Request exceeds 1 MiB'}, status_code=413)
                # Request.body is restored below for FastAPI's downstream parser.
                body.extend(chunk)
            request._body = bytes(body) if size else b''
        response = await call_next(request)
        response.headers.update({
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        })
        return response

    # Avoid echoing passwords and imported material in Pydantic validation responses.
    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({'detail': [{'loc': error['loc'], 'msg': error['msg'], 'type': error['type']}
                                       for error in exc.errors()]}, status_code=422)

    @app.exception_handler(KeyError)
    async def not_found(request, exc):
        return JSONResponse({'detail': 'Session project or experiment not found'}, status_code=404)

    @app.exception_handler(ValueError)
    async def conflict(request, exc):
        return JSONResponse({'detail': str(exc)}, status_code=409)

    @app.get('/health')
    def health():
        return {'application': 'WPA2 Recovery Lab Pro', 'status': 'ok'}

    @app.get('/api/session')
    def session():
        return {'status': 'ok'}

    @app.get('/api/dashboard')
    def dashboard():
        with engine.lock:
            return {'scan': last_scan, 'projects': [engine.project_public(p) for p in engine.projects],
                    'jobs': [engine.get(j) for j in engine.jobs], 'history': engine.store.history()}

    @app.post('/api/scan')
    def scan():
        if not scan_lock.acquire(blocking=False):
            raise HTTPException(409, 'Scan already in progress')
        try:
            if last_scan['timestamp'] and time.time() - last_scan['timestamp'] < 4:
                raise HTTPException(429, 'Wait four seconds before requesting another scan')
            result = scanner.scan()
            last_scan.clear()
            last_scan.update(result)
            return result
        finally:
            scan_lock.release()

    @app.post('/api/projects/generated')
    def generated(data: ProjectInput):
        return engine.project(data.name, generate(data.ssid, data.password), 'Generated synthetic laboratory data')

    @app.post('/api/projects/import')
    def imported(data: ImportInput):
        return engine.project(data.name, data.data, 'User-authorized imported laboratory proof')

    @app.get('/api/projects/{pid}/data')
    def export_data(pid: str):
        with engine.lock:
            return engine.projects[pid]['data'].model_dump()

    @app.post('/api/tests')
    def start_test(data: TestInput):
        return engine.start(data.project_id, data.candidates, data.limit)

    @app.get('/api/tests/{jid}')
    def test_status(jid: str):
        return engine.get(jid)

    @app.post('/api/tests/{jid}/cancel')
    def cancel(jid: str):
        return engine.cancel(jid)

    @app.post('/api/password/analyze')
    def analyze(data: PasswordInput):
        return password_advice(data.password)

    @app.post('/api/password/generate')
    def strong_password():
        alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*-_'
        return {'password': ''.join(secrets.choice(alphabet) for _ in range(24))}

    @app.post('/api/session/clear')
    def clear():
        engine.clear_sensitive()
        return {'status': 'cleared'}

    @app.post('/api/reports')
    def report(data: ReportInput):
        try:
            record = engine.get(data.job_id)
        except KeyError:
            record = next((r for r in engine.store.history() if r['id'] == data.job_id), None)
            if record is None:
                raise HTTPException(404, 'Experiment not found')
        if data.include_password and not data.confirm_sensitive:
            raise HTTPException(400, 'Explicit sensitive export confirmation required')
        if data.include_password and not record.get('password'):
            raise HTTPException(409, 'No password retained for this experiment')
        if not data.include_password:
            record.pop('password', None)
        record['hardware_at_export'] = last_scan['adapters']
        record['recommendations'] = ['Use WPA3 or WPA2-AES, a unique random passphrase, and current firmware.',
                                      'Lab proof success does not verify access to an actual router.']
        record['report_note'] = 'Hardware snapshot at export time, not a historical scan.'
        if data.format == 'json':
            content, mime = json.dumps(record, ensure_ascii=False, indent=2), 'application/json'
        elif data.format == 'csv':
            stream = io.StringIO(newline='')
            writer = csv.writer(stream)
            writer.writerow(['field', 'value'])
            for key, value in record.items():
                text = json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else str(value)
                # Prevent spreadsheet formula injection, including whitespace prefixes.
                if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
                    text = "'" + text
                writer.writerow([key, text])
            content, mime = stream.getvalue(), 'text/csv'
        else:
            content = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Laboratory report</title><h1>WPA2 laboratory report</h1><table>'
            content += ''.join(f'<tr><th>{html.escape(k)}</th><td><pre>{html.escape(str(v))}</pre></td></tr>' for k, v in record.items())
            content += '</table></html>'
            mime = 'text/html'
        return Response(content, media_type=mime,
                        headers={'Content-Disposition': f'attachment; filename="lab-report.{data.format}"'})

    @app.post('/api/shutdown')
    def stop():
        if shutdown:
            threading.Timer(0.3, shutdown).start()
        return {'status': 'shutting down'}

    static = Path(__file__).parent / 'static'

    @app.get('/')
    def index():
        return FileResponse(static / 'index.html')

    app.mount('/static', StaticFiles(directory=static), name='static')
    return app
