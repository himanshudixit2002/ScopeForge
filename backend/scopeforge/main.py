import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .db import Database, NotFound, QueueFull, new_id
from .models import FindingCreate, FindingUpdate, ImportCreate, ProgramCreate, ScanBatchCreate, ScanCancelAll, ScanCreate
from .security import ScopeError, normalize_path, parse_expiry, parse_target, validate_program
from .worker import Worker

MAX_API_BODY_BYTES = 32 * 1024
MAX_IMPORT_BODY_BYTES = 1024 * 1024
_LOCAL_HOST = re.compile(r"^(localhost|127\.0\.0\.1)(?::([0-9]{1,5}))?$")
_DEV_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}


class LocalBoundaryMiddleware:
    """Protect a loopback app against cross-origin mutations and DNS rebinding."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        pairs = [(key.decode("latin-1").lower(), value.decode("latin-1")) for key, value in scope["headers"]]
        headers = dict(pairs)

        async def reject(status, detail):
            await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)

        if sum(key == "host" for key, _ in pairs) != 1 or sum(key == "origin" for key, _ in pairs) > 1:
            await reject(400, "A single local Host and at most one Origin header are required.")
            return
        host = headers.get("host", "").lower()
        match = _LOCAL_HOST.fullmatch(host)
        if not match or (match[2] is not None and not 1 <= int(match[2]) <= 65535):
            await reject(403, "ScopeForge only accepts requests addressed to localhost or 127.0.0.1.")
            return
        origin = headers.get("origin")
        own_origin = f"{scope.get('scheme', 'http')}://{host}"
        if origin is not None and origin not in {own_origin, *_DEV_ORIGINS}:
            await reject(403, "Cross-origin requests are not allowed.")
            return
        if headers.get("sec-fetch-site") == "cross-site":
            await reject(403, "Cross-site requests are not allowed.")
            return
        if scope["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
            if headers.get("x-scopeforge-client") != "dashboard":
                await reject(403, "Mutation requests require X-ScopeForge-Client: dashboard.")
                return
        content_length = headers.get("content-length")
        body_limit = MAX_IMPORT_BODY_BYTES if scope["path"] == "/api/imports/analyze" else MAX_API_BODY_BYTES
        body_limit_message = "Import request body is limited to 1 MiB." if body_limit == MAX_IMPORT_BODY_BYTES else "Request body is limited to 32 KiB."
        try:
            if content_length is not None and (int(content_length) < 0 or int(content_length) > body_limit):
                await reject(413, body_limit_message)
                return
        except ValueError:
            await reject(400, "Invalid Content-Length header.")
            return
        if scope["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
            # Bound chunked bodies too, before a route can perform mutations.
            chunks = []
            size = 0
            deadline = time.monotonic() + 5.0
            while True:
                try:
                    message = await asyncio.wait_for(receive(), timeout=max(0.001, deadline - time.monotonic()))
                except TimeoutError:
                    await reject(408, "Request body timed out.")
                    return
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                size += len(chunk)
                if size > body_limit:
                    await reject(413, body_limit_message)
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
            delivered = False
            original_receive = receive

            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await original_receive()

            receive = replay

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cross-origin-resource-policy", b"same-origin"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
                ]
                if scope["path"].startswith("/api"):
                    message["headers"].append((b"cache-control", b"no-store"))
            await send(message)

        await self.app(scope, receive, secure_send)


def render_report(finding: dict) -> str:
    source = finding.get("source", "scan")
    provenance = {
        "scan": "Single-response observation — manual validation is required before submission.",
        "http-import": "Offline review of an operator-provided HTTP capture. No target request was sent by this analysis.",
        "openapi": "Offline review of an operator-provided OpenAPI document. No described endpoint was contacted.",
        "manual": "Analyst-entered record. ScopeForge did not independently observe or verify this issue.",
    }[source]
    if finding["is_demo"]:
        provenance = "SYNTHETIC OFFLINE DEMO — do not submit this fixture as a real finding. " + provenance
    reproduction = {
        "scan": "Inspect the same URL's response with one permitted GET; compare the response headers and, for a web profile, the bounded static HTML evidence.",
        "http-import": "Obtain the original authorized capture and compare its response metadata with this offline observation; confirm the capture is current and belongs to the stated target.",
        "openapi": "Review the referenced operation and inherited settings in the original API document; confirm with the owner whether the deployed API has additional controls.",
        "manual": "Follow the analyst's authorized reproduction steps recorded in the evidence and notes; independently validate each claim and its impact.",
    }[source]
    return f"""# {finding['title']}

> {provenance}

- Program: {finding['program_name']}
- Target: {finding['target_url']}
- Source: {source}
- Severity: {finding['severity']} (observation only)
- Observation confidence: {finding['confidence']}
- Operator status: {finding['status']}
- CWE: {finding.get('cwe') or 'Not assigned'}
- First observed at: {finding.get('first_seen') or finding['created_at']}
- Last observed at: {finding.get('last_seen') or finding['created_at']}
- Observations recorded: {finding.get('occurrence_count', 1)}
- Finding ID: {finding['id']}
- Latest analysis ID: {finding['scan_id']}

## Observation

{finding['description']}

## Evidence

```text
{finding['evidence']}
```

## Potential impact and limits

{finding['impact']}

This check does not establish exploitability, affected users, or bounty eligibility.
Automated analysis performs no authentication, crawling, redirect following, or exploit payloads.
Raw imported content and fetched response bodies are not retained. Analyst-entered evidence is retained as provided; redact secrets before exporting.
Occurrence counts represent recorded observations, not proof of continuous exposure. A missing observation on a later run does not automatically resolve an earlier finding.

## Reproduction and manual validation

1. Confirm current written authorization, the exact origin, and path exclusions.
2. {reproduction}
3. Check whether this observation affects a sensitive workflow and whether another control mitigates it.
4. Add a reproducible impact explanation and sanitized evidence before submitting through the program's approved channel.

## Suggested remediation

{finding['remediation']}

## Operator notes

{finding['notes'] or 'No manual validation notes recorded.'}
"""


def create_app(db_path=None, *, start_worker=True, frontend_dir=None):
    @asynccontextmanager
    async def lifespan(app):
        database = Database(db_path or os.environ.get("SCOPEFORGE_DB", "data/scopeforge.sqlite3"))
        worker = Worker(database)
        app.state.database = database
        app.state.worker = worker
        if start_worker:
            worker.start()
        try:
            yield
        finally:
            if start_worker:
                await asyncio.to_thread(worker.stop)

    app = FastAPI(title="ScopeForge local API", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.add_middleware(LocalBoundaryMiddleware)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, error):
        # Pydantic's default error payload includes the rejected input. Never
        # echo imported captures, authorization notes, or analyst evidence.
        return JSONResponse({"detail": [{"loc": item["loc"], "msg": item["msg"], "type": item["type"]} for item in error.errors()]}, status_code=422)

    @app.exception_handler(ScopeError)
    async def scope_error(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=422)

    @app.exception_handler(NotFound)
    async def not_found(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=404)

    @app.exception_handler(QueueFull)
    async def queue_full(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=429)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__, "mode": "local", "worker": "running" if app.state.worker.running else "stopped"}

    @app.get("/api/overview")
    def overview():
        return app.state.database.overview()

    @app.get("/api/programs")
    def programs():
        return app.state.database.programs()

    @app.post("/api/programs", status_code=201)
    def create_program(payload: ProgramCreate):
        if not payload.authorized:
            raise ScopeError("Explicit authorization confirmation is required.")
        name = payload.name.strip()
        note = payload.authorization_note.strip()
        if len(name) < 2 or len(note) < 12:
            raise ScopeError("Provide a program name and a meaningful authorization note.")
        # The policy is a saved reference link; it is never fetched or treated
        # as proof of authorization, and never contributes target scope.
        try:
            policy = urlsplit(payload.policy_url)
            policy_port = policy.port
            valid_policy = (
                policy.scheme in {"http", "https"} and policy.hostname
                and policy.username is None and policy.password is None
                and (policy_port is None or 1 <= policy_port <= 65535)
            )
        except ValueError:
            valid_policy = False
        if not valid_policy or any(ord(char) <= 32 or ord(char) == 127 for char in payload.policy_url) or "\\" in payload.policy_url:
            raise ScopeError("Policy URL must be an HTTP(S) link without credentials or control characters.")
        expiry = parse_expiry(payload.authorization_expires_at)
        if expiry <= datetime.now(timezone.utc):
            raise ScopeError("Authorization expiry must be in the future.")
        origins = list(dict.fromkeys(parse_target(value, origin_only=True).origin for value in payload.scope_origins))
        exclusions = list(dict.fromkeys(normalize_path(value) for value in payload.excluded_paths))
        return app.state.database.create_program({
            **payload.model_dump(), "name": name, "authorization_note": note,
            "scope_origins": origins, "excluded_paths": exclusions,
            "authorization_expires_at": expiry.isoformat().replace("+00:00", "Z"), "is_demo": False,
        })

    @app.post("/api/programs/{program_id}/revoke")
    def revoke_program(program_id: str):
        program = app.state.database.revoke_program(program_id)
        app.state.worker.wake()
        return program

    @app.get("/api/checks")
    def checks():
        from .catalog import get_checks
        return get_checks()

    @app.get("/api/programs/{program_id}/report")
    def program_report(program_id: str, format: str = Query(default="markdown", pattern="^(markdown|json)$")):
        program = app.state.database.get_program(program_id)
        records = app.state.database.program_findings(program_id)
        limitations = "Observations require manual validation and do not establish exploitability or bounty eligibility. Offline and manual records make zero network requests. Nothing is submitted automatically. Review analyst evidence and notes for secrets before sharing."
        if format == "json":
            return JSONResponse({"application": "ScopeForge", "version": __version__, "exported_at": datetime.now(timezone.utc).isoformat(), "program": program, "findings": records, "limitations": limitations}, headers={"Content-Disposition": f'attachment; filename="scopeforge-program-{program_id}.json"'})
        text = f"# ScopeForge program report: {program['name']}\n\n{limitations}\n\nRecorded findings: {len(records)}\n\n"
        if program["is_demo"]:
            text += "> SYNTHETIC OFFLINE DEMO — no real target observations.\n\n"
        text += "\n\n---\n\n".join(render_report(record) for record in records)
        return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="scopeforge-program-{program_id}.md"'})

    @app.get("/api/assets")
    def assets():
        return app.state.database.assets()

    @app.get("/api/scans")
    def scans():
        return app.state.database.scans()

    @app.post("/api/scans", status_code=202)
    def create_scan(payload: ScanCreate):
        program = app.state.database.get_program(payload.program_id)
        target = app.state.database.validate_scan(program, payload.target_url, payload.mode, payload.profile)
        scan = app.state.database.create_scan(program["id"], target.url, payload.mode, payload.profile)
        app.state.worker.wake()
        return scan

    @app.post("/api/scans/batch", status_code=202)
    def create_scan_batch(payload: ScanBatchCreate):
        scans = app.state.database.create_scans(payload.program_id, payload.target_urls, profile=payload.profile, real_only=True)
        app.state.worker.wake()
        return {"scans": scans, "submitted": len(scans), "request_budget": len(scans)}

    @app.post("/api/scans/cancel-all")
    def cancel_all_scans(payload: ScanCancelAll):
        count = app.state.database.cancel_all(payload.program_id)
        app.state.worker.wake()
        return {"cancelled": count}

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        return app.state.database.get_scan(scan_id)

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str):
        scan = app.state.database.cancel_scan(scan_id)
        app.state.worker.wake()
        return scan

    @app.get("/api/findings")
    def findings():
        return app.state.database.findings()

    @app.post("/api/findings", status_code=201)
    def create_manual_finding(payload: FindingCreate):
        program = app.state.database.get_program(payload.program_id)
        target = validate_program(program, payload.target_url, "manual")
        observation = payload.model_dump(exclude={"program_id", "target_url"})
        observation["check_id"] = f"manual:{new_id()}"
        _scan, finding_ids = app.state.database.create_offline_result(program["id"], target.url, "manual", [observation], [], {"analysis": "analyst-entered", "network_requests": 0, "independently_verified": False, "synthetic": program["is_demo"]})
        return app.state.database.get_finding(finding_ids[0])

    @app.get("/api/findings/{finding_id}/occurrences")
    def finding_occurrences(finding_id: str):
        return app.state.database.occurrences(finding_id)

    @app.post("/api/imports/analyze", status_code=201)
    def analyze_offline_import(payload: ImportCreate):
        from .offline import analyze_import
        program = app.state.database.get_program(payload.program_id)
        target = validate_program(program, payload.target_url, "import")
        try:
            observations, checks, warnings, summary = analyze_import(payload.format, payload.content, target, synthetic=program["is_demo"])
        except ValueError as error:
            raise ScopeError(str(error)) from None
        source = "http-import" if payload.format == "http" else "openapi"
        scan, _ids = app.state.database.create_offline_result(program["id"], target.url, source, observations, checks, summary)
        return {"scan": scan, "findings_count": len(observations), "warnings": warnings}

    @app.patch("/api/findings/{finding_id}")
    def update_finding(finding_id: str, payload: FindingUpdate):
        return app.state.database.update_finding(finding_id, payload.status, payload.notes)

    @app.get("/api/findings/{finding_id}/report", response_class=PlainTextResponse)
    def finding_report(finding_id: str):
        finding = app.state.database.get_finding(finding_id)
        return PlainTextResponse(render_report(finding), headers={"Content-Disposition": f'attachment; filename="scopeforge-{finding["id"]}.md"'})

    @app.get("/api/audit")
    def audit():
        return app.state.database.audit()

    # Unknown API paths stay JSON 404s even when a frontend is installed.
    @app.api_route("/api/{unknown:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    def unknown_api(unknown: str):
        raise HTTPException(status_code=404, detail="API endpoint not found.")

    static_dir = Path(frontend_dir or os.environ.get("SCOPEFORGE_FRONTEND_DIR", str(Path.cwd() / "frontend" / "dist")))
    if (static_dir / "index.html").is_file():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="dashboard")
    else:
        @app.get("/")
        def missing_dashboard():
            return {"application": "ScopeForge", "message": "Build the frontend to serve the dashboard here. The API is available at /api/health."}
    return app


app = create_app()
