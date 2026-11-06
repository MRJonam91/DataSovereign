"""Loopback HTTP API for the owner and delegated applications."""

import secrets
import sqlite3
from pathlib import Path
from urllib.parse import unquote

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .store import MAX_FILE_BYTES, Forbidden, NotFound, Store, Unauthorized, ValidationError, VaultDataError
from .backup import MAX_BACKUP_BYTES
from .http_security import LocalSecurityMiddleware, read_limited

STATIC = Path(__file__).parent / "static"


class CollectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)


class GrantInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app_name: str = Field(min_length=1, max_length=80)
    purpose: str = Field(min_length=1, max_length=200)
    collection_id: str = Field(min_length=36, max_length=36)
    duration_minutes: int = Field(strict=True, ge=1, le=10080)
    resource_ids: list[str] | None = Field(default=None, max_length=1000)


def _bearer(request: Request) -> str:
    value = request.headers.get("authorization", "")
    prefix, sep, token = value.partition(" ")
    if prefix.casefold() != "bearer" or not sep:
        return ""
    return token.strip()


def _error(exc: Exception) -> HTTPException:
    if isinstance(exc, Unauthorized):
        return HTTPException(401, str(exc))
    if isinstance(exc, Forbidden):
        return HTTPException(403, str(exc))
    if isinstance(exc, NotFound):
        return HTTPException(404, str(exc))
    if isinstance(exc, ValidationError):
        return HTTPException(400, str(exc))
    if isinstance(exc, VaultDataError):
        return HTTPException(409, str(exc))
    if isinstance(exc, (OSError, sqlite3.Error)):
        return HTTPException(503, "Archivio non disponibile: verifica il dispositivo e riprova")
    raise exc


def _call(method, *args, **kwargs):
    try:
        return method(*args, **kwargs)
    except Exception as exc:
        raise _error(exc) from exc


def create_app(store: Store, owner_token: str) -> FastAPI:
    if not owner_token:
        raise ValueError("Chiave admin obbligatoria")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(LocalSecurityMiddleware, owner_token=owner_token)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        return response

    def owner(request: Request) -> None:
        token = _bearer(request)
        if not token or not secrets.compare_digest(token.encode("utf-8"), owner_token.encode("utf-8")):
            raise HTTPException(401, "Chiave di amministrazione non valida")

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return JSONResponse({"detail": "Richiesta non valida: controlla campi e valori"}, status_code=422)

    @app.get("/")
    def dashboard():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/admin/state", dependencies=[Depends(owner)])
    def state():
        return store.state(include_audit=False)

    @app.post("/admin/collections", status_code=201, dependencies=[Depends(owner)])
    def create_collection(payload: CollectionInput):
        try:
            return store.create_collection(payload.name)
        except Exception as exc:
            raise _error(exc) from exc

    @app.post("/admin/collections/{collection_id}/resources", status_code=201, dependencies=[Depends(owner)])
    async def import_resource(collection_id: str, request: Request):
        filename = unquote(request.headers.get("x-file-name", ""))
        data = await read_limited(request, MAX_FILE_BYTES)
        try:
            return await run_in_threadpool(store.import_resource, collection_id, filename, data)
        except Exception as exc:
            raise _error(exc) from exc

    @app.post("/admin/grants", status_code=201, dependencies=[Depends(owner)])
    def create_grant(payload: GrantInput):
        try:
            return store.create_grant(payload.app_name, payload.purpose, payload.collection_id, payload.duration_minutes, resource_ids=payload.resource_ids)
        except Exception as exc:
            raise _error(exc) from exc

    @app.post("/admin/grants/{grant_id}/revoke", dependencies=[Depends(owner)])
    def revoke_grant(grant_id: str):
        try:
            return store.revoke_grant(grant_id)
        except Exception as exc:
            raise _error(exc) from exc

    @app.get("/admin/export", dependencies=[Depends(owner)])
    def export_data():
        try:
            data = store.export_zip()
        except Exception as exc:
            raise _error(exc) from exc
        return Response(data, media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="datasovereign-export.zip"'})

    @app.get("/v1/resources")
    def list_resources(request: Request):
        try:
            return store.list_resources(_bearer(request))
        except Exception as exc:
            raise _error(exc) from exc

    @app.get("/v1/resources/{resource_id}/content")
    def read_resource(resource_id: str, request: Request):
        try:
            data = store.read_resource(_bearer(request), resource_id)
        except Exception as exc:
            raise _error(exc) from exc
        return Response(data, media_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="document.bin"'})

    @app.get("/admin/resources/{resource_id}/content", dependencies=[Depends(owner)])
    def owner_read(resource_id: str):
        return Response(_call(store.owner_read, resource_id), media_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="document.bin"'})

    @app.post("/admin/resources/{resource_id}/trash", dependencies=[Depends(owner)])
    def trash_resource(resource_id: str):
        return _call(store.trash_resource, resource_id)

    @app.post("/admin/resources/{resource_id}/restore", dependencies=[Depends(owner)])
    def restore_resource(resource_id: str):
        return _call(store.restore_resource, resource_id)

    @app.get("/admin/audit", dependencies=[Depends(owner)])
    def audit(before: int | None = Query(None, ge=1), outcome: str | None = Query(None, pattern="^(allowed|denied|error)$"), limit: int = Query(50, ge=1, le=200)):
        return _call(store.audit_page, before=before, outcome=outcome, limit=limit)

    @app.get("/admin/health", dependencies=[Depends(owner)])
    def health():
        return _call(store.health)

    @app.get("/admin/backup", dependencies=[Depends(owner)])
    def backup():
        return Response(_call(store.backup_zip), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="datasovereign-backup.zip"'})

    @app.post("/admin/backup/restore", dependencies=[Depends(owner)])
    async def restore_backup(request: Request):
        data = await read_limited(request, MAX_BACKUP_BYTES)
        return await run_in_threadpool(_call, store.restore_backup, data)

    return app
