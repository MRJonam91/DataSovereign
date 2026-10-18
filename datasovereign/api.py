"""Loopback HTTP API for the owner and delegated applications."""

import secrets
from pathlib import Path
from urllib.parse import unquote

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .store import MAX_FILE_BYTES, Forbidden, NotFound, Store, Unauthorized, ValidationError

STATIC = Path(__file__).parent / "static"


class CollectionInput(BaseModel):
    name: str


class GrantInput(BaseModel):
    app_name: str
    purpose: str
    collection_id: str
    duration_minutes: int


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
    raise exc


def create_app(store: Store, owner_token: str) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
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
        if not token or not secrets.compare_digest(token, owner_token):
            raise HTTPException(401, "Chiave di amministrazione non valida")

    @app.get("/")
    def dashboard():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/admin/state", dependencies=[Depends(owner)])
    def state():
        return store.state()

    @app.post("/admin/collections", status_code=201, dependencies=[Depends(owner)])
    def create_collection(payload: CollectionInput):
        try:
            return store.create_collection(payload.name)
        except Exception as exc:
            raise _error(exc) from exc

    @app.post("/admin/collections/{collection_id}/resources", status_code=201, dependencies=[Depends(owner)])
    async def import_resource(collection_id: str, request: Request):
        filename = unquote(request.headers.get("x-file-name", ""))
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > MAX_FILE_BYTES:
                raise HTTPException(413, "File superiore a 10 MiB")
            data.extend(chunk)
        try:
            return store.import_resource(collection_id, filename, bytes(data))
        except Exception as exc:
            raise _error(exc) from exc

    @app.post("/admin/grants", status_code=201, dependencies=[Depends(owner)])
    def create_grant(payload: GrantInput):
        try:
            return store.create_grant(payload.app_name, payload.purpose, payload.collection_id, payload.duration_minutes)
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

    return app
