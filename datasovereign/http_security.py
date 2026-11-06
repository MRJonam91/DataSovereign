"""Loopback owner authentication, same-origin checks and bounded JSON bodies."""

import secrets

from fastapi import HTTPException, Request
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

MAX_JSON_BYTES = 64 * 1024


def bearer(headers) -> str:
    prefix, sep, token = headers.get("authorization", "").partition(" ")
    return token.strip() if sep and prefix.casefold() == "bearer" else ""


async def read_limited(request: Request, limit: int) -> bytes:
    length = request.headers.get("content-length")
    if length is not None:
        try:
            size = int(length)
        except ValueError as exc:
            raise HTTPException(400, "Lunghezza richiesta non valida") from exc
        if size < 0:
            raise HTTPException(400, "Lunghezza richiesta non valida")
        if size > limit:
            raise HTTPException(413, "Richiesta superiore al limite")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > limit:
            raise HTTPException(413, "Richiesta superiore al limite")
        data.extend(chunk)
    return bytes(data)


class LocalSecurityMiddleware:
    def __init__(self, app, owner_token: str):
        self.app = app
        self.owner_token = owner_token.encode("utf-8")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        origin = headers.get("origin")
        if origin is not None and origin != f"http://{headers.get('host', '')}":
            return await JSONResponse({"detail": "Origine richiesta non consentita"}, status_code=403)(scope, receive, send)
        path = scope["path"]
        if path == "/admin" or path.startswith("/admin/"):
            token = bearer(headers).encode("utf-8")
            if not token or not secrets.compare_digest(token, self.owner_token):
                return await JSONResponse({"detail": "Chiave di amministrazione non valida"}, status_code=401)(scope, receive, send)
        if scope["method"] == "POST" and path in ("/admin/collections", "/admin/grants"):
            try:
                data = await read_limited(Request(scope, receive), MAX_JSON_BYTES)
            except HTTPException as exc:
                return await JSONResponse({"detail": exc.detail}, status_code=exc.status_code)(scope, receive, send)
            delivered = False

            async def bounded_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": data, "more_body": False}
                return await receive()

            return await self.app(scope, bounded_receive, send)
        return await self.app(scope, receive, send)
