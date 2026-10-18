"""SQLite-backed local vault, permissions and audit."""

import hashlib
import io
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
import zipfile
from pathlib import Path

from .crypto import protect, unprotect

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_EXPORT_BYTES = 50 * 1024 * 1024
DASHBOARD_AUDIT_LIMIT = 1000


class ValidationError(ValueError):
    pass


class Unauthorized(Exception):
    pass


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


def _label(value: str, *, filename: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError("Nome non valido")
    value = value.strip()
    limit = 120 if filename else 80
    if not value or len(value) > limit or value in {".", ".."}:
        raise ValidationError("Nome non valido")
    if any(ord(ch) < 32 or ch in '<>:"/\\|?*' for ch in value) or value.endswith("."):
        raise ValidationError("Nome non valido")
    if filename and value.split(".")[0].casefold() in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}:
        raise ValidationError("Nome riservato da Windows")
    return value


def _required_text(value: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise ValidationError("Campo obbligatorio o troppo lungo")
    return value.strip()


def _dict(row: sqlite3.Row) -> dict:
    return dict(row)


class Store:
    def __init__(self, root: str | Path, *, max_export_bytes: int = MAX_EXPORT_BYTES):
        self.root = Path(root)
        self.blob_dir = self.root / "blobs"
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self.max_export_bytes = max_export_bytes
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.root / "vault.db", check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS collections (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS resources (
                id TEXT PRIMARY KEY, collection_id TEXT NOT NULL REFERENCES collections(id),
                name TEXT NOT NULL, size INTEGER NOT NULL, created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grants (
                id TEXT PRIMARY KEY, collection_id TEXT NOT NULL REFERENCES collections(id),
                app_name TEXT NOT NULL, purpose TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE, created_at REAL NOT NULL,
                expires_at REAL NOT NULL, revoked_at REAL
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
                event TEXT NOT NULL, outcome TEXT NOT NULL,
                grant_id TEXT, resource_id TEXT, detail TEXT NOT NULL
            );
            """
        )
        self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _audit(self, event: str, outcome: str, *, grant_id: str | None = None, resource_id: str | None = None, detail: str = "", now: float | None = None) -> None:
        self._db.execute(
            "INSERT INTO audit(at,event,outcome,grant_id,resource_id,detail) VALUES (?,?,?,?,?,?)",
            (time.time() if now is None else now, event, outcome, grant_id, resource_id, detail),
        )

    def create_collection(self, name: str) -> dict:
        name = _label(name)
        result = {"id": str(uuid.uuid4()), "name": name, "created_at": time.time()}
        with self._lock, self._db:
            try:
                self._db.execute("INSERT INTO collections(id,name,created_at) VALUES (?,?,?)", tuple(result.values()))
            except sqlite3.IntegrityError as exc:
                raise ValidationError("Raccolta già esistente") from exc
            self._audit("collection", "allowed", detail="created")
        return result

    def import_resource(self, collection_id: str, name: str, data: bytes) -> dict:
        name = _label(name, filename=True)
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise ValidationError("File non valido o superiore a 10 MiB")
        result = {"id": str(uuid.uuid4()), "collection_id": collection_id, "name": name, "size": len(data), "created_at": time.time()}
        blob_path = self.blob_dir / f"{result['id']}.bin"
        temporary = self.blob_dir / f"{result['id']}.tmp"
        with self._lock:
            if not self._db.execute("SELECT 1 FROM collections WHERE id=?", (collection_id,)).fetchone():
                raise NotFound("Raccolta non trovata")
            try:
                temporary.write_bytes(protect(data))
                os.replace(temporary, blob_path)
                with self._db:
                    self._db.execute("INSERT INTO resources(id,collection_id,name,size,created_at) VALUES (?,?,?,?,?)", tuple(result.values()))
                    self._audit("import", "allowed", resource_id=result["id"])
            except Exception:
                temporary.unlink(missing_ok=True)
                blob_path.unlink(missing_ok=True)
                raise
        return result

    def create_grant(self, app_name: str, purpose: str, collection_id: str, duration_minutes: int, *, now: float | None = None) -> dict:
        app_name = _required_text(app_name, 80)
        purpose = _required_text(purpose, 200)
        if type(duration_minutes) is not int or not 1 <= duration_minutes <= 10080:
            raise ValidationError("Durata richiesta: da 1 minuto a 7 giorni")
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        result = {
            "id": str(uuid.uuid4()), "collection_id": collection_id,
            "app_name": app_name, "purpose": purpose,
            "created_at": now, "expires_at": now + duration_minutes * 60,
            "revoked_at": None,
        }
        with self._lock, self._db:
            if not self._db.execute("SELECT 1 FROM collections WHERE id=?", (collection_id,)).fetchone():
                raise NotFound("Raccolta non trovata")
            self._db.execute(
                "INSERT INTO grants(id,collection_id,app_name,purpose,token_hash,created_at,expires_at,revoked_at) VALUES (?,?,?,?,?,?,?,?)",
                (result["id"], collection_id, app_name, purpose, hashlib.sha256(token.encode()).hexdigest(), now, result["expires_at"], None),
            )
            self._audit("grant", "allowed", grant_id=result["id"], now=now)
        return {**result, "token": token}

    def revoke_grant(self, grant_id: str, *, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self._lock, self._db:
            row = self._db.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
            if row is None:
                raise NotFound("Delega non trovata")
            if row["revoked_at"] is None:
                self._db.execute("UPDATE grants SET revoked_at=? WHERE id=?", (now, grant_id))
                self._audit("revoke", "allowed", grant_id=grant_id, now=now)
            return {**{key: row[key] for key in row.keys() if key != "token_hash"}, "revoked_at": row["revoked_at"] or now}

    def _grant_for(self, token: str, event: str, resource_id: str | None, now: float) -> sqlite3.Row:
        if not token or len(token) > 256:
            self._audit(event, "denied", resource_id=resource_id, detail="invalid_token", now=now)
            self._db.commit()
            raise Unauthorized("Token mancante o non valido")
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = self._db.execute("SELECT * FROM grants WHERE token_hash=?", (digest,)).fetchone()
        if row is None:
            self._audit(event, "denied", resource_id=resource_id, detail="invalid_token", now=now)
            self._db.commit()
            raise Unauthorized("Token mancante o non valido")
        if row["revoked_at"] is not None or now >= row["expires_at"]:
            self._audit(event, "denied", grant_id=row["id"], resource_id=resource_id, detail="inactive_grant", now=now)
            self._db.commit()
            raise Forbidden("Delega scaduta o revocata")
        return row

    def list_resources(self, token: str, *, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        with self._lock, self._db:
            grant = self._grant_for(token, "list", None, now)
            rows = self._db.execute("SELECT id,collection_id,name,size,created_at FROM resources WHERE collection_id=? ORDER BY name,id", (grant["collection_id"],)).fetchall()
            self._audit("list", "allowed", grant_id=grant["id"], now=now)
            return [_dict(row) for row in rows]

    def read_resource(self, token: str, resource_id: str, *, now: float | None = None) -> bytes:
        now = time.time() if now is None else now
        with self._lock, self._db:
            grant = self._grant_for(token, "read", resource_id, now)
            resource = self._db.execute("SELECT * FROM resources WHERE id=? AND collection_id=?", (resource_id, grant["collection_id"])).fetchone()
            if resource is None:
                self._audit("read", "denied", grant_id=grant["id"], resource_id=resource_id, detail="out_of_scope", now=now)
                self._db.commit()
                raise NotFound("Risorsa non trovata")
            data = unprotect((self.blob_dir / f"{resource_id}.bin").read_bytes())
            self._audit("read", "allowed", grant_id=grant["id"], resource_id=resource_id, now=now)
            return data

    def state(self, *, full_audit: bool = False) -> dict:
        with self._lock:
            collections = [_dict(row) for row in self._db.execute("SELECT * FROM collections ORDER BY name")]
            resources = [_dict(row) for row in self._db.execute("SELECT * FROM resources ORDER BY created_at DESC")]
            grants = [{key: row[key] for key in row.keys() if key != "token_hash"} for row in self._db.execute("SELECT * FROM grants ORDER BY created_at DESC")]
            audit_query = "SELECT * FROM audit ORDER BY id DESC"
            if not full_audit:
                audit_query += f" LIMIT {DASHBOARD_AUDIT_LIMIT}"
            audit = [_dict(row) for row in self._db.execute(audit_query)]
            return {"collections": collections, "resources": resources, "grants": grants, "audit": audit}

    def export_zip(self) -> bytes:
        with self._lock, self._db:
            state = self.state(full_audit=True)
            total = sum(item["size"] for item in state["resources"])
            if total > self.max_export_bytes:
                raise ValidationError("Export superiore al limite di 50 MiB")
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", json.dumps(state, ensure_ascii=False, indent=2))
                for item in state["resources"]:
                    content = unprotect((self.blob_dir / f"{item['id']}.bin").read_bytes())
                    archive.writestr(f"documents/{item['collection_id']}/{item['id']}-{item['name']}", content)
            result = output.getvalue()
            if len(result) > self.max_export_bytes:
                raise ValidationError("Export superiore al limite di 50 MiB")
            self._audit("export", "allowed")
            return result
