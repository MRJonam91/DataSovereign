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
from .schema import SCHEMA_VERSION, migrate

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


class VaultDataError(Exception):
    pass


def _canonical_id(value: str) -> str | None:
    try:
        return str(uuid.UUID(value)) if len(value) == 36 else None
    except (ValueError, TypeError, AttributeError):
        return None


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
        try:
            migrate(self._db, self.blob_dir)
        except Exception:
            self._db.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def backup_zip(self) -> bytes:
        from .backup import build_backup
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            return build_backup(self)

    def restore_backup(self, data: bytes) -> dict:
        from .backup import restore_backup
        with self._lock:
            return restore_backup(self, data)

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
        result = {"id": str(uuid.uuid4()), "collection_id": collection_id, "name": name, "size": len(data), "created_at": time.time(), "sha256": hashlib.sha256(data).hexdigest(), "deleted_at": None}
        blob_path = self.blob_dir / f"{result['id']}.bin"
        temporary = self.blob_dir / f"{result['id']}.tmp"
        with self._lock:
            if not self._db.execute("SELECT 1 FROM collections WHERE id=?", (collection_id,)).fetchone():
                raise NotFound("Raccolta non trovata")
            try:
                temporary.write_bytes(protect(data))
                os.replace(temporary, blob_path)
                with self._db:
                    self._db.execute("INSERT INTO resources(id,collection_id,name,size,created_at,sha256,deleted_at) VALUES (?,?,?,?,?,?,?)", tuple(result.values()))
                    self._audit("import", "allowed", resource_id=result["id"])
            except Exception:
                temporary.unlink(missing_ok=True)
                blob_path.unlink(missing_ok=True)
                raise
        return result

    def create_grant(self, app_name: str, purpose: str, collection_id: str, duration_minutes: int, *, now: float | None = None, resource_ids: list[str] | None = None) -> dict:
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
            self._db.execute("BEGIN IMMEDIATE")
            if not self._db.execute("SELECT 1 FROM collections WHERE id=?", (collection_id,)).fetchone():
                raise NotFound("Raccolta non trovata")
            available = {row[0] for row in self._db.execute("SELECT id FROM resources WHERE collection_id=? AND deleted_at IS NULL", (collection_id,))}
            if resource_ids is None:
                selected = sorted(available)
            elif isinstance(resource_ids, list) and all(isinstance(r, str) for r in resource_ids):
                selected = sorted(set(resource_ids))
            else:
                raise ValidationError("Selezione documenti non valida")
            if not selected or len(selected) > 1000 or not set(selected) <= available:
                raise ValidationError("Seleziona da 1 a 1000 documenti attivi della raccolta")
            self._db.execute(
                "INSERT INTO grants(id,collection_id,app_name,purpose,token_hash,created_at,expires_at,revoked_at) VALUES (?,?,?,?,?,?,?,?)",
                (result["id"], collection_id, app_name, purpose, hashlib.sha256(token.encode()).hexdigest(), now, result["expires_at"], None),
            )
            self._db.executemany("INSERT INTO grant_resources VALUES (?,?)", [(result["id"], rid) for rid in selected])
            self._audit("grant", "allowed", grant_id=result["id"], now=now)
        return {**result, "token": token, "scope": "snapshot", "resource_ids": selected}

    def revoke_grant(self, grant_id: str, *, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
            if row is None:
                raise NotFound("Delega non trovata")
            if row["revoked_at"] is None:
                self._db.execute("UPDATE grants SET revoked_at=? WHERE id=?", (now, grant_id))
                self._audit("revoke", "allowed", grant_id=grant_id, now=now)
            return {**{key: row[key] for key in row.keys() if key != "token_hash"}, "revoked_at": now if row["revoked_at"] is None else row["revoked_at"]}

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
            self._db.execute("BEGIN IMMEDIATE")
            grant = self._grant_for(token, "list", None, now)
            rows = self._db.execute("SELECT r.id,r.collection_id,r.name,r.size,r.created_at FROM resources r JOIN grant_resources s ON s.resource_id=r.id WHERE s.grant_id=? AND r.collection_id=? AND r.deleted_at IS NULL ORDER BY r.name,r.id", (grant["id"], grant["collection_id"])).fetchall()
            self._audit("list", "allowed", grant_id=grant["id"], now=now)
            return [_dict(row) for row in rows]

    def read_resource(self, token: str, resource_id: str, *, now: float | None = None) -> bytes:
        now = time.time() if now is None else now
        resource_id = _canonical_id(resource_id)
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            grant = self._grant_for(token, "read", resource_id, now)
            resource = self._db.execute("SELECT r.* FROM resources r JOIN grant_resources s ON s.resource_id=r.id WHERE r.id=? AND r.collection_id=? AND s.grant_id=? AND r.deleted_at IS NULL", (resource_id, grant["collection_id"], grant["id"])).fetchone()
            if resource is None:
                self._audit("read", "denied", grant_id=grant["id"], resource_id=resource_id, detail="out_of_scope", now=now)
                self._db.commit()
                raise NotFound("Risorsa non trovata")
            try:
                data = self._content(resource)
            except VaultDataError:
                self._audit("read", "error", grant_id=grant["id"], resource_id=resource_id, detail="integrity", now=now)
                self._db.commit()
                raise
            self._audit("read", "allowed", grant_id=grant["id"], resource_id=resource_id, now=now)
            return data

    def _content(self, resource) -> bytes:
        try:
            path = self.blob_dir / f"{resource['id']}.bin"
            if path.stat().st_size > MAX_FILE_BYTES + 65536:
                raise VaultDataError("Documento cifrato superiore al limite")
            data = unprotect(path.read_bytes())
        except OSError as exc:
            raise VaultDataError("Documento non disponibile o non decifrabile") from exc
        digest = hashlib.sha256(data).hexdigest()
        if not resource["sha256"] or not secrets.compare_digest(digest, resource["sha256"]) or len(data) != resource["size"]:
            raise VaultDataError("Integrità del documento non verificabile")
        return data

    def owner_read(self, resource_id: str) -> bytes:
        with self._lock, self._db:
            row = self._db.execute("SELECT * FROM resources WHERE id=? AND deleted_at IS NULL", (_canonical_id(resource_id),)).fetchone()
            if row is None:
                raise NotFound("Risorsa non trovata")
            try:
                data = self._content(row)
            except VaultDataError:
                self._audit("owner_read", "error", resource_id=row["id"], detail="integrity")
                self._db.commit()
                raise
            self._audit("owner_read", "allowed", resource_id=row["id"])
            return data

    def trash_resource(self, resource_id: str) -> dict:
        return self._set_deleted(resource_id, True)

    def restore_resource(self, resource_id: str) -> dict:
        return self._set_deleted(resource_id, False)

    def _set_deleted(self, resource_id: str, deleted: bool) -> dict:
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute("SELECT * FROM resources WHERE id=?", (_canonical_id(resource_id),)).fetchone()
            if row is None:
                raise NotFound("Risorsa non trovata")
            value = time.time() if deleted else None
            if (row["deleted_at"] is not None) != deleted:
                if not deleted:
                    self._content(row)
                self._db.execute("UPDATE resources SET deleted_at=? WHERE id=?", (value, row["id"]))
                self._db.execute("DELETE FROM grant_resources WHERE resource_id=?", (row["id"],))
                self._audit("trash" if deleted else "restore_document", "allowed", resource_id=row["id"])
            return {"id": row["id"], "deleted_at": value if (row["deleted_at"] is not None) != deleted else row["deleted_at"]}

    def audit_page(self, *, before: int | None = None, outcome: str | None = None, limit: int = 50) -> dict:
        if type(limit) is not int or not 1 <= limit <= 200 or (before is not None and (type(before) is not int or before < 1)) or outcome not in (None, "allowed", "denied", "error"):
            raise ValidationError("Filtro audit non valido")
        clauses, parameters = [], []
        if before is not None:
            clauses.append("id<?")
            parameters.append(before)
        if outcome is not None:
            clauses.append("outcome=?")
            parameters.append(outcome)
        query = "SELECT * FROM audit" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self._db.execute(query, [*parameters, limit + 1]).fetchall()
            return {"items": [_dict(row) for row in rows[:limit]], "next_before": rows[limit - 1]["id"] if len(rows) > limit else None}

    def health(self) -> dict:
        with self._lock:
            rows = self._db.execute("SELECT * FROM resources ORDER BY id").fetchall()
            unreadable = []
            for row in rows:
                try:
                    self._content(row)
                except VaultDataError:
                    unreadable.append(row["id"])
            known = {f"{row['id']}.bin" for row in rows}
            orphan_count = sum(path.name not in known for path in self.blob_dir.glob("*.bin"))
            database_ok = self._db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            return {"ok": database_ok and not unreadable and not orphan_count, "schema_version": SCHEMA_VERSION, "active_count": sum(r["deleted_at"] is None for r in rows), "trashed_count": sum(r["deleted_at"] is not None for r in rows), "unreadable_resource_ids": unreadable, "orphan_blob_count": orphan_count}

    def state(self, *, full_audit: bool = False, include_audit: bool = True) -> dict:
        with self._lock:
            collections = [_dict(row) for row in self._db.execute("SELECT * FROM collections ORDER BY name")]
            resources = [_dict(row) for row in self._db.execute("SELECT * FROM resources ORDER BY created_at DESC")]
            grants = [{key: row[key] for key in row.keys() if key != "token_hash"} for row in self._db.execute("SELECT * FROM grants ORDER BY created_at DESC")]
            scopes = {}
            for row in self._db.execute("SELECT grant_id,resource_id FROM grant_resources ORDER BY resource_id"):
                scopes.setdefault(row["grant_id"], []).append(row["resource_id"])
            for grant in grants:
                grant.update(scope="snapshot", resource_ids=scopes.get(grant["id"], []))
            audit_query = "SELECT * FROM audit ORDER BY id DESC"
            if not full_audit:
                audit_query += f" LIMIT {DASHBOARD_AUDIT_LIMIT}"
            audit = [_dict(row) for row in self._db.execute(audit_query)] if include_audit else []
            return {"collections": collections, "resources": resources, "grants": grants, "audit": audit}

    def export_zip(self) -> bytes:
        with self._lock, self._db:
            state = self.state(full_audit=True)
            state["resources"] = [r for r in state["resources"] if r["deleted_at"] is None]
            total = sum(item["size"] for item in state["resources"])
            if total > self.max_export_bytes:
                raise ValidationError("Export superiore al limite di 50 MiB")
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", json.dumps(state, ensure_ascii=False, indent=2))
                for item in state["resources"]:
                    content = self._content(item)
                    archive.writestr(f"documents/{item['collection_id']}/{item['id']}-{item['name']}", content)
            result = output.getvalue()
            if len(result) > self.max_export_bytes:
                raise ValidationError("Export superiore al limite di 50 MiB")
            self._audit("export", "allowed")
            return result
