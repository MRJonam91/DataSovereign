"""Bounded encrypted backup format. No archive paths are extracted."""

import hashlib
import io
import json
import os
import secrets
import time
import uuid
import zipfile
from typing import Literal

from pydantic import BaseModel, Field, ValidationError as ModelError

from .crypto import protect, unprotect

MAX_BACKUP_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
ID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class Collection(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    name: str = Field(min_length=1, max_length=80)
    created_at: float = Field(ge=0, allow_inf_nan=False)


class Resource(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    collection_id: str = Field(pattern=ID_PATTERN)
    name: str = Field(min_length=1, max_length=120)
    size: int = Field(strict=True, ge=0, le=10 * 1024 * 1024)
    created_at: float = Field(ge=0, allow_inf_nan=False)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deleted_at: float | None = Field(default=None, ge=0, allow_inf_nan=False)


class Grant(BaseModel):
    id: str = Field(pattern=ID_PATTERN)
    collection_id: str = Field(pattern=ID_PATTERN)
    app_name: str = Field(min_length=1, max_length=80)
    purpose: str = Field(min_length=1, max_length=200)
    created_at: float = Field(ge=0, allow_inf_nan=False)
    expires_at: float = Field(ge=0, allow_inf_nan=False)
    revoked_at: float | None = Field(default=None, ge=0, allow_inf_nan=False)


class Audit(BaseModel):
    at: float = Field(ge=0, allow_inf_nan=False)
    event: str = Field(min_length=1, max_length=40)
    outcome: Literal["allowed", "denied", "error"]
    grant_id: str | None = Field(default=None, max_length=256)
    resource_id: str | None = Field(default=None, max_length=256)
    detail: str = Field(max_length=256)


class Manifest(BaseModel):
    format: Literal["datasovereign-dpapi"]
    version: Literal[1]
    collections: list[Collection] = Field(max_length=10000)
    resources: list[Resource] = Field(max_length=9999)
    grants: list[Grant] = Field(max_length=10000)
    audit: list[Audit]


def build_backup(store) -> bytes:
    from .store import ValidationError, _canonical_id

    state = store.state(full_audit=True)
    for event in state["audit"]:
        for key in ("resource_id", "grant_id"):
            event[key] = _canonical_id(event[key]) if event[key] is not None else None
    try:
        Manifest.model_validate({"format": "datasovereign-dpapi", "version": 1, **state})
    except ModelError as exc:
        raise ValidationError("Backup non creabile: verifica integrità e dimensioni dei metadati") from exc
    metadata = json.dumps({"format": "datasovereign-dpapi", "version": 1, **state}, ensure_ascii=False).encode()
    if len(metadata) > MAX_METADATA_BYTES or len(state["resources"]) >= 10000:
        raise ValidationError("Metadati backup superiori al limite")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.dpapi", protect(metadata))
        for resource in state["resources"]:
            store._content(resource)
            blob = (store.blob_dir / f"{resource['id']}.bin").read_bytes()
            if output.tell() + len(blob) > MAX_BACKUP_BYTES - 65536:
                raise ValidationError("Backup superiore a 64 MiB")
            archive.writestr(f"blobs/{resource['id']}.bin", blob)
    result = output.getvalue()
    if len(result) > MAX_BACKUP_BYTES:
        raise ValidationError("Backup superiore a 64 MiB")
    store._audit("backup", "allowed")
    return result


def decode_backup(data: bytes):
    from .store import MAX_FILE_BYTES, ValidationError, _label

    try:
        if not isinstance(data, bytes) or len(data) > MAX_BACKUP_BYTES:
            raise ValueError("size")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > 10000 or len({m.filename for m in members}) != len(members):
                raise ValueError("entries")
            if sum(m.file_size for m in members) > MAX_BACKUP_BYTES:
                raise ValueError("expanded size")
            if any(m.flag_bits & 1 or m.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) for m in members):
                raise ValueError("encoding")
            if archive.getinfo("manifest.dpapi").file_size > MAX_METADATA_BYTES + 65536:
                raise ValueError("metadata")
            metadata = unprotect(archive.read("manifest.dpapi"))
            if len(metadata) > MAX_METADATA_BYTES:
                raise ValueError("metadata")
            manifest = Manifest.model_validate_json(metadata)
            for rows in (manifest.collections, manifest.resources, manifest.grants):
                if len({row.id for row in rows}) != len(rows):
                    raise ValueError("duplicate ID")
            collection_ids = {c.id for c in manifest.collections}
            if len({c.name for c in manifest.collections}) != len(manifest.collections):
                raise ValueError("duplicate collection")
            for collection in manifest.collections:
                if _label(collection.name) != collection.name:
                    raise ValueError("name")
            if any(g.collection_id not in collection_ids for g in manifest.grants):
                raise ValueError("grant collection")
            expected = {"manifest.dpapi", *(f"blobs/{r.id}.bin" for r in manifest.resources)}
            if {m.filename for m in members} != expected:
                raise ValueError("paths")
            blobs = {}
            for resource in manifest.resources:
                if resource.collection_id not in collection_ids or _label(resource.name, filename=True) != resource.name:
                    raise ValueError("resource")
                path = f"blobs/{resource.id}.bin"
                if archive.getinfo(path).file_size > MAX_FILE_BYTES + 65536:
                    raise ValueError("blob size")
                blob = archive.read(path)
                plaintext = unprotect(blob)
                if len(plaintext) != resource.size or hashlib.sha256(plaintext).hexdigest() != resource.sha256:
                    raise ValueError("integrity")
                blobs[resource.id] = blob
            return manifest, blobs
    except (ValueError, TypeError, KeyError, OSError, ModelError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ValidationError("Backup non valido, corrotto o non decifrabile da questo account Windows") from exc


def restore_backup(store, data: bytes) -> dict:
    with store._db:
        store._db.execute("BEGIN IMMEDIATE")
        return _restore_locked(store, data)


def _restore_locked(store, data: bytes) -> dict:
    from .store import ValidationError

    if any(store._db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() for table in ("collections", "resources", "grants")):
        raise ValidationError("Ripristino consentito solo in un vault vuoto")
    manifest, blobs = decode_backup(data)
    if any(store.blob_dir.iterdir()):
        raise ValidationError("Il vault contiene file da verificare prima del ripristino")
    stage = store.root / f".restore-{uuid.uuid4()}"
    stage.mkdir()
    created = []
    try:
        for rid, blob in blobs.items():
            (stage / f"{rid}.bin").write_bytes(blob)
        with store._db:
            for c in manifest.collections:
                store._db.execute("INSERT INTO collections VALUES (?,?,?)", (c.id, c.name, c.created_at))
            for r in manifest.resources:
                store._db.execute("INSERT INTO resources(id,collection_id,name,size,created_at,sha256,deleted_at) VALUES (?,?,?,?,?,?,?)", (r.id, r.collection_id, r.name, r.size, r.created_at, r.sha256, r.deleted_at))
                target = store.blob_dir / f"{r.id}.bin"
                os.replace(stage / target.name, target)
                created.append(target)
            for g in manifest.grants:
                store._db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,?)", (g.id, g.collection_id, g.app_name, g.purpose, hashlib.sha256(secrets.token_bytes(32)).hexdigest(), g.created_at, g.expires_at, time.time()))
            for a in reversed(manifest.audit):
                store._db.execute("INSERT INTO audit(at,event,outcome,grant_id,resource_id,detail) VALUES (?,?,?,?,?,?)", (a.at, a.event, a.outcome, a.grant_id, a.resource_id, a.detail))
            store._audit("restore_backup", "allowed")
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    finally:
        for path in stage.iterdir():
            path.unlink()
        stage.rmdir()
    return {"collections": len(manifest.collections), "resources": len(manifest.resources), "grants_revoked": len(manifest.grants)}
