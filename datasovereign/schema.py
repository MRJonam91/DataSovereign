"""Transactional, idempotent migration of alpha vaults."""

import hashlib
import sqlite3
from pathlib import Path

from .crypto import unprotect

SCHEMA_VERSION = 2


def migrate(db: sqlite3.Connection, blob_dir: Path) -> None:
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError("Vault creato da una versione più recente di DataSovereign")
    if version < 2 and db.execute("SELECT 1 FROM sqlite_master WHERE name='resources'").fetchone():
        rollback_path = blob_dir.parent / "vault.pre-beta.db"
        if not rollback_path.exists():
            rollback = sqlite3.connect(rollback_path)
            try:
                db.backup(rollback)
            except Exception:
                rollback.close()
                rollback_path.unlink(missing_ok=True)
                raise
            else:
                rollback.close()
    with db:
        db.execute("BEGIN IMMEDIATE")
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError("Vault creato da una versione più recente di DataSovereign")
        for statement in (
            "CREATE TABLE IF NOT EXISTS collections(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,created_at REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS resources(id TEXT PRIMARY KEY,collection_id TEXT NOT NULL REFERENCES collections(id),name TEXT NOT NULL,size INTEGER NOT NULL,created_at REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,collection_id TEXT NOT NULL REFERENCES collections(id),app_name TEXT NOT NULL,purpose TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,created_at REAL NOT NULL,expires_at REAL NOT NULL,revoked_at REAL)",
            "CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at REAL NOT NULL,event TEXT NOT NULL,outcome TEXT NOT NULL,grant_id TEXT,resource_id TEXT,detail TEXT NOT NULL)",
        ):
            db.execute(statement)
        columns = {row[1] for row in db.execute("PRAGMA table_info(resources)")}
        if "sha256" not in columns:
            db.execute("ALTER TABLE resources ADD COLUMN sha256 TEXT")
        if "deleted_at" not in columns:
            db.execute("ALTER TABLE resources ADD COLUMN deleted_at REAL")
        db.execute("CREATE TABLE IF NOT EXISTS grant_resources(grant_id TEXT NOT NULL REFERENCES grants(id),resource_id TEXT NOT NULL REFERENCES resources(id),PRIMARY KEY(grant_id,resource_id))")
        if version < 2:
            db.execute("INSERT OR IGNORE INTO grant_resources SELECT g.id,r.id FROM grants g JOIN resources r ON r.collection_id=g.collection_id WHERE r.deleted_at IS NULL")
            for row in db.execute("SELECT id FROM resources WHERE sha256 IS NULL").fetchall():
                try:
                    data = unprotect((blob_dir / f"{row[0]}.bin").read_bytes())
                except OSError:
                    continue  # Preserve unreadable alpha data for diagnosis/recovery.
                db.execute("UPDATE resources SET sha256=? WHERE id=?", (hashlib.sha256(data).hexdigest(), row[0]))
        db.execute("CREATE INDEX IF NOT EXISTS resources_collection ON resources(collection_id,deleted_at,name,id)")
        db.execute("CREATE INDEX IF NOT EXISTS audit_outcome ON audit(outcome,id)")
        db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
