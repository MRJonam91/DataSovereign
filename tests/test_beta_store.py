import sqlite3
import uuid

import pytest

from datasovereign.crypto import protect
from datasovereign.store import NotFound, Store, ValidationError


@pytest.fixture
def vault(tmp_path):
    store = Store(tmp_path)
    yield store
    store.close()


def test_existing_grant_never_reads_future_imports(vault):
    collection = vault.create_collection("Docs")
    first = vault.import_resource(collection["id"], "first.txt", b"first")
    grant = vault.create_grant("Agent", "Read", collection["id"], 30)
    future = vault.import_resource(collection["id"], "future.txt", b"future")
    assert [r["id"] for r in vault.list_resources(grant["token"])] == [first["id"]]
    with pytest.raises(NotFound):
        vault.read_resource(grant["token"], future["id"])


def test_explicit_document_selection_and_scope_validation(vault):
    collection = vault.create_collection("Docs")
    a = vault.import_resource(collection["id"], "a.txt", b"a")
    b = vault.import_resource(collection["id"], "b.txt", b"b")
    grant = vault.create_grant("Agent", "Read", collection["id"], 30, resource_ids=[a["id"]])
    assert grant["resource_ids"] == [a["id"]]
    with pytest.raises(NotFound):
        vault.read_resource(grant["token"], b["id"])
    other = vault.create_collection("Other")
    with pytest.raises(ValidationError):
        vault.create_grant("Agent", "Read", other["id"], 30, resource_ids=[a["id"]])
    with pytest.raises(ValidationError):
        vault.create_grant("Agent", "Read", collection["id"], 30, resource_ids=[])


def test_empty_collection_cannot_receive_new_delegation(vault):
    collection = vault.create_collection("Docs")
    with pytest.raises(ValidationError):
        vault.create_grant("Agent", "Read", collection["id"], 30)


def test_substituted_valid_dpapi_ciphertext_is_rejected(vault):
    from datasovereign.store import VaultDataError

    collection = vault.create_collection("Docs")
    a = vault.import_resource(collection["id"], "a.txt", b"a")
    b = vault.import_resource(collection["id"], "b.txt", b"b")
    grant = vault.create_grant("Agent", "Read", collection["id"], 30)
    (vault.blob_dir / f"{a['id']}.bin").write_bytes((vault.blob_dir / f"{b['id']}.bin").read_bytes())
    with pytest.raises(VaultDataError):
        vault.read_resource(grant["token"], a["id"])
    assert vault.health()["unreadable_resource_ids"] == [a["id"]]
    assert vault.state()["audit"][0]["outcome"] == "error"


def test_trash_then_restore_requires_new_document_consent(vault):
    collection = vault.create_collection("Docs")
    doc = vault.import_resource(collection["id"], "a.txt", b"a")
    grant = vault.create_grant("Agent", "Read", collection["id"], 30)
    vault.trash_resource(doc["id"])
    assert vault.list_resources(grant["token"]) == []
    vault.restore_resource(doc["id"])
    with pytest.raises(NotFound):
        vault.read_resource(grant["token"], doc["id"])
    assert vault.owner_read(doc["id"]) == b"a"


def test_audit_keyset_paging_and_denial_filter(vault):
    collection = vault.create_collection("Docs")
    doc = vault.import_resource(collection["id"], "a.txt", b"a")
    grant = vault.create_grant("Agent", "Read", collection["id"], 30)
    with pytest.raises(NotFound):
        vault.read_resource(grant["token"], str(uuid.uuid4()))
    first = vault.audit_page(limit=2)
    second = vault.audit_page(before=first["next_before"], limit=2)
    assert not {x["id"] for x in first["items"]} & {x["id"] for x in second["items"]}
    filtered = vault.audit_page(outcome="denied")
    assert len(filtered["items"]) == 1
    assert filtered["items"][0]["resource_id"] != doc["id"]


def test_alpha_database_migrates_existing_scope_once(tmp_path):
    cid, rid, gid = (str(uuid.uuid4()) for _ in range(3))
    import hashlib

    blob_dir = tmp_path / "blobs"
    blob_dir.mkdir()
    (blob_dir / f"{rid}.bin").write_bytes(protect(b"original"))
    with sqlite3.connect(tmp_path / "vault.db") as db:
        db.executescript("""
        CREATE TABLE collections(id TEXT PRIMARY KEY,name TEXT UNIQUE,created_at REAL);
        CREATE TABLE resources(id TEXT PRIMARY KEY,collection_id TEXT,name TEXT,size INTEGER,created_at REAL);
        CREATE TABLE grants(id TEXT PRIMARY KEY,collection_id TEXT,app_name TEXT,purpose TEXT,token_hash TEXT UNIQUE,created_at REAL,expires_at REAL,revoked_at REAL);
        CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at REAL,event TEXT,outcome TEXT,grant_id TEXT,resource_id TEXT,detail TEXT);
        """)
        db.execute("INSERT INTO collections VALUES (?,?,?)", (cid, "Legacy", 1))
        db.execute("INSERT INTO resources VALUES (?,?,?,?,?)", (rid, cid, "old.txt", 8, 1))
        db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,?)", (gid, cid, "App", "Read", hashlib.sha256(b"old-token").hexdigest(), 1, 9999999999, None))
    store = Store(tmp_path)
    try:
        assert (tmp_path / "vault.pre-beta.db").is_file()
        with sqlite3.connect(tmp_path / "vault.pre-beta.db") as rollback:
            assert rollback.execute("SELECT id FROM resources").fetchone()[0] == rid
            assert rollback.execute("PRAGMA user_version").fetchone()[0] == 0
            assert rollback.execute("SELECT name FROM sqlite_master WHERE name='grant_resources'").fetchone() is None
        assert store.read_resource("old-token", rid) == b"original"
        future = store.import_resource(cid, "new.txt", b"new")
    finally:
        store.close()
    reopened = Store(tmp_path)
    try:
        with pytest.raises(NotFound):
            reopened.read_resource("old-token", future["id"])
        assert reopened.health()["schema_version"] == 2
    finally:
        reopened.close()


def test_future_schema_is_not_modified(tmp_path):
    with sqlite3.connect(tmp_path / "vault.db") as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(RuntimeError):
        Store(tmp_path)
    with sqlite3.connect(tmp_path / "vault.db") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 999
        assert db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
