import io
import json
import zipfile

import pytest

from datasovereign.store import Store, Unauthorized, ValidationError
from datasovereign.crypto import protect, unprotect


def populated(path):
    vault = Store(path)
    collection = vault.create_collection("Docs")
    doc = vault.import_resource(collection["id"], "note.txt", b"private note")
    grant = vault.create_grant("Agent", "Read", collection["id"], 30)
    return vault, doc, grant


def rewrite(archive, change):
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        entries = {name: source.read(name) for name in source.namelist()}
    change(entries)
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as target:
        for name, value in entries.items():
            target.writestr(name, value)
    return result.getvalue()


def test_encrypted_backup_roundtrip_never_restores_live_tokens(tmp_path):
    source, doc, grant = populated(tmp_path / "source")
    destination = Store(tmp_path / "destination")
    try:
        archive = source.backup_zip()
        source.revoke_grant(grant["id"])
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            assert b"private note" not in zf.read(f"blobs/{doc['id']}.bin")
            assert b"Docs" not in zf.read("manifest.dpapi")
            metadata = unprotect(zf.read("manifest.dpapi"))
            assert grant["token"].encode() not in metadata
            assert b"token_hash" not in metadata
        destination.restore_backup(archive)
        assert destination.owner_read(doc["id"]) == b"private note"
        with pytest.raises(Unauthorized):
            destination.list_resources(grant["token"])
        assert destination.state()["grants"][0]["revoked_at"] is not None
        assert destination.health()["ok"]
    finally:
        source.close()
        destination.close()


@pytest.mark.parametrize("kind", ["traversal", "corruption", "missing", "duplicate_id", "bad_json"])
def test_invalid_backup_leaves_destination_empty(tmp_path, kind):
    source, doc, _ = populated(tmp_path / "source")
    destination = Store(tmp_path / "destination")
    try:
        def change(entries):
            key = f"blobs/{doc['id']}.bin"
            if kind == "traversal":
                entries["../outside.txt"] = b"bad"
            elif kind == "corruption":
                entries[key] = b"wrong account or corrupt"
            elif kind == "missing":
                del entries[key]
            elif kind == "bad_json":
                entries["manifest.dpapi"] = protect(b"[]")
            else:
                manifest = json.loads(unprotect(entries["manifest.dpapi"]))
                manifest["resources"].append(manifest["resources"][0])
                entries["manifest.dpapi"] = protect(json.dumps(manifest).encode())
        archive = rewrite(source.backup_zip(), change)
        with pytest.raises(ValidationError):
            destination.restore_backup(archive)
        assert destination.state()["collections"] == []
        assert list(destination.blob_dir.iterdir()) == []
    finally:
        source.close()
        destination.close()


def test_restore_never_overwrites_existing_data(tmp_path):
    vault, doc, _ = populated(tmp_path)
    try:
        with pytest.raises(ValidationError):
            vault.restore_backup(vault.backup_zip())
        assert vault.owner_read(doc["id"]) == b"private note"
    finally:
        vault.close()


def test_zip_bomb_is_rejected_before_decompression(tmp_path):
    vault = Store(tmp_path)
    output = io.BytesIO()
    try:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.dpapi", b" " * (2 * 1024 * 1024 + 65537))
        with pytest.raises(ValidationError):
            vault.restore_backup(output.getvalue())
        assert vault.state()["resources"] == []
    finally:
        vault.close()


def test_disk_failure_rolls_back_restore_database_and_files(tmp_path, monkeypatch):
    import datasovereign.backup as backup

    source, _, _ = populated(tmp_path / "source")
    target = Store(tmp_path / "target")
    try:
        archive = source.backup_zip()
        def fail_replace(*args):
            raise OSError("disk failure")
        monkeypatch.setattr(backup.os, "replace", fail_replace)
        with pytest.raises(OSError):
            target.restore_backup(archive)
        assert target.state()["collections"] == []
        assert list(target.blob_dir.iterdir()) == []
    finally:
        source.close()
        target.close()


def test_restore_preserves_historical_audit_order(tmp_path):
    source, _, grant = populated(tmp_path / "source")
    target = Store(tmp_path / "target")
    try:
        source.list_resources(grant["token"])
        events = [r["event"] for r in source.state()["audit"]]
        target.restore_backup(source.backup_zip())
        restored = [r["event"] for r in target.state()["audit"]]
        assert restored == ["restore_backup", *events]
    finally:
        source.close()
        target.close()


def test_backup_of_legacy_unbounded_audit_is_restorable(tmp_path):
    import sqlite3

    source, _, _ = populated(tmp_path / "source")
    target = Store(tmp_path / "target")
    try:
        with sqlite3.connect(source.root / "vault.db") as db:
            db.execute("INSERT INTO audit(at,event,outcome,resource_id,detail) VALUES (1,'read','denied',?,'invalid_token')", ("x" * 3000,))
        target.restore_backup(source.backup_zip())
        legacy = next(a for a in target.state()["audit"] if a["detail"] == "invalid_token")
        assert legacy["resource_id"] is None
    finally:
        source.close()
        target.close()
