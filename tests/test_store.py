import io
import json
import zipfile

import pytest

from datasovereign.store import Forbidden, NotFound, Store, ValidationError


@pytest.fixture
def vault(tmp_path):
    store = Store(tmp_path)
    yield store
    store.close()


def test_grant_reads_only_its_collection_and_blobs_are_encrypted(vault, tmp_path):
    documents = vault.create_collection("Documenti")
    photos = vault.create_collection("Foto")
    doc = vault.import_resource(documents["id"], "contratto.txt", b"contratto privato")
    photo = vault.import_resource(photos["id"], "foto.txt", b"foto privata")
    grant = vault.create_grant("Agente AI", "Leggere il contratto", documents["id"], 30)

    assert b"contratto privato" not in (tmp_path / "blobs" / f"{doc['id']}.bin").read_bytes()
    assert [item["id"] for item in vault.list_resources(grant["token"])] == [doc["id"]]
    assert vault.read_resource(grant["token"], doc["id"]) == b"contratto privato"
    with pytest.raises(NotFound):
        vault.read_resource(grant["token"], photo["id"])
    assert any(item["event"] == "read" and item["outcome"] == "denied" for item in vault.state()["audit"])


def test_revocation_and_expiry_block_new_reads(vault):
    collection = vault.create_collection("Documenti")
    resource = vault.import_resource(collection["id"], "a.txt", b"A")
    grant = vault.create_grant("Agent", "Search", collection["id"], 1, now=1000)

    assert vault.read_resource(grant["token"], resource["id"], now=1001) == b"A"
    with pytest.raises(Forbidden):
        vault.read_resource(grant["token"], resource["id"], now=1060)

    second = vault.create_grant("Agent", "Search", collection["id"], 60, now=1000)
    vault.revoke_grant(second["id"], now=1002)
    with pytest.raises(Forbidden):
        vault.read_resource(second["token"], resource["id"], now=1003)


def test_import_rejects_paths_and_oversized_content(vault):
    collection = vault.create_collection("Documenti")
    with pytest.raises(ValidationError):
        vault.import_resource(collection["id"], "../secret.txt", b"x")
    with pytest.raises(ValidationError):
        vault.import_resource(collection["id"], "sub\\secret.txt", b"x")
    with pytest.raises(ValidationError):
        vault.import_resource(collection["id"], "large.bin", b"x" * (10 * 1024 * 1024 + 1))


def test_export_includes_plaintext_and_audit_but_never_token(vault):
    collection = vault.create_collection("Documenti")
    vault.import_resource(collection["id"], "a.txt", b"hello")
    grant = vault.create_grant("Agent", "Search", collection["id"], 30)
    archive = vault.export_zip()

    assert grant["token"].encode() not in archive
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        assert len(manifest["collections"]) == 1
        assert len(manifest["grants"]) == 1
        assert "token_hash" not in str(manifest)
        document_path = next(name for name in zf.namelist() if name.startswith("documents/"))
        assert zf.read(document_path) == b"hello"


def test_export_enforces_limit(tmp_path):
    vault = Store(tmp_path, max_export_bytes=2)
    try:
        collection = vault.create_collection("Documenti")
        vault.import_resource(collection["id"], "a.txt", b"hello")
        with pytest.raises(ValidationError):
            vault.export_zip()
    finally:
        vault.close()


def test_export_includes_complete_audit_not_only_dashboard_window(vault, monkeypatch):
    monkeypatch.setattr("datasovereign.store.DASHBOARD_AUDIT_LIMIT", 2)
    collection = vault.create_collection("Documenti")
    grant = vault.create_grant("Agent", "Search", collection["id"], 30)
    for _ in range(3):
        vault.list_resources(grant["token"])

    assert len(vault.state()["audit"]) == 2
    with zipfile.ZipFile(io.BytesIO(vault.export_zip())) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert len(manifest["audit"]) >= 5
