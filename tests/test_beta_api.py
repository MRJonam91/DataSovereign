import json
import uuid

import pytest
from fastapi.testclient import TestClient

from datasovereign.api import create_app
from datasovereign.store import Store

OWNER = {"Authorization": "Bearer owner-test"}


@pytest.fixture
def api(tmp_path):
    store = Store(tmp_path)
    with TestClient(create_app(store, "owner-test"), base_url="http://127.0.0.1") as client:
        yield client, store
    store.close()


def test_http_document_scope_and_trash_restore(api):
    client, store = api
    col = store.create_collection("Docs")
    a = store.import_resource(col["id"], "a.txt", b"a")
    b = store.import_resource(col["id"], "b.txt", b"b")
    response = client.post("/admin/grants", headers=OWNER, json={"app_name": "Agent", "purpose": "Read", "collection_id": col["id"], "duration_minutes": 30, "resource_ids": [a["id"]]})
    assert response.status_code == 201
    token = {"Authorization": f"Bearer {response.json()['token']}"}
    assert client.get(f"/v1/resources/{b['id']}/content", headers=token).status_code == 404
    assert client.post(f"/admin/resources/{a['id']}/trash", headers=OWNER).status_code == 200
    assert client.post(f"/admin/resources/{a['id']}/restore", headers=OWNER).status_code == 200
    assert client.get(f"/v1/resources/{a['id']}/content", headers=token).status_code == 404
    assert client.get(f"/admin/resources/{a['id']}/content", headers=OWNER).content == b"a"


@pytest.mark.parametrize("duration", [True, "30", 1.5, 0, 10081])
def test_duration_is_strict_and_validation_does_not_echo_input(api, duration):
    client, store = api
    col = store.create_collection("Docs")
    response = client.post("/admin/grants", headers=OWNER, json={"app_name": "sensitive-input-value", "purpose": "Read", "collection_id": col["id"], "duration_minutes": duration})
    assert response.status_code == 422
    assert "sensitive-input-value" not in response.text


def test_large_chunked_json_is_bounded(api):
    client, _ = api
    body = json.dumps({"name": "x" * 70000}).encode()
    response = client.post("/admin/collections", headers={**OWNER, "Content-Type": "application/json"}, content=iter([body[:30000], body[30000:]]))
    assert response.status_code == 413


def test_non_ascii_owner_token_and_foreign_origin_are_safe(api):
    client, _ = api
    response = client.get("/admin/state", headers=[(b"authorization", b"Bearer \xe9")])
    assert response.status_code == 401
    assert client.get("/admin/state", headers={**OWNER, "Origin": "https://evil.test"}).status_code == 403


def test_failed_reads_do_not_persist_arbitrary_path_text(api):
    client, store = api
    client.get("/v1/resources/" + "x" * 2000 + "/content")
    assert store.state()["audit"][0]["resource_id"] is None


def test_corrupt_document_returns_controlled_error_and_health_result(api):
    client, store = api
    col = store.create_collection("Docs")
    doc = store.import_resource(col["id"], "a.txt", b"a")
    (store.blob_dir / f"{doc['id']}.bin").write_bytes(b"corrupt")
    response = client.get(f"/admin/resources/{doc['id']}/content", headers=OWNER)
    assert response.status_code == 409
    assert str(store.root) not in response.text
    health = client.get("/admin/health", headers=OWNER)
    assert health.json()["unreadable_resource_ids"] == [doc["id"]]


def test_backup_route_and_restore_into_empty_vault(api, tmp_path):
    client, store = api
    col = store.create_collection("Docs")
    doc = store.import_resource(col["id"], "a.txt", b"a")
    backup = client.get("/admin/backup", headers=OWNER)
    assert backup.status_code == 200
    assert backup.headers["cache-control"] == "no-store"
    target = Store(tmp_path / "target")
    try:
        with TestClient(create_app(target, "owner-test"), base_url="http://127.0.0.1") as target_client:
            response = target_client.post("/admin/backup/restore", content=backup.content, headers=OWNER)
            assert response.status_code == 200
            assert target.owner_read(doc["id"]) == b"a"
    finally:
        target.close()


def test_http_audit_page_is_bounded_and_filterable(api):
    client, store = api
    for _ in range(3):
        client.get(f"/v1/resources/{uuid.uuid4()}/content")
    response = client.get("/admin/audit?limit=2&outcome=denied", headers=OWNER)
    assert response.status_code == 200
    assert len(response.json()["items"]) == 2
    assert response.json()["next_before"]
    assert client.get("/admin/audit?limit=100000", headers=OWNER).status_code == 422
