from fastapi.testclient import TestClient

from datasovereign.api import create_app
from datasovereign.store import Store


def test_owner_grant_api_and_revocation(tmp_path):
    vault = Store(tmp_path)
    client = TestClient(create_app(vault, "owner-secret"), base_url="http://127.0.0.1")
    owner = {"Authorization": "Bearer owner-secret"}

    assert client.post("/admin/collections", json={"name": "Documenti"}).status_code == 401
    collection = client.post("/admin/collections", json={"name": "Documenti"}, headers=owner).json()
    imported = client.post(
        f"/admin/collections/{collection['id']}/resources",
        content=b"private text",
        headers={**owner, "X-File-Name": "note.txt", "Content-Type": "application/octet-stream"},
    )
    assert imported.status_code == 201
    resource = imported.json()
    created = client.post(
        "/admin/grants",
        json={"app_name": "Agente AI", "purpose": "Leggere note", "collection_id": collection["id"], "duration_minutes": 30},
        headers=owner,
    )
    assert created.status_code == 201
    grant = created.json()
    app_headers = {"Authorization": f"Bearer {grant['token']}"}

    listed = client.get("/v1/resources", headers=app_headers)
    assert [item["id"] for item in listed.json()] == [resource["id"]]
    assert client.get(f"/v1/resources/{resource['id']}/content", headers=app_headers).content == b"private text"
    assert client.post(f"/admin/grants/{grant['id']}/revoke", headers=owner).status_code == 200
    assert client.get("/v1/resources", headers=app_headers).status_code == 403

    state = client.get("/admin/state", headers=owner)
    assert state.status_code == 200
    assert "token_hash" not in state.text
    assert grant["token"] not in state.text
    vault.close()


def test_wrong_collection_resource_is_hidden(tmp_path):
    vault = Store(tmp_path)
    client = TestClient(create_app(vault, "owner-secret"), base_url="http://127.0.0.1")
    docs = vault.create_collection("Docs")
    photos = vault.create_collection("Photos")
    photo = vault.import_resource(photos["id"], "private.jpg", b"secret")
    grant = vault.create_grant("Agent", "Docs", docs["id"], 30)

    response = client.get(f"/v1/resources/{photo['id']}/content", headers={"Authorization": f"Bearer {grant['token']}"})
    assert response.status_code == 404
    assert response.content != b"secret"
    vault.close()


def test_local_api_rejects_foreign_host_and_invalid_token(tmp_path):
    vault = Store(tmp_path)
    loopback = TestClient(create_app(vault, "owner-secret"), base_url="http://127.0.0.1")
    foreign = TestClient(create_app(vault, "owner-secret"), base_url="http://attacker.test")

    assert foreign.get("/admin/state", headers={"Authorization": "Bearer owner-secret"}).status_code == 400
    assert loopback.get("/v1/resources", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert any(item["detail"] == "invalid_token" for item in vault.state()["audit"])
    vault.close()


def test_http_import_limit_rejects_body_before_storing_it(tmp_path):
    vault = Store(tmp_path)
    client = TestClient(create_app(vault, "owner-secret"), base_url="http://127.0.0.1")
    owner = {"Authorization": "Bearer owner-secret"}
    collection = vault.create_collection("Documenti")

    response = client.post(
        f"/admin/collections/{collection['id']}/resources",
        content=b"x" * (10 * 1024 * 1024 + 1),
        headers={**owner, "X-File-Name": "large.bin", "Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 413
    assert vault.state()["resources"] == []
    vault.close()
