import json
import sqlite3

import pytest

from datasovereign import cli


def test_serve_remains_loopback_and_closes_store_on_start_failure(tmp_path, monkeypatch):
    stores = []
    original = cli.Store

    def make_store(path):
        store = original(path)
        stores.append(store)
        return store

    def failed_start(app, **options):
        assert options["host"] == "127.0.0.1"
        assert options["port"] == 9876
        assert options["access_log"] is False
        raise OSError("port unavailable")

    monkeypatch.setattr(cli, "Store", make_store)
    monkeypatch.setattr(cli.uvicorn, "run", failed_start)
    with pytest.raises(OSError):
        cli.main(["serve", "--data-dir", str(tmp_path), "--port", "9876"])
    with pytest.raises(sqlite3.ProgrammingError):
        stores[0].state()


def test_doctor_reports_integrity_and_uses_exit_status(tmp_path, capsys):
    store = cli.Store(tmp_path)
    collection = store.create_collection("Docs")
    resource = store.import_resource(collection["id"], "a.txt", b"a")
    (store.blob_dir / f"{resource['id']}.bin").write_bytes(b"corrupt")
    store.close()
    with pytest.raises(SystemExit) as result:
        cli.main(["doctor", "--data-dir", str(tmp_path)])
    assert result.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["unreadable_resource_ids"] == [resource["id"]]
