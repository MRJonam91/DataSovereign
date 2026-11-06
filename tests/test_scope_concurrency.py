import sqlite3

from datasovereign.store import Store


def test_scope_selection_serializes_against_other_store(tmp_path):
    first, second = Store(tmp_path), Store(tmp_path)
    try:
        collection = first.create_collection("Docs")
        document = first.import_resource(collection["id"], "a.txt", b"a")
        second._db.execute("PRAGMA busy_timeout=0")
        connection = first._db
        blocked = False

        class Interleave:
            def __getattr__(self, name):
                return getattr(connection, name)

            def __enter__(self):
                return connection.__enter__()

            def __exit__(self, *args):
                return connection.__exit__(*args)

            def execute(self, sql, *args):
                nonlocal blocked
                cursor = connection.execute(sql, *args)
                if sql.startswith("SELECT id FROM resources WHERE"):
                    rows = cursor.fetchall()
                    try:
                        second.trash_resource(document["id"])
                    except sqlite3.OperationalError as exc:
                        assert "locked" in str(exc).lower()
                        blocked = True
                    return rows
                return cursor

        first._db = Interleave()
        grant = first.create_grant("Agent", "Read", collection["id"], 30)
        if blocked:
            second.trash_resource(document["id"])
        second.restore_resource(document["id"])
        assert first.list_resources(grant["token"]) == []
        assert blocked
    finally:
        first.close()
        second.close()
