"""Run the local DataSovereign service."""

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

import uvicorn

from .api import create_app
from .store import Store
from . import __version__


def default_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise RuntimeError("LOCALAPPDATA non disponibile: specifica --data-dir")
    return Path(base) / "DataSovereign" / "alpha"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="DataSovereign: vault locale per Windows")
    parser.add_argument("command", nargs="?", choices=["serve", "doctor"], default="serve")
    parser.add_argument("--version", action="version", version=f"DataSovereign {__version__}")
    parser.add_argument("--data-dir", type=Path, help="Directory del vault locale")
    parser.add_argument("--port", type=int, default=8765, help="Porta loopback (default: 8765)")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("Questa versione richiede Windows DPAPI")
    if not 1 <= args.port <= 65535:
        parser.error("La porta deve essere compresa tra 1 e 65535")
    root = args.data_dir or default_data_dir()
    store = Store(root)
    if args.command == "doctor":
        try:
            report = store.health()
            print(json.dumps(report, indent=2))
        finally:
            store.close()
        raise SystemExit(0 if report["ok"] else 1)
    owner_token = secrets.token_urlsafe(32)
    print(f"DataSovereign {__version__}. Dopo l'avvio apri questo URL nel browser:", flush=True)
    print(f"http://127.0.0.1:{args.port}/#access={owner_token}", flush=True)
    print(f"Vault: {root}", flush=True)
    print("Premi Ctrl+C per fermare il servizio. La chiave admin scadrà.", flush=True)
    try:
        uvicorn.run(create_app(store, owner_token), host="127.0.0.1", port=args.port, access_log=False)
    finally:
        store.close()
