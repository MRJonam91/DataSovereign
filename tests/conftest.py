import uuid
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path():
    # Windows sandbox users cannot reopen pytest's mode-0700 temporary folders.
    root = Path(__file__).resolve().parents[1] / ".tmp"
    root.mkdir(exist_ok=True)
    folder = root / f"case-{uuid.uuid4()}"
    folder.mkdir()
    return folder
