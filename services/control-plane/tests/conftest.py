import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def local_settings_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in tuple(os.environ):
        if name.startswith("MATHEWS_"):
            monkeypatch.delenv(name)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MATHEWS_ENVIRONMENT", "local")
