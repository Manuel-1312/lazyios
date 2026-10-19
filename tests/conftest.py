import pytest


@pytest.fixture(autouse=True)
def _color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
