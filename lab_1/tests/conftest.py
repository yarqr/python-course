import pytest


@pytest.fixture(autouse=True)
def speed_up_iterations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pwmanager.crypto.ITERATIONS", 7777)
