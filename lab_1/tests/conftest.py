"""Общие фикстуры pytest."""

import pytest


@pytest.fixture(autouse=True)
def speed_up_iterations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Уменьшение количества итераций для увеличения скорости выполнения тестов."""
    monkeypatch.setattr("pwmanager.crypto.ITERATIONS", 7777)
