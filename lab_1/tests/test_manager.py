import json
from pathlib import Path

import pytest

from pwmanager.crypto import MINIMAL_SALT_LENGTH, EntryPassword
from pwmanager.manager import (
    AlreadyInitializedError,
    EntryAlreadyExistsError,
    EntryNotFoundError,
    FileCorruptedError,
    MasterPasswordInvalidError,
    NotInitializedError,
    PasswordManager,
)

MASTER_PASSWORD = "master_password_777"  # noqa: S105
INCORRECT_MASTER_PASSWORD = "incorrect_password_master_777"  # noqa: S105
ENTRY_NAME = "entry_name_777"
INCORRECT_ENTRY_NAME = "incorrect_name_entry_777"
ENTRY_LOGIN = "entry_login_777"
ENTRY_PASSWORD = "entry_password_777"  # noqa: S105
SALT_AND_HASH = f'{{"salt": "{"00" * MINIMAL_SALT_LENGTH}", "hash": "00", '


@pytest.fixture
def storage_path(tmp_path: Path) -> Path:
    return tmp_path / ".pwmanager" / "vault.json"


@pytest.fixture
def manager(storage_path: Path) -> PasswordManager:
    pw_manager = PasswordManager(storage_path)
    pw_manager.init_master(MASTER_PASSWORD)
    return PasswordManager(storage_path)


def test_init_master_one_time_initialization(manager: PasswordManager) -> None:
    # necessary test: 2
    with pytest.raises(AlreadyInitializedError):
        manager.init_master(MASTER_PASSWORD)


def test_init_master_correct(manager: PasswordManager, storage_path: Path) -> None:
    assert storage_path.exists()

    data = json.loads(storage_path.read_text())
    assert data["salt"]
    assert data["hash"]


# TODO: test load


def test_unlock_correct(manager: PasswordManager) -> None:
    # necessary test: 1
    assert manager.unlock(MASTER_PASSWORD)
    assert not manager.unlock(INCORRECT_MASTER_PASSWORD)


@pytest.fixture
def unlocked_manager(manager: PasswordManager) -> PasswordManager:
    manager.unlock(MASTER_PASSWORD)
    return manager


def test_chain_add_list_get(unlocked_manager: PasswordManager) -> None:
    # necessary test: 3
    unlocked_manager.unlock(MASTER_PASSWORD)
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    assert ENTRY_NAME in unlocked_manager.list_entries()
    assert unlocked_manager.get_entry(ENTRY_NAME, MASTER_PASSWORD) == {
        "login": ENTRY_LOGIN,
        "password": ENTRY_PASSWORD,
    }


def test_add_entry_same_name(unlocked_manager: PasswordManager) -> None:
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    with pytest.raises(EntryAlreadyExistsError):
        unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)


def test_get_entry_with_incorrect_master_password(manager: PasswordManager) -> None:
    with pytest.raises(MasterPasswordInvalidError):
        manager.get_entry(ENTRY_NAME, INCORRECT_MASTER_PASSWORD)


def test_get_entry_incorrect_name(unlocked_manager: PasswordManager) -> None:
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    with pytest.raises(EntryNotFoundError):
        unlocked_manager.get_entry(INCORRECT_ENTRY_NAME, MASTER_PASSWORD)


def test_get_entry_incorrect_password_token(
    unlocked_manager: PasswordManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(EntryPassword, "encrypt", lambda self, key: b"invalid_token")
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)

    with pytest.raises(FileCorruptedError):
        unlocked_manager.get_entry(ENTRY_NAME, MASTER_PASSWORD)


def test_delete_unknown_entry(unlocked_manager: PasswordManager) -> None:
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    with pytest.raises(EntryNotFoundError):
        unlocked_manager.delete_entry(INCORRECT_ENTRY_NAME)


def test_delete_entry_correct(unlocked_manager: PasswordManager) -> None:
    # necessary test: 4
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    assert ENTRY_NAME in unlocked_manager.list_entries()

    unlocked_manager.delete_entry(ENTRY_NAME)
    assert ENTRY_NAME not in unlocked_manager.list_entries()


def test_persist_correct(unlocked_manager: PasswordManager, storage_path: Path) -> None:
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)

    restarted_manager = PasswordManager(storage_path)
    restarted_manager.unlock(MASTER_PASSWORD)
    assert restarted_manager.get_entry(ENTRY_NAME, MASTER_PASSWORD) == {
        "login": ENTRY_LOGIN,
        "password": ENTRY_PASSWORD,
    }


def test_load_without_initialization(storage_path: Path) -> None:
    with pytest.raises(NotInitializedError):
        PasswordManager(storage_path).unlock(MASTER_PASSWORD)


@pytest.mark.parametrize(
    "content",
    [
        "no json",
        "{}",
        '{"hash": "00", "entries": {}}',
        '{"salt": "00", "entries": {}}',
        '{"salt": "00", "hash": "00"}',
        '{"salt": "i", "hash": "00", "entries": {}}',
        '{"salt": "00", "hash": "i", "entries": {}}',
        '{"salt": 0, "hash": "00", "entries": {}}',
        '{"salt": "00", "hash": 0, "entries": {}}',
        SALT_AND_HASH + '"entries": []}',
        SALT_AND_HASH + '"entries": {"name": {"l": "1", "password": "00"}}}',
        SALT_AND_HASH + '"entries": {"name": {"login": "1", "p": "00"}}}',
        SALT_AND_HASH + '"entries": {"name": {"login": "1"}}}',
        SALT_AND_HASH + '"entries": {"name": {"password": "00"}}}',
        SALT_AND_HASH + '"entries": {"name": {"login": 1, "password": "00"}}}',
        SALT_AND_HASH + '"entries": {"name": {"login": "1", "password": 0}}}',
        SALT_AND_HASH + '"entries": {"name": {"login": "1", "password": "i"}}}',
    ],
)
def test_load_corrupted_file(
    manager: PasswordManager, storage_path: Path, content: str
) -> None:
    storage_path.write_text(content)

    with pytest.raises(FileCorruptedError):
        manager.unlock(MASTER_PASSWORD)


def test_passwords_not_stored_raw_in_file(
    unlocked_manager: PasswordManager, storage_path: Path
) -> None:
    # necessary test: 5
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    raw = storage_path.read_text()
    assert MASTER_PASSWORD not in raw
    assert MASTER_PASSWORD.encode().hex() not in raw
    assert ENTRY_PASSWORD not in raw
    assert ENTRY_PASSWORD.encode().hex() not in raw
