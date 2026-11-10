"""Тесты менеджера паролей."""

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
    """Путь к файлу хранилища во временном каталоге."""
    return tmp_path / ".pwmanager" / "vault.json"


@pytest.fixture
def manager(storage_path: Path) -> PasswordManager:
    """Менеджер для уже инициализированного хранилища."""
    pw_manager = PasswordManager(storage_path)
    pw_manager.init_master(MASTER_PASSWORD)
    return PasswordManager(storage_path)


def test_init_master_one_time_initialization(
    manager: PasswordManager, storage_path: Path
) -> None:
    """Повторная инициализация хранилища запрещена.

    Необходимый из ТЗ тест №2.
    """
    original = storage_path.read_text()
    with pytest.raises(AlreadyInitializedError):
        manager.init_master(MASTER_PASSWORD)
    assert storage_path.read_text() == original


def test_init_master_correct(manager: PasswordManager, storage_path: Path) -> None:
    """После инициализации файл содержит соль и хэш."""
    assert storage_path.exists()

    data = json.loads(storage_path.read_text())
    assert data["salt"]
    assert data["hash"]


def test_unlock_correct(manager: PasswordManager) -> None:
    """Верный мастер-пароль открывает хранилище, неверный — нет.

    Необходимый из ТЗ тест №1.
    """
    assert manager.unlock(MASTER_PASSWORD)
    assert not manager.unlock(INCORRECT_MASTER_PASSWORD)


@pytest.fixture
def unlocked_manager(manager: PasswordManager) -> PasswordManager:
    """Менеджер, для которого выполнен unlock."""
    manager.unlock(MASTER_PASSWORD)
    return manager


def test_chain_add_list_get(unlocked_manager: PasswordManager) -> None:
    """Добавленная запись видна в списке и читается с мастер-паролем.

    Необходимый из ТЗ тест №3.
    """
    unlocked_manager.unlock(MASTER_PASSWORD)
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    assert ENTRY_NAME in unlocked_manager.list_entries()
    assert unlocked_manager.get_entry(ENTRY_NAME, MASTER_PASSWORD) == {
        "login": ENTRY_LOGIN,
        "password": ENTRY_PASSWORD,
    }


def test_add_entry_same_name(unlocked_manager: PasswordManager) -> None:
    """Запись с повторяющимся названием не добавляется."""
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    with pytest.raises(EntryAlreadyExistsError):
        unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)


def test_get_entry_with_incorrect_master_password(manager: PasswordManager) -> None:
    """Получение записи с неверным мастер-паролем запрещено."""
    with pytest.raises(MasterPasswordInvalidError):
        manager.get_entry(ENTRY_NAME, INCORRECT_MASTER_PASSWORD)


def test_get_entry_incorrect_name(unlocked_manager: PasswordManager) -> None:
    """Получение несуществующей записи вызывает ошибку."""
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    with pytest.raises(EntryNotFoundError):
        unlocked_manager.get_entry(INCORRECT_ENTRY_NAME, MASTER_PASSWORD)


def test_get_entry_incorrect_password_token(
    unlocked_manager: PasswordManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Не расшифровываемый пароль записи считается повреждением файла."""
    monkeypatch.setattr(EntryPassword, "encrypt", lambda self, key: b"invalid_token")
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)

    with pytest.raises(FileCorruptedError):
        unlocked_manager.get_entry(ENTRY_NAME, MASTER_PASSWORD)


def test_delete_unknown_entry(unlocked_manager: PasswordManager) -> None:
    """Удаление несуществующей записи вызывает ошибку."""
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    with pytest.raises(EntryNotFoundError):
        unlocked_manager.delete_entry(INCORRECT_ENTRY_NAME)


def test_delete_entry_correct(unlocked_manager: PasswordManager) -> None:
    """Удалённая запись пропадает из списка.

    Необходимый из ТЗ тест №4.
    """
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    assert ENTRY_NAME in unlocked_manager.list_entries()

    unlocked_manager.delete_entry(ENTRY_NAME)
    assert ENTRY_NAME not in unlocked_manager.list_entries()


def test_persist_correct(unlocked_manager: PasswordManager, storage_path: Path) -> None:
    """Записи сохраняются и читаются новым экземпляром менеджера."""
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)

    restarted_manager = PasswordManager(storage_path)
    restarted_manager.unlock(MASTER_PASSWORD)
    assert restarted_manager.get_entry(ENTRY_NAME, MASTER_PASSWORD) == {
        "login": ENTRY_LOGIN,
        "password": ENTRY_PASSWORD,
    }


def test_load_without_initialization(storage_path: Path) -> None:
    """Вход без инициализации вызывает NotInitializedError."""
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
    """Повреждённый файл хранилища вызывает FileCorruptedError."""
    storage_path.write_text(content)

    with pytest.raises(FileCorruptedError):
        manager.unlock(MASTER_PASSWORD)


def test_passwords_not_stored_raw_in_file(
    unlocked_manager: PasswordManager, storage_path: Path
) -> None:
    """Мастер-пароль и пароль записи не хранятся в файле открыто.

    Необходимый из ТЗ тест №5.
    """
    unlocked_manager.add_entry(ENTRY_NAME, ENTRY_LOGIN, ENTRY_PASSWORD)
    raw = storage_path.read_text()
    assert MASTER_PASSWORD not in raw
    assert MASTER_PASSWORD.encode().hex() not in raw
    assert ENTRY_PASSWORD not in raw
    assert ENTRY_PASSWORD.encode().hex() not in raw
