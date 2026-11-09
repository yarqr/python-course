import json
from pathlib import Path
from typing import TypedDict

from cryptography.fernet import InvalidToken

from pwmanager.crypto import EntryPassword, MasterPassword, PasswordCredentials

DEFAULT_PATH = Path.home() / ".pwmanager" / "vault.json"


class StorageError(Exception):
    pass


class AlreadyInitializedError(StorageError):
    pass


class NotInitializedError(StorageError):
    pass


class FileCorruptedError(StorageError):
    pass


class MasterPasswordInvalidError(StorageError):
    pass


class EntryAlreadyExistsError(StorageError):
    pass


class EntryNotFoundError(StorageError):
    pass


class EntryData(TypedDict):
    login: str
    password: str


class JsonData(TypedDict):
    salt: str
    hash: str
    entries: dict[str, EntryData]


class PasswordManager:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DEFAULT_PATH
        self._salt: bytes = b""
        self._hash: bytes = b""
        self._entries: dict[str, EntryData] = {}
        self._key: bytes = b""

    def init_master(self, password: str) -> None:
        if self.path.exists():
            raise AlreadyInitializedError("Master password already set")
        master = MasterPassword(password)
        credentials = master.create_credentials()
        self._salt = credentials.salt
        self._hash = credentials.password_hash
        self._persist()

    def unlock(self, password: str) -> bool:
        self._load()
        master = MasterPassword(password)
        if master.compare(PasswordCredentials(self._hash, self._salt)):
            if not self._key:
                self._key = master.derive_key(self._salt)
            return True
        return False

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        if name in self.list_entries():
            raise EntryAlreadyExistsError("Entry with this name already exists")
        password = EntryPassword(unencrypted=pwd)
        self._entries[name] = {
            "login": login,
            "password": password.encrypt(self._key).hex(),
        }
        self._persist()

    def list_entries(self) -> list[str]:
        return list(self._entries.keys())

    def get_entry(self, name: str, master_password: str) -> EntryData:
        if not self.unlock(master_password):
            # исходя из тз, нужен новый параметр - master_password:
            # get_entry(name) -> login/pwd
            # get <name> — показать пароль (после подтверждения мастер-паролем)
            raise MasterPasswordInvalidError("Wrong master password")
        if name not in self.list_entries():
            raise EntryNotFoundError(f"Entry with name {name} not found")
        data = self._entries[name]
        try:
            entry_password = EntryPassword(encrypted=bytes.fromhex(data["password"]))
            return {
                "login": data["login"],
                "password": entry_password.decrypt(self._key),
            }
        except InvalidToken as e:
            raise FileCorruptedError(f"Cannot decrypt entry with name {name}") from e

    def delete_entry(self, name: str) -> None:
        if name not in self.list_entries():
            raise EntryNotFoundError("Entry with this name not found")
        self._entries.pop(name)
        self._persist()

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data: JsonData = {
            "salt": self._salt.hex(),
            "hash": self._hash.hex(),
            "entries": self._entries,
        }
        self.path.write_text(json.dumps(data))

    def _load(self) -> None:
        try:
            data: JsonData = json.loads(self.path.read_text())
            self._salt = bytes.fromhex(data["salt"])
            self._hash = bytes.fromhex(data["hash"])
            self._entries = data["entries"]
            if not isinstance(self._entries, dict):
                raise FileCorruptedError("Entries is not a dictionary")
            for entry in self._entries.values():
                if not isinstance(entry["login"], str):
                    raise FileCorruptedError("Entry login must be str")
                bytes.fromhex(entry["password"])
        except FileNotFoundError as e:
            raise NotInitializedError("First initialize the master password") from e
        except (ValueError, KeyError, TypeError) as e:
            raise FileCorruptedError("Storage file corrupted") from e
