"""Криптографическая основа менеджера паролей."""

import base64
import hashlib
import secrets
import string
from dataclasses import dataclass
from enum import Enum

from cryptography.fernet import Fernet

ITERATIONS = 777_000
MINIMAL_SALT_LENGTH = 16
HASH_ALGORITHM = "sha256"


def generate_salt(length: int = MINIMAL_SALT_LENGTH) -> bytes:
    """Генерация криптографически стойкой случайной соли."""
    if length < MINIMAL_SALT_LENGTH:
        raise ValueError(f"Length must be at least {MINIMAL_SALT_LENGTH}")
    return secrets.token_bytes(length)


def generate_password(length: int = 16) -> str:
    """Генерация надёжного пароля."""
    sets = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation,
    ]
    alphabet = "".join(sets)
    minimal_length = len(sets)
    if length < minimal_length:
        raise ValueError(f"Length must be at least {minimal_length}")
    while True:
        password = [secrets.choice(alphabet) for _ in range(length)]
        if all(any(c in s for c in password) for s in sets):
            return "".join(password)


class SaltTag(Enum):
    """Типы назначения соли."""

    VERIFICATION = "verification"
    ENCRYPTION = "encryption"


@dataclass(frozen=True)
class PasswordCredentials:
    """Проверочные данные пароля."""

    password_hash: bytes
    salt: bytes


@dataclass(frozen=True, repr=False)
class MasterPassword:
    """Мастер-пароль и операции с ним."""

    original_value: str

    def __post_init__(self) -> None:
        """Проверка мастер-пароля."""
        if not self.original_value:
            raise ValueError("Master password cannot be empty")

    def _derive_hash(self, salt: bytes, salt_tag: SaltTag) -> bytes:
        """Хэширование мастер-пароля."""
        if len(salt) < MINIMAL_SALT_LENGTH:
            raise ValueError(f"Salt length must be at least {MINIMAL_SALT_LENGTH}")
        return hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            self.original_value.encode(),
            salt + salt_tag.value.encode(),
            ITERATIONS,
        )

    def create_credentials(self, salt: bytes | None = None) -> PasswordCredentials:
        """Создание проверочных данных мастер-пароля."""
        if salt is None:
            salt = generate_salt()
        return PasswordCredentials(self._derive_hash(salt, SaltTag.VERIFICATION), salt)

    def compare(self, credentials: PasswordCredentials) -> bool:
        """Проверка мастер-пароля при помощи проверочных данных."""
        return secrets.compare_digest(
            self._derive_hash(credentials.salt, SaltTag.VERIFICATION),
            credentials.password_hash,
        )

    def derive_key(self, salt: bytes) -> bytes:
        """Получение ключа шифрования для Fernet."""
        return base64.urlsafe_b64encode(self._derive_hash(salt, SaltTag.ENCRYPTION))


@dataclass(frozen=True, repr=False, kw_only=True)
class EntryPassword:
    """Пароль записи в одном из видов."""

    unencrypted: str | None = None
    encrypted: bytes | None = None

    def __post_init__(self) -> None:
        """Проверка пароля записи."""
        if (self.encrypted is None) == (self.unencrypted is None):
            raise ValueError("Exactly one of arguments must be specified")

    def encrypt(self, encryption_key: bytes) -> bytes:
        """Шифрование пароля при помощи Fernet."""
        if self.unencrypted is None:
            raise ValueError("Unencrypted value not specified")
        return Fernet(encryption_key).encrypt(self.unencrypted.encode())

    def decrypt(self, encryption_key: bytes) -> str:
        """Расшифровка пароля при помощи Fernet."""
        if self.encrypted is None:
            raise ValueError("Encrypted value not specified")
        return Fernet(encryption_key).decrypt(self.encrypted).decode()
