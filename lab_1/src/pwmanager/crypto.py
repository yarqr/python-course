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
    if length < MINIMAL_SALT_LENGTH:
        raise ValueError(f"Length must be at least {MINIMAL_SALT_LENGTH}")
    return secrets.token_bytes(length)


def generate_password(length: int = 16) -> str:
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
    VERIFICATION = "verification"
    ENCRYPTION = "encryption"


@dataclass(frozen=True)
class PasswordCredentials:
    password_hash: bytes
    salt: bytes


@dataclass(frozen=True)
class MasterPassword:
    original_value: str

    def __post_init__(self) -> None:
        if not self.original_value:
            raise ValueError("Master password cannot be empty")

    def _derive_hash(self, salt: bytes, salt_tag: SaltTag) -> bytes:
        if len(salt) < MINIMAL_SALT_LENGTH:
            raise ValueError(f"Salt length must be at least {MINIMAL_SALT_LENGTH}")
        return hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            self.original_value.encode(),
            salt + salt_tag.value.encode(),
            ITERATIONS,
        )

    def create_credentials(self, salt: bytes | None = None) -> PasswordCredentials:
        if salt is None:
            salt = generate_salt()
        return PasswordCredentials(self._derive_hash(salt, SaltTag.VERIFICATION), salt)

    def compare(self, credentials: PasswordCredentials) -> bool:
        return secrets.compare_digest(
            self._derive_hash(credentials.salt, SaltTag.VERIFICATION),
            credentials.password_hash,
        )

    def derive_key(self, salt: bytes) -> bytes:
        return base64.urlsafe_b64encode(self._derive_hash(salt, SaltTag.ENCRYPTION))


@dataclass(frozen=True, kw_only=True)
class EntryPassword:
    unencrypted: str | None = None
    encrypted: bytes | None = None

    def __post_init__(self) -> None:
        if (self.encrypted is None) == (self.unencrypted is None):
            raise ValueError("Only one argument can be specified")

    def encrypt(self, encryption_key: bytes) -> bytes:
        if self.unencrypted is None:
            raise ValueError("Unencrypted value not specified")
        return Fernet(encryption_key).encrypt(self.unencrypted.encode())

    def decrypt(self, encryption_key: bytes) -> str:
        if self.encrypted is None:
            raise ValueError("Encrypted value not specified")
        return Fernet(encryption_key).decrypt(self.encrypted).decode()
