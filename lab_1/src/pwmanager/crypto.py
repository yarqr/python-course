import base64
import hashlib
import secrets
import string
from dataclasses import dataclass
from enum import Enum

from cryptography.fernet import Fernet

ITERATIONS = 777_000
HASH_ALGORITHM = "sha256"


def generate_salt(length: int = 16) -> bytes:
    if length <= 0:
        raise ValueError("Length must be greater than 0")
    return secrets.token_bytes(length)


def generate_password(length: int = 16) -> str:
    if length <= 0:
        raise ValueError("Length must be greater than 0")
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


class SaltTag(Enum):
    VERIFICATION = "verification"
    ENCRYPTION = "encryption"


@dataclass
class MasterPassword:
    original_value: str

    def derive_hash(
        self, salt: bytes, salt_tag: SaltTag, iterations: int = ITERATIONS
    ) -> bytes:
        return hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            self.original_value.encode(),
            salt + salt_tag.value.encode(),
            iterations,
        )

    def compare_with_hash(
        self, expected_hash: bytes, salt: bytes, iterations: int = ITERATIONS
    ) -> bool:
        return secrets.compare_digest(
            self.derive_hash(salt, SaltTag.VERIFICATION, iterations), expected_hash
        )

    def derive_key(self, salt: bytes, iterations: int = ITERATIONS) -> bytes:
        return base64.urlsafe_b64encode(
            self.derive_hash(salt, SaltTag.ENCRYPTION, iterations)
        )


@dataclass(kw_only=True)
class Entry:
    unencrypted: str | None = None
    encrypted: bytes | None = None

    def encrypt(self, encryption_key: bytes) -> bytes:
        if self.unencrypted is None:
            raise ValueError("Unencrypted value not specified")
        return Fernet(encryption_key).encrypt(self.unencrypted.encode())

    def decrypt(self, encryption_key: bytes) -> str:
        if self.encrypted is None:
            raise ValueError("Encrypted value not specified")
        return Fernet(encryption_key).decrypt(self.encrypted).decode()
