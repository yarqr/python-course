from secrets import compare_digest

import pytest
from cryptography.fernet import Fernet, InvalidToken

from pwmanager.crypto import (
    EntryPassword,
    MasterPassword,
    SaltTag,
    generate_password,
    generate_salt,
)


@pytest.mark.parametrize("length", [-5, 0])
def test_incorrect_salt_length(length: int) -> None:
    with pytest.raises(ValueError):
        generate_salt(length)


def test_salt_generate_random() -> None:
    assert generate_salt() != generate_salt()


@pytest.mark.parametrize("length", [-5, 0])
def test_incorrect_generate_password_length(length: int) -> None:
    with pytest.raises(ValueError):
        generate_password(length)


def test_password_generate_random() -> None:
    assert generate_password() != generate_password()


@pytest.fixture
def master_password() -> MasterPassword:
    return MasterPassword("master123correct")


@pytest.fixture
def salt() -> bytes:
    return generate_salt()


def test_derive_hash(master_password: MasterPassword, salt: bytes) -> None:
    hash_ = master_password.derive_hash(salt, SaltTag.VERIFICATION)
    hash_same_salt = master_password.derive_hash(salt, SaltTag.VERIFICATION)
    assert compare_digest(hash_, hash_same_salt) is True

    hash_different_salt = master_password.derive_hash(
        generate_salt(), SaltTag.VERIFICATION
    )
    assert compare_digest(hash_, hash_different_salt) is False

    hash_different_tag = master_password.derive_hash(salt, SaltTag.ENCRYPTION)
    assert compare_digest(hash_, hash_different_tag) is False


def test_compare_with_hash(master_password: MasterPassword, salt: bytes) -> None:
    expected_hash = master_password.derive_hash(salt, SaltTag.VERIFICATION)
    assert master_password.compare_with_hash(expected_hash, salt) is True

    incorrect_hash = MasterPassword("incorrect_password")
    assert incorrect_hash.compare_with_hash(expected_hash, salt) is False


def test_derive_key(master_password: MasterPassword, salt: bytes) -> None:
    key = master_password.derive_key(salt)
    assert Fernet(key)

    key_same_salt = master_password.derive_key(salt)
    assert key == key_same_salt


@pytest.fixture
def encryption_key(master_password: MasterPassword, salt: bytes) -> bytes:
    return master_password.derive_key(salt)


def test_entry_encrypt(encryption_key: bytes) -> None:
    original = "secret"
    entry = EntryPassword(unencrypted=original)
    assert entry.encrypt(encryption_key) != original.encode()


def test_entry_decrypt(encryption_key: bytes) -> None:
    original = "secret"
    entry = EntryPassword(unencrypted=original)
    entry.encrypted = entry.encrypt(encryption_key)
    assert entry.decrypt(encryption_key) == original


def test_entry_different_encryption(encryption_key: bytes) -> None:
    entry = EntryPassword(unencrypted="secret")
    assert entry.encrypt(encryption_key) != entry.encrypt(encryption_key)


def test_entry_decrypt_wrong_key(encryption_key: bytes) -> None:
    entry = EntryPassword(unencrypted="secret")
    entry.encrypted = entry.encrypt(encryption_key)

    another_key = MasterPassword("another").derive_key(generate_salt())
    with pytest.raises(InvalidToken):
        entry.decrypt(another_key)


def test_entry_invalid_data(encryption_key: bytes) -> None:
    entry = EntryPassword(encrypted=b"invalid data")
    with pytest.raises(InvalidToken):
        entry.decrypt(encryption_key)


def test_entry_empty_values(encryption_key: bytes) -> None:
    entry = EntryPassword()
    with pytest.raises(ValueError):
        entry.encrypt(encryption_key)
    with pytest.raises(ValueError):
        entry.decrypt(encryption_key)
