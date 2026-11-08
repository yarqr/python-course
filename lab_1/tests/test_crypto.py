from secrets import compare_digest

import pytest
from cryptography.fernet import Fernet, InvalidToken

from pwmanager.crypto import (
    MINIMAL_SALT_LENGTH,
    EntryPassword,
    MasterPassword,
    PasswordCredentials,
    generate_password,
    generate_salt,
)


@pytest.mark.parametrize("length", [-777, 0, MINIMAL_SALT_LENGTH - 1])
def test_incorrect_salt_length(length: int) -> None:
    with pytest.raises(ValueError):
        generate_salt(length)


def test_salt_generate_random() -> None:
    assert generate_salt() != generate_salt()


@pytest.mark.parametrize("length", [-777, 0])
def test_incorrect_generate_password_length(length: int) -> None:
    with pytest.raises(ValueError):
        generate_password(length)


@pytest.mark.parametrize("length", [100, 777])
def test_generate_password_length(length: int) -> None:
    assert len(generate_password(length)) == length


def test_password_generate_random_password() -> None:
    assert generate_password() != generate_password()


def test_empty_master_password() -> None:
    with pytest.raises(ValueError):
        MasterPassword("")


@pytest.fixture
def master_password() -> MasterPassword:
    return MasterPassword("master123correct")


@pytest.fixture
def salt() -> bytes:
    return generate_salt()


def test_create_credentials(master_password: MasterPassword, salt: bytes) -> None:
    credentials = master_password.create_credentials(salt)
    assert credentials.salt == salt

    same_credentials = master_password.create_credentials(salt)
    assert compare_digest(credentials.password_hash, same_credentials.password_hash)

    different_credentials = master_password.create_credentials(generate_salt())
    assert not compare_digest(
        credentials.password_hash, different_credentials.password_hash
    )


def test_compare(master_password: MasterPassword, salt: bytes) -> None:
    credentials = master_password.create_credentials(salt)
    assert master_password.compare(credentials)

    incorrect_password = MasterPassword("incorrect_password")
    assert not incorrect_password.compare(credentials)


def test_derive_key(master_password: MasterPassword, salt: bytes) -> None:
    key = master_password.derive_key(salt)
    assert Fernet(key)

    key_same_salt = master_password.derive_key(salt)
    assert key == key_same_salt

    key_another_salt = master_password.derive_key(generate_salt())
    assert key != key_another_salt


def test_short_salt(master_password: MasterPassword) -> None:
    short_salt = b"q" * (MINIMAL_SALT_LENGTH - 1)
    with pytest.raises(ValueError):
        master_password.create_credentials(short_salt)
    with pytest.raises(ValueError):
        master_password.compare(PasswordCredentials(b"test_hash", short_salt))
    with pytest.raises(ValueError):
        master_password.derive_key(short_salt)


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
    encrypted_entry = EntryPassword(encrypted=entry.encrypt(encryption_key))
    assert encrypted_entry.decrypt(encryption_key) == original


def test_entry_different_encryption(encryption_key: bytes) -> None:
    entry = EntryPassword(unencrypted="secret")
    assert entry.encrypt(encryption_key) != entry.encrypt(encryption_key)


def test_entry_decrypt_wrong_key(encryption_key: bytes) -> None:
    entry = EntryPassword(unencrypted="secret")
    encrypted_entry = EntryPassword(encrypted=entry.encrypt(encryption_key))

    another_key = MasterPassword("another").derive_key(generate_salt())
    with pytest.raises(InvalidToken):
        encrypted_entry.decrypt(another_key)


def test_entry_invalid_data(encryption_key: bytes) -> None:
    entry = EntryPassword(encrypted=b"invalid data")
    with pytest.raises(InvalidToken):
        entry.decrypt(encryption_key)


def test_entry_empty_values() -> None:
    with pytest.raises(ValueError):
        EntryPassword()


def test_entry_both_values() -> None:
    with pytest.raises(ValueError):
        EntryPassword(unencrypted="secret", encrypted=b"encrypted_secret")


def test_entry_encrypt_without_value(encryption_key: bytes) -> None:
    with pytest.raises(ValueError):
        EntryPassword(encrypted=b"other_value_specified").encrypt(encryption_key)


def test_entry_decrypt_without_value(encryption_key: bytes) -> None:
    with pytest.raises(ValueError):
        EntryPassword(unencrypted="other_value_specified").decrypt(encryption_key)
