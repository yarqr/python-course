import argparse
from getpass import getpass

from pwmanager.crypto import generate_password
from pwmanager.manager import (
    AlreadyInitializedError,
    EntryAlreadyExistsError,
    EntryNotFoundError,
    FileCorruptedError,
    MasterPasswordInvalidError,
    NotInitializedError,
    PasswordManager,
)

EXIT_OK = 0
EXIT_FAIL = 1

MP_INPUT_TEXT = "Введите мастер-пароль: "
MP_CREATE_INPUT_TEXT = "Придумайте мастер-пароль: "
MP_CONFIRM_INPUT_TEXT = "Подтвердите мастер-пароль: "
COMMAND_INPUT_TEXT = "Введите команду: "
ENTRY_NAME_INPUT_TEXT = "Введите название записи: "
ENTRY_LOGIN_INPUT_TEXT = "Введите логин: "
ENTRY_PASSWORD_INPUT_TEXT = "Введите пароль: "  # noqa: S105

COMMAND_MENU_TEXT = """
=== МЕНЕДЖЕР ПАРОЛЕЙ ===
add - добавить запись
list - показать названия записей
get - найти и показать запись
delete - удалить запись
exit - выйти из менеджера
========================\
"""
STORAGE_INIT_SUCCESS_TEXT = "Хранилище успешно инициализировано"
UNKNOWN_COMMAND_TEXT = "Неизвестная команда, попробуйте заново"
SECURE_PASSWORD_TEXT = "Надёжный пароль: {}"  # noqa: S105
MANAGER_EXIT_SUCCESS_TEXT = "Вы успешно вышли из менеджера паролей"
LIST_ENTRIES_EMPTY_TEXT = "Список записей пуст"
LIST_ENTRIES_INTRO_TEXT = "Список записей:"
ENTRY_NAME_TEXT = "• '{}'"
ENTRY_ADD_SUCCESS_TEXT = "Запись успешно добавлена"
ENTRY_DELETE_SUCCESS_TEXT = "Запись успешно удалена"
ENTRY_GET_TEXT = "Название: {}\n• Логин: {}\n• Пароль: {}"

MP_EMPTY_ERR_TEXT = "Ошибка: мастер-пароль не может быть пустым"
MP_NOT_CONFIRMED_ERR_TEXT = "Ошибка: мастер-пароль должен быть подтверждён"
MPS_NOT_SAME_ERR_TEXT = "Ошибка: мастер-пароли не совпадают, запустите --init ещё раз"
STORAGE_ALREADY_INIT_ERR_TEXT = "Ошибка: хранилище уже было инициализировано"
STORAGE_NOT_INIT_ERR_TEXT = "Ошибка: хранилище не создано, запустите --init сначала"
STORAGE_CORRUPTED_ERR_TEXT = "Ошибка: файл хранилища повреждён"
MP_NOT_CORRECT_ERR_TEXT = "Ошибка: неправильный мастер-пароль"
LEN_ONLY_GEN_ERR_TEXT = "Ошибка: --length можно использовать только вместе с --generate"
ENTRY_NAME_EMPTY_ERR_TEXT = "Ошибка: название записи не должно быть пустым"
ENTRY_LOGIN_EMPTY_ERR_TEXT = "Ошибка: логин не должен быть пустым"
ENTRY_PASSWORD_EMPTY_ERR_TEXT = "Ошибка: пароль не должен быть пустым"  # noqa: S105
ENTRY_ALREADY_EXISTS_ERR_TEXT = "Ошибка: запись с таким названием уже существует"
ENTRY_NOT_FOUND_ERR_TEXT = "Ошибка: записи с таким названием не существует"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser("PasswordManager")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--init", action="store_true")
    group.add_argument("--unlock", action="store_true")
    group.add_argument("--generate", action="store_true")

    parser.add_argument("--length", type=int, default=None)

    return parser


class PasswordService:
    def __init__(self, manager: PasswordManager) -> None:
        self.manager = manager

    def add(self) -> None:
        name = input(ENTRY_NAME_INPUT_TEXT).strip()
        if not name:
            print(ENTRY_NAME_EMPTY_ERR_TEXT)
            return
        login = input(ENTRY_LOGIN_INPUT_TEXT).strip()
        if not login:
            print(ENTRY_LOGIN_EMPTY_ERR_TEXT)
            return
        password = getpass(ENTRY_PASSWORD_INPUT_TEXT)
        if not password:
            print(ENTRY_PASSWORD_EMPTY_ERR_TEXT)
            return

        try:
            self.manager.add_entry(name, login, password)
            print(ENTRY_ADD_SUCCESS_TEXT)
        except EntryAlreadyExistsError:
            print(ENTRY_ALREADY_EXISTS_ERR_TEXT)

    def list(self) -> None:
        data = self.manager.list_entries()
        if not data:
            print(LIST_ENTRIES_EMPTY_TEXT)
        else:
            print(LIST_ENTRIES_INTRO_TEXT)
            for name in data:
                print(ENTRY_NAME_TEXT.format(name))

    def get(self) -> None:
        name = input(ENTRY_NAME_INPUT_TEXT).strip()
        if not name:
            print(ENTRY_NAME_EMPTY_ERR_TEXT)
            return

        pw = getpass(MP_INPUT_TEXT)
        if not pw:
            print(MP_EMPTY_ERR_TEXT)
            return
        try:
            entry = self.manager.get_entry(name, pw)
            print(ENTRY_GET_TEXT.format(name, entry["login"], entry["password"]))
        except MasterPasswordInvalidError:
            print(MP_NOT_CORRECT_ERR_TEXT)
        except EntryNotFoundError:
            print(ENTRY_NOT_FOUND_ERR_TEXT)

    def delete(self) -> None:
        name = input(ENTRY_NAME_INPUT_TEXT).strip()
        if not name:
            print(ENTRY_NAME_EMPTY_ERR_TEXT)
            return

        try:
            self.manager.delete_entry(name)
            print(ENTRY_DELETE_SUCCESS_TEXT)
        except EntryNotFoundError:
            print(ENTRY_NOT_FOUND_ERR_TEXT)


class StorageService:
    def __init__(self, manager: PasswordManager) -> None:
        self.manager = manager

    def init(self) -> int:
        pw = getpass(MP_CREATE_INPUT_TEXT)
        pw_confirm = getpass(MP_CONFIRM_INPUT_TEXT)
        if not pw:
            print(MP_EMPTY_ERR_TEXT)
            return EXIT_FAIL
        if not pw_confirm:
            print(MP_NOT_CONFIRMED_ERR_TEXT)
            return EXIT_FAIL
        if pw != pw_confirm:
            print(MPS_NOT_SAME_ERR_TEXT)
            return EXIT_FAIL

        try:
            self.manager.init_master(pw)
            print(STORAGE_INIT_SUCCESS_TEXT)
            return EXIT_OK
        except AlreadyInitializedError:
            print(STORAGE_ALREADY_INIT_ERR_TEXT)
            return EXIT_FAIL

    def unlock(self) -> int:
        pw = getpass(MP_INPUT_TEXT)
        if not pw:
            print(MP_EMPTY_ERR_TEXT)
            return EXIT_FAIL
        if not self.manager.unlock(pw):
            print(MP_NOT_CORRECT_ERR_TEXT)
            return EXIT_FAIL

        password_service = PasswordService(self.manager)
        while True:
            print(COMMAND_MENU_TEXT)
            command = input(COMMAND_INPUT_TEXT)
            match command:
                case "add":
                    password_service.add()
                case "list":
                    password_service.list()
                case "get":
                    password_service.get()
                case "delete":
                    password_service.delete()
                case "exit":
                    print(MANAGER_EXIT_SUCCESS_TEXT)
                    return EXIT_OK
                case _:
                    print(UNKNOWN_COMMAND_TEXT)

    @staticmethod
    def generate(length: int | None) -> int:
        if length is None:
            password = generate_password()
        else:
            try:
                password = generate_password(length)
            except ValueError as e:
                print(f"Ошибка при создании пароля: {e}")
                return EXIT_FAIL

        print(SECURE_PASSWORD_TEXT.format(password))
        return EXIT_OK


def run() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.generate and args.length is not None:
        print(LEN_ONLY_GEN_ERR_TEXT)
        return EXIT_FAIL

    manager = PasswordManager()
    service = StorageService(manager)
    try:
        if args.init:
            return service.init()
        if args.unlock:
            return service.unlock()
        if args.generate:
            return service.generate(args.length)
    except NotInitializedError:
        print(STORAGE_NOT_INIT_ERR_TEXT)
    except FileCorruptedError:
        print(STORAGE_CORRUPTED_ERR_TEXT)
    return EXIT_FAIL


def main() -> int:
    try:
        return run()
    except KeyboardInterrupt:
        print(MANAGER_EXIT_SUCCESS_TEXT)
        return EXIT_FAIL
