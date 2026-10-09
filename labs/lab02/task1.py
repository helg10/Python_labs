import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from hashlib import pbkdf2_hmac


class PasswordNone(Exception):
    """Не вказано пароль або ж він коротший за 8 символів"""


class User:
    # дані (користувач, емейл) не мають бути пустими
    __username: str
    __email: str
    role: str
    active: bool
    __password_hash: str
    __password_salt: str
    # regex = /^[A-Za-z][0-9A-Za-z_]{2,63}@([A-Za-z]+\.)+[A-Za-z]+$

    def __init__(self, username: str, email: str, role: str):
        self.username = (
            username  # викликає сетер, тож справжня назва атрибуту -- __username
        )
        self.email = email  # викликає сетер, тож справжня назва атрибуту -- __email
        self.role = role
        self.active = True
        self.__password_hash = None
        self.__password_salt = None

    # гетер та сетер для username:
    @property
    def username(self):
        return self.__username

    @username.setter
    def username(self, value: str):
        if value and type(value) == str:
            self.__username = value
        else:
            raise ValueError("Ім'я користувача не може бути порожнім стрінгом")

    # гетер та сетер для email:
    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, value):
        if type(value) == str and re.fullmatch(
            r"^[A-Za-z][0-9A-Za-z_]{2,63}@([A-Za-z]+\.)+[A-Za-z]+$", value
        ):
            self.__email = value
        else:
            raise ValueError("Email не відповідає формату. Введіть правильне значення.")

    def set_password(self, password: str):
        if not len(password) >= 8:
            raise PasswordNone(
                "Пароль занадто короткий (менше 8 символів)"
            )  # а в main() цю помилку перехоплювати
        passwd_byted = password.encode(
            "utf-8"
        )  # перетворення в байти з кодуванням в utf8
        salt = os.urandom(16)
        passwd_hash = pbkdf2_hmac(
            "sha256", passwd_byted, salt, iterations=777777
        )  # рекомендована к-сть ітерацій для sha-256 -- понад 600тис.
        # Зберігання атрибутів з сіллю та паролем відповідно
        self.__password_salt = salt
        self.__password_hash = passwd_hash

    def check_password(self, password: str) -> bool:
        if not self.__password_hash:
            raise PasswordNone("Пароль не ініціалізовано")
        passwd_byted = password.encode("utf-8")
        passwd_hash = pbkdf2_hmac(
            "sha256", passwd_byted, self.__password_salt, iterations=777777
        )
        return self.__password_hash == passwd_hash

    def deactivate(self):
        self.active = False


class Admin(User):
    permissions: set[str]

    def __init__(
        self, username: str, email: str, role: str, permissions: set[str] | None = None
    ):
        super().__init__(username, email, role)

        if permissions is None:
            self.permissions = set()
        else:
            self.permissions = set(permissions)

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        # на відміну від remove, не викличе помилки, якщо дозволу немає в множині
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self):
        rights = ", ".join(self.permissions) if self.permissions else "жодних"
        return f"Користувач {self.username} має дозволи: {rights}"


class Session:
    ip: str
    login_time: datetime
    last_activity: datetime

    def __init__(self, ip: str):
        self.ip = ip
        # час реєстрації
        datetime_obj = datetime.now(UTC)
        self.login_time = datetime_obj
        self.last_activity = datetime_obj

    def touch(self):
        self.last_activity = datetime.now(UTC)

    def is_active(self, timeout_sec: int) -> bool:
        return datetime.now(UTC) - self.last_activity <= timedelta(seconds=timeout_sec)


class AuditingAction(Enum):  # Незмінюваний об'єкт
    USER_CREATED = "user_created"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    DEACTIVATE = "deactivate"
    LOGOUT = "logout"


@dataclass
class AuditLogEntry:
    time: datetime
    username: str
    action: AuditingAction


class AuditLog:
    actions: list

    def __init__(self):
        self.actions: list[AuditLogEntry] = []

    def add_log(self, username, action: AuditingAction):
        log = AuditLogEntry(datetime.now(UTC), username, action)
        self.actions.append(log)

    def show_all(self):
        print("ВИВІД ВМІСТУ ЖУРНАЛУ ПОДІЙ:".center(50, "~"))
        for action in self.actions:
            print(
                f"Time: {action.time}, user: {action.username}, action: {action.action.value}"
            )
        print("".center(50, "~"))


class UserAccount:  # Об'єднайте User , Session та AuditLog
    SESSION_TIMEOUT_SEC = 900
    user: User
    session: Session
    journal: AuditLog

    def __init__(self, user: User):
        self.user = user
        self.journal = AuditLog()

    def login(self, username, password, ip):
        authenticated = (
            self.user.username == username
            and self.user.active
            and self.user.check_password(password)
        )

        if authenticated:
            self.session = Session(ip)
            self.session.touch()
            self.journal.add_log(username, AuditingAction.LOGIN_SUCCESS)
            return True
        else:
            self.journal.add_log(self.user.username, AuditingAction.LOGIN_FAILURE)
            return False

    def is_authenticated(self) -> bool:
        return self.session and self.session.is_active(self.SESSION_TIMEOUT_SEC)

    def logout(self):
        if self.session:  # !!!
            self.session = None
            self.journal.add_log(self.user.username, AuditingAction.LOGOUT)

    def __getitem__(self, key):
        match key:
            case "username":
                return self.user.username
            case "email":
                return self.user.email
            case "role":
                return self.user.role
            case "active":
                return self.user.active

            case "permissions":
                if not isinstance(self.user, Admin):
                    raise KeyError("Incorrect key. User is not admin")
                return self.user.permissions

            case "login_time":
                if not self.session:  # !!!
                    raise KeyError("Incorrect key. There's no active session")
                return self.session.login_time

            case "last_activity":
                if not self.session:  # !!!
                    raise KeyError("Incorrect key. There's no active session")
                return self.session.last_activity

            case "ip":
                if not self.session:  # !!!
                    raise KeyError("Incorrect key. There's no active session")
                return self.session.ip

            case _:
                raise KeyError("Incorrect key.")

    def __setitem__(self, key, value):
        match key:
            case "username":
                self.user.username = value
            case "email":
                self.user.email = value

            case "role":
                if type(value) is not str:
                    raise TypeError("Must be str")
                self.user.role = value

            case "active":
                if type(value) is not bool:
                    raise TypeError("Must be bool")
                else:
                    self.user.active = value

            case "ip":
                if not self.session:  # !!!
                    raise KeyError("Incorrect key. There's no active session")
                elif type(value) is not str:
                    raise TypeError("Must be str")
                else:
                    self.session.ip = value

            case _:
                raise KeyError("Incorrect key.")


def main():
    pass


if __name__ == "__main__":
    main()
