# md5 8(minimum lenght)
import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
import hashlib

from rich.console import Console
from rich.table import Table
from rich.text import Text
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


class ValidationError(Exception):
    """Виникає, якщо змінна password, передана
    в фун. generate_hash коротша за 8 символів"""  # docstring tutorial


salt = "00012"
users_to_register = (
    ("login", "password"),
    ("dragon_warrior", "qwerty232"),
    ("admin", "Admin2000!"),
    ("Linus", "#!jln@#fK$"),
    ("monster", "werewolf225"),
    ("mise", "joiyo&*$Giy"),
    ("root", "GreatSecret"),
    ("cochroach", "bread_crumps"),
    ("ted", "1993teds"),
    ("college", "trustfull_pass"),
)


def generate_hash(password: str, salt: str = "00012") -> str:
    if not password or not salt:
        raise ValueError("Відсутнє значення переданої змінної password або salt (None)")
    if len(password) < 8:
        raise ValidationError(
            "Атрибут password повинен мати довжину не менше 8 символів"
        )
    password = password + salt
    bpassword = password.encode("utf-8")
    hex_hash = hashlib.md5(bpassword).hexdigest()
    return hex_hash


def create_user(username, password) -> tuple:
    try:
        generated_hash = generate_hash(password, "00012")
        return (username, generated_hash)
    
    except ValueError:
        print("ValueError: Відсутнє значення переданої змінної password або " \
        "salt (None). Неможливо згенерувати хеш, користувача не зареєстровано")

    except ValidationError:
        print("ValidationError: Атрибут password повинен мати довжину не менше" \
        " 8 символів. Неможливо згенерувати хеш, користувача не зареєстровано")

def user_in_csv(file, column_name, searched_username) -> bool:
    file.flush()
    file.seek(0, 0)
    reader = csv.DictReader(file)
    for row in reader:
        if row.get(f"{column_name}") == searched_username:
            return True
    return False


def create_users(users_list) -> None:

    try:
        csv_path = Path("./data/users.csv")
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with open(csv_path, "a+") as db:
            # Додавання атрибутів у перший рядок csv файлу
            if db.tell() == 0:
                db.write("username,passwords_hash")
            for account in users_list:
                # Перевірка наявності користувача в системі
                registered_acc = create_user(*account)
                if not user_in_csv(db, "username", f"{registered_acc[0]}"):
                    db.seek(0, 2)
                    db.write(f"\n{registered_acc[0]},{registered_acc[1]}")
    except OSError:
        print("IOError: щось пішло не так на стороні системи під час запису користувачів у БД")

    except PermissionError:
        print("PermissionError: помилка прав під час запису/читання користувачів у БД")


def create_table(title, color, *col_names):
    title_name = Text(title, style=color)
    table = Table(title=title_name, header_style=color)
    for name in col_names:
        table.add_column(f"{name}", style="bold white", justify="center", no_wrap=True)
    return table


def log_event(func: callable):
    def wrapper(*args, **kwargs):
        rv = func(*args, **kwargs)
        # Час логування
        local_time = datetime.now().astimezone()
        timestamp = local_time.isoformat(timespec="seconds").split("T")
        timestamp[1] = timestamp[1][:8]
        timestamp = " ".join(timestamp)
        # Створення папки, якщо вона не існує
        try:
            log_path = Path("./data/log.jsonl")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # Створення/запис в log.jsonl
            with open(log_path, "a") as log_json:
                log = {
                    "event": f"{func.__name__}",
                    "user": f"{args[0] if args else kwargs['username']}",
                    "result": f"{'success' if rv else 'failure'}",
                    "timestamp": f"{timestamp}",
                    "args": [arg for arg in args],
                    "kwargs": kwargs,
                }
                if log_json.tell() == 0:
                    log_json.write(json.dumps(log))
                else:
                    log_json.write(f"\n{json.dumps(log)}")
            return rv
        except OSError:
            print("IOError: щось пішло не так на стороні системи під логування")
        except PermissionError:
            print("PermissionError: помилка прав під час запису/читання логів")
    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    try:
        if not username or not password:
            raise ValueError("Значення username або/і password порожнє")
        with open("./data/users.csv") as db:
            reader = csv.DictReader(db)
            hash_value = generate_hash(password, salt="00012")
            for row in reader:
                if username == row["username"] and hash_value == row["passwords_hash"]:
                    return True
        return False
    
    except OSError:
        print("IOError: щось пішло не так на стороні системи " \
        "під час перевірки на наявність користувача у БД")

    except PermissionError:
        print("PermissionError: помилка прав під час перевірки " \
        "на наявність користувача у БД")

def main():
    create_users(users_to_register)
    console = Console()
    db_table = create_table("users.csv", "orange3", "user", "hash-value")
    with open("./data/users.csv") as db:
        reader = csv.DictReader(db)
        user_db = []
        for account in reader:
            db_table.add_row(
                f"[yellow]{account['username']}[/yellow]",
                f"[purple]{account['passwords_hash']}[/purple]",
            )
            user_db.append(account)
    console.print(db_table, justify="center")
    print(f"Login: Linus; Password: #!jln@#fK$; Status:{login("Linus", "#!jln@#fK$")}")
    print(f"Login: admin; Password: wrong_pass; Status:{login("admin", "wrong_pass")}")
    print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)


if __name__ == "__main__":
    main()