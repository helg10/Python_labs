import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
import random

from rich.console import Console
from rich.table import Table
from rich.text import Text
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


# Головна програма
def main():
    passwords = [
        "SIEM@An4lysis",
        "easy123",
        "S0C@Analyst",
        "observer",
        "Threat@Hunt1ng",
        "viewer",
        "Incid3nt@Handle",
        "monitor",
        "Log@An4lysis",
        "watcher",
    ]
    criteria = {
        "min_length": 9,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }
    forbidden_passwords = {
        "easy123",
        "observer",
        "viewer",
        "monitor",
        "watcher",
        "admin",
    }
    # Генерація рандомних індексів
    random_indxs = []
    while len(random_indxs) != 3:
        random_i = random.randrange(0, len(passwords))
        if random_i not in random_indxs:
            random_indxs.append(random_i)
    # Імітація повторного використання паролів
    for i in random_indxs:
        passwords.append(passwords[i])
    # Збереження унікальних паролів
    unique_passwords = set(passwords)

    console = Console()
    # Створення таблиць
    tables = {
        "Forbidden": make_table("Заборонені", "red"),
        "Weak": make_table("Слабкі", "orange3"),
        "Mid": make_table("Середні", "yellow"),
        "Strong": make_table("Сильні", "green"),
        "Secure": make_table("Дуже сильні", "green"),
    }

    for password in unique_passwords:
        criteria_checked = criteria_check(password, forbidden_passwords)
        # Недозволені паролі заповнюють цю таблицю:
        if is_forbidden(criteria_checked, criteria):
            tables["Forbidden"].add_row(
                criteria_checked["password"],
                f"{criteria_checked['length']}",
                f"{criteria_checked['has_digit']}",
                f"{criteria_checked['has_upper']}",
                f"{criteria_checked['has_special']}",
            )
            continue
        # Слабкі паролі заповнюють цю таблицю:
        if is_weak(criteria_checked, criteria):
            tables["Weak"].add_row(
                criteria_checked["password"],
                f"{criteria_checked['length']}",
                f"{criteria_checked['has_digit']}",
                f"{criteria_checked['has_upper']}",
                f"{criteria_checked['has_special']}",
            )
            continue
        # Середні паролі заповнюють цю таблицю:
        if is_mid(criteria_checked, criteria):
            tables["Mid"].add_row(
                criteria_checked["password"],
                f"{criteria_checked['length']}",
                f"{criteria_checked['has_digit']}",
                f"{criteria_checked['has_upper']}",
                f"{criteria_checked['has_special']}",
            )
            continue
        # Сильні паролі заповнюють цю таблицю:
        if is_strong(criteria_checked, criteria):
            tables["Strong"].add_row(
                criteria_checked["password"],
                f"{criteria_checked['length']}",
                f"{criteria_checked['has_digit']}",
                f"{criteria_checked['has_upper']}",
                f"{criteria_checked['has_special']}",
            )
            continue
        # Дуже сильні паролі заповнюють цю таблицю:
        if is_secure(criteria_checked, criteria):
            tables["Secure"].add_row(
                criteria_checked["password"],
                f"{criteria_checked['length']}",
                f"{criteria_checked['has_digit']}",
                f"{criteria_checked['has_upper']}",
                f"{criteria_checked['has_special']}",
            )
    # Виводимо всі таблички
    console.print(tables["Forbidden"], justify="center")
    console.print(tables["Weak"], justify="center")
    console.print(tables["Mid"], justify="center")
    console.print(tables["Strong"], justify="center")
    console.print(tables["Secure"], justify="center")
    print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)


def criteria_check(
    passwd, forbidden_passwords
) -> dict:  # повертає значення критеріїв для паролю
    digits = "0123456789"
    upper_symbols = "ETAOINSRHLDCUMFPGWYBVKXJQZ"
    special_symbols = "!@#$%^&*()_-"
    criteria_checked = {
        "password": passwd,
        "length": len(passwd),
        "permission": passwd not in forbidden_passwords,
        "has_digit": any(ch in digits for ch in passwd),
        "has_upper": any(ch in upper_symbols for ch in passwd),
        "has_special": any(ch in special_symbols for ch in passwd),
    }
    return criteria_checked


def make_table(title_text, color):  # створює таблицю
    title = Text(title_text, style=f"bold {color}")
    table = Table(title=title, header_style=f"bold {color}")
    table.add_column("Пароль", style="bold white", justify="center", no_wrap=True)
    table.add_column("Довжина", style="bold white", justify="center")
    table.add_column("Цифри", style="bold white", justify="center")
    table.add_column("Верх. регістр", style="bold white", justify="center")
    table.add_column("Спецсимволи", style="bold white", justify="center")
    return table


# Перевірка категорії паролю
def is_forbidden(criteria_checked, criteria) -> bool:
    return (criteria_checked["permission"] == False) or (
        criteria_checked["length"] < criteria["min_length"]
    )


def is_weak(criteria_checked, criteria) -> bool:
    return list(criteria_checked.values()).count(True) == 2 and (
        criteria_checked["length"] >= criteria["min_length"]
    )


def is_mid(criteria_checked, criteria) -> bool:
    return list(criteria_checked.values()).count(True) == 3 and (
        criteria_checked["length"] >= criteria["min_length"]
    )


def is_strong(criteria_checked, criteria) -> bool:
    return list(criteria_checked.values()).count(True) == 4 and (
        criteria_checked["length"] < criteria["min_length"] + 4
    )


def is_secure(criteria_checked, criteria) -> bool:
    return list(criteria_checked.values()).count(True) == 4 and (
        criteria_checked["length"] > criteria["min_length"] + 4
    )


if __name__ == "__main__":
    main()
