import argparse
import time

from .task1 import *


# Створіть об'єкти й покажіть:
# успішний і невдалий вхід, зміну email із валідацією, права адміністратора,
# завершення сеансу за таймаутом, вихід із системи та записи AuditLog .
# Запускайте демонстрацію командою python -m labs.lab02.main demo ; вона не
# повинна виконуватися при імпорті task1.py .
def demo():
    print("Сценарій демонстрації".center(50, "~"))
    usr = User("helgi", "e_X2ample@gmail.com", "devops")

    print("\n\nПеревірки  при заданні та перевірці паролю")
    try:
        usr.check_password("")
    except PasswordNone as p:
        print(f"Програма впала б: {p}")

    try:
        usr.set_password("qwerty")
    except PasswordNone as p:
        print(f"Програма впала б:{p}")
    # Правильна ініціалізація паролю
    usr.set_password("enough?!")

    usr_acc = UserAccount(usr)
    print("\n\nВдалий та невдалий вхід")
    # Невдалий вхід
    print(f"Автентифіковано?: {usr_acc.login('helgi', 'enough?', '127.0.0.0')}")
    # Вдалий вхід
    print(f"Автентифіковано?: {usr_acc.login('helgi', 'enough?!', '127.0.0.0')}")
    usr_acc.journal.show_all()

    # Введення емейлу неправильного формату
    print("\n\nВедення емейлу неправильного формату")
    try:
        usr_acc["email"] = "1bad@poo.com"
        usr_acc["email"] = ""
        usr_acc["email"] = "person@gmail"
    except ValueError as v:
        print(f"Валідацію email не пройдено: {v}")
    # Введення правильного емейлу
    usr_acc["email"] = "helgi01@edu.lpnu.ua"
    print(usr_acc["email"])
    # Admin
    admin = Admin("admin", "admin@gmail.com", "sysadmin", ("database", "modify"))
    print("\n\nПрава адміністратора")
    admin.revoke_permission("modify")
    admin.has_permission("modify")
    print(admin)

    print("\n\nЗавершення сеансу за таймаутом")
    # Модицікуємо константу
    usr_acc.SESSION_TIMEOUT_SEC = 3
    usr_acc.login("helgi", "enough?!", "127.0.0.0")
    time.sleep(3)
    print(f"Сеанс активний?:{usr_acc.is_authenticated()}")

    print("\n\nВихід із системи та записи AuditLog")
    usr_acc.logout()
    usr_acc.journal.show_all()


def main():
    parser = argparse.ArgumentParser(description="Програма-демонстрація")

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Доступні команди"
    )

    demo_parser = subparsers.add_parser("demo", help="Запустити демонтстрацію")

    demo_parser.set_defaults(func=demo)
    args = parser.parse_args()
    args.func()


if __name__ == "__main__":
    main()
