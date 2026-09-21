import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from rich.console import Console
from rich.table import Table
from rich.text import Text
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


class User:
    def __init__(self, user: str, clearance: int, department: str, active: bool):
        self.user = user
        self.clearance = clearance
        self.department = department
        self.active = active

    def __contains__(self, other):
        return other == self.user

    def request_resource(self, resource, system):
        return system.request_access(self, resource)

    def __str__(self):
        return f"User: {self.user}, clearance: {self.clearance},\
                department: {self.department}, active: {self.active}"


class Resource:
    def __init__(self, resource: str, access_lvl: int):
        self.resource = resource
        self.access_lvl = access_lvl

    def __str__(self):
        return f"Recource:{self.resource} Access_lvl{self.access_lvl}"


class ResourceAccessControl:
    def __init__(self, security_levels: tuple):
        self.security_levels = security_levels
        self.users = {}
        self.resources = []
        self.blocked_users = set()

    def register_user(self, user: str, clearance: int, department: str, active: bool):
        if user not in self.users:
            new_user = User(user, clearance, department, active)
            self.users[user] = new_user
            return new_user
        else:
            assert False, (
                "Користувач з таким іменем вже існує"
            )  # Бажано створити свій виняток

    def register_resource(self, resource: str, access_lvl: int):
        new_resource = Resource(resource, access_lvl)
        self.resources.append(new_resource)
        return new_resource

    def block_user(self, user):
        self.blocked_users.add(user)

    def display_swaped(self):  # Виконання умови 2 завдання
        print(
            "Виведення списку всіх ресурсів із заміненим рівнем безпеки ресурсу".center(
                79, "~"
            )
        )
        for res in self.resources:
            res_lvl = self.security_levels[res.access_lvl - 1]
            print(f"{res.resource} | {res_lvl} ({res.access_lvl})".center(69, " "))

    def request_access(self, user: User, resource: str):
        if user.user not in self.users:
            return "DENY (User not found)"
        if user.user in self.blocked_users:
            return "DENY (User is blocked)"
        if not user.active:
            return "DENY (Account inactive)"
        for rec in self.resources:
            if resource == rec.resource:
                if user.clearance >= rec.access_lvl:
                    # print("ALLOW")
                    # return rec
                    return "ALLOW"
                else:
                    return "DENY (Insufficient clearance)"
                    break
        else:
            print("Incorrect recource name, try again")


def main():
    users = {
        "devsecops_lead": {
            "role": "devsecops",
            "clearance": 4,
            "department": "DevSecOps",
            "active": True,
        },
        "security_engineer": {
            "role": "security_engineer",
            "clearance": 3,
            "department": "Security Engineering",
            "active": True,
        },
        "automation_tech": {
            "role": "automation",
            "clearance": 2,
            "department": "Automation",
            "active": True,
        },
        "api_developer": {
            "role": "api_developer",
            "clearance": 2,
            "department": "API",
            "active": True,
        },
        "sandbox_env": {
            "role": "sandbox",
            "clearance": 1,
            "department": "Testing",
            "active": False,
        },
    }
    resources = [
        ("security_pipelines", 4),
        ("secure_coding_standards", 3),
        ("automation_scripts", 2),
        ("api_specifications", 2),
        ("threat_models", 4),
        ("testing_frameworks", 1),
        ("security_gates", 3),
        ("vulnerability_scans", 4),
        ("integration_tests", 2),
        ("mock_services", 1),
    ]
    security_levels = ("Sandbox", "Development", "Secure", "Production Critical")
    blocked_users = {"sandbox_env", "pipeline_breach", "automation_fail"}
    rc_contrl = ResourceAccessControl(security_levels)
    for us in users:
        rc_contrl.register_user(
            us,
            users[us]["clearance"],
            users[us]["department"],
            users[us]["active"],
        )
    for rec in resources:
        rc_contrl.register_resource(rec[0], rec[1])
    for blocked_usr in blocked_users:
        rc_contrl.block_user(blocked_usr)
    rc_contrl.display_swaped()
    print("\n\n\n\n")
    # Створення таблиці для зручного виводу 4 пункту
    console = Console()
    title = Text("Результат", style="bold green")
    table = Table(title=title, header_style="bold orange3")
    table.add_column("User", style="bold white", justify="center", no_wrap=True)
    table.add_column("Recource", style="bold white", justify="center")
    table.add_column("Permission", style="bold white", justify="center")
    for us in rc_contrl.users:
        user = rc_contrl.users[us]
        for rec in rc_contrl.resources:
            rec_name = rec.resource
            permission = user.request_resource(rec_name, rc_contrl)
            if permission == "ALLOW":
                table.add_row(user.user, rec_name, f"[green]{permission}[/green]")
            else:
                table.add_row(user.user, rec_name, f"[red]{permission}[/red]")
    console.print(table, justify="center")
    print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)


if __name__ == "__main__":
    # pass
    main()
