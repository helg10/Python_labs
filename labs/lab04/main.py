"""Точка входу CLI для отримання та аналізу записів CVE з NVD API або локального JSON"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_ID_PATTERN: re.Pattern[str] = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MIN_VARIANT = 1
MAX_VARIANT = 15


def _validate_variant(variant: Any) -> int:
    """Перевіряє, що номер варіанта є цілим числом від 1 до 15 і не є bool"""
    if isinstance(variant, bool) or not isinstance(variant, int):
        raise TypeError("Номер варіанта має бути цілим числом (не bool).")
    if not (MIN_VARIANT <= variant <= MAX_VARIANT):
        raise ValueError(
            f"Номер варіанта має бути в межах від {MIN_VARIANT} до {MAX_VARIANT}."
        )
    return variant


def _validate_cve_id(cve_id: str) -> str:
    """Перевіряє, що ідентифікатор CVE відповідає шаблону (регулярному виразу)"""
    if not isinstance(cve_id, str) or CVE_ID_PATTERN.fullmatch(cve_id) is None:
        raise ValueError(
            "Некоректний формат --cve: очікується шаблон CVE-[0-9]{4}-[0-9]{4,}."
        )
    return cve_id


def load_response(path: str | Path) -> dict[str, Any]:
    """Читає локальний JSON-файл у кодуванні UTF-8 та повертає розпарсений словник."""
    file_path = Path(path)
    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(
            f"Не вдалося прочитати вхідний файл {str(file_path)!r}."
        ) from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Вхідний файл {str(file_path)!r} містить некоректний JSON."
        ) from exc

    if not isinstance(payload, dict):
        raise TypeError("Кореневий елемент локального JSON-файлу має бути об'єктом")

    return payload


def _build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка"""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Отримання та аналіз запису CVE з NVD API 2.0 або локального JSON-файлу.",
    )
    parser.add_argument(
        "--cve",
        required=True,
        help="Ідентифікатор CVE у форматі, наприклад, CVE-2099-10001",
    )
    parser.add_argument(
        "--input",
        default=None,
        help="Необов'язковий шлях до локального JSON-файлу з відповіддю NVD.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Виконує CLI-сценарій і повертає код завершення: 0, 1 або 2."""
    try:
        variant = _validate_variant(VARIANT_NUMBER)
    except (TypeError, ValueError) as exc:
        print(f"Помилка конфігурації варіанта: {exc}", file=sys.stderr)
        return 2

    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        cve_id = _validate_cve_id(args.cve)
    except ValueError as exc:
        print(f"Помилка аргументів: {exc}", file=sys.stderr)
        return 2

    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(cve_id)

        record = analysis.extract_record(payload, cve_id)
        report = analysis.build_report(record, cve_id, variant)
    except (api_client.ApiClientError, TypeError, ValueError) as exc:
        print(f"Помилка обробки даних: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
