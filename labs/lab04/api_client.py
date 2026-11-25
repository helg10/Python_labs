"""Клієнт для звернення до NVD CVE API 2.0."""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT: tuple[float, float] = (3.05, 10.0)


class ApiClientError(Exception):
    """Помилка мережевого запиту, HTTP-статусу або декодування відповіді NVD."""


def build_headers() -> dict[str, str]:
    """Формує HTTP-заголовки запиту до NVD API з урахуванням NVD_API_KEY."""
    headers: dict[str, str] = {"Accept": "application/json"}
    raw_key = os.getenv("NVD_API_KEY")
    if raw_key is not None:
        cleaned_key = raw_key.strip()
        if cleaned_key:
            headers["apiKey"] = cleaned_key
    return headers


def fetch_response(cve_id: str) -> dict[str, Any]:
    """Виконує один GET-запит до NVD API за ідентифікатором CVE і повертає JSON-словник"""
    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout as exc:
        raise ApiClientError(
            "Перевищено час очікування відповіді від NVD API."
        ) from exc
    except requests.exceptions.TooManyRedirects as exc:
        raise ApiClientError(
            "NVD API повернув перенаправлення замість очікуваної відповіді"
        ) from exc
    except requests.exceptions.HTTPError as exc:
        status_code = (
            exc.response.status_code if exc.response is not None else "невідомий"
        )
        raise ApiClientError(
            f"NVD API повернув помилку HTTP зі статусом {status_code}."
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise ApiClientError(
            "Не вдалося виконати запит до NVD API через мережеву помилку."
        ) from exc

    if response.status_code != 200:
        raise ApiClientError(
            f"Очікувався статус HTTP 200, отримано {response.status_code}."
        )

    try:
        payload = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError) as exc:
        raise ApiClientError("Відповідь NVD API не є коректним JSON.") from exc

    if not isinstance(payload, dict):
        raise ApiClientError(
            "Кореневий елемет відповіді NVD API має бути JSON-об'єктом"
        )

    return payload
