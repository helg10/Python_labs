"""Тести для labs.lab04.api_client з мокуванням requests.get."""

from typing import Any

import pytest
import requests

from labs.lab04 import api_client
from labs.lab04.tests.conftest import DummyResponse


def test_fetch_response_success(monkeypatch: pytest.MonkeyPatch) -> None:
    expected_payload = {"vulnerabilities": []}
    captured: dict[str, Any] = {}

    def fake_get(url: str, **kwargs: Any) -> DummyResponse:
        captured["url"] = url
        captured["kwargs"] = kwargs
        return DummyResponse(status_code=200, json_data=expected_payload)

    monkeypatch.setattr(api_client.requests, "get", fake_get)

    result = api_client.fetch_response("CVE-2024-12345")

    assert result == expected_payload
    assert captured["url"] == api_client.NVD_API_URL
    assert captured["kwargs"]["params"] == {"cveId": "CVE-2024-12345"}
    assert captured["kwargs"]["headers"].get("Accept") == "application/json"


def test_fetch_response_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> DummyResponse:
        return DummyResponse(
            status_code=503,
            raise_for_status_exc=requests.HTTPError("503 Service Unavailable"),
        )

    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(api_client.ApiClientError):
        api_client.fetch_response("CVE-2024-12345")


def test_fetch_response_request_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> DummyResponse:
        raise requests.Timeout("Connection timed out")

    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(api_client.ApiClientError):
        api_client.fetch_response("CVE-2024-12345")


@pytest.mark.parametrize("bad_json", ["not a dict", [1, 2, 3], None, 42])
def test_fetch_response_non_dict_json(
    monkeypatch: pytest.MonkeyPatch, bad_json: Any
) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> DummyResponse:
        return DummyResponse(status_code=200, json_data=bad_json)

    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(api_client.ApiClientError):
        api_client.fetch_response("CVE-2024-12345")


def test_fetch_response_invalid_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(*args: Any, **kwargs: Any) -> DummyResponse:
        return DummyResponse(status_code=200, json_error=ValueError("Invalid JSON"))

    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(api_client.ApiClientError):
        api_client.fetch_response("CVE-2024-12345")
