"""Спільні фікстури та допоміжні конструктори даних для тестів lab04."""

from typing import Any

import pytest


class DummyResponse:
    """Мінімальний об'єкт-замінник відповіді requests.Response."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: Any = None,
        json_error: Exception | None = None,
        raise_for_status_exc: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data
        self._json_error = json_error
        self._raise_for_status_exc = raise_for_status_exc

    def raise_for_status(self) -> None:
        if self._raise_for_status_exc is not None:
            raise self._raise_for_status_exc

    def json(self) -> Any:
        if self._json_error is not None:
            raise self._json_error
        return self._json_data


def make_nvd_payload(
    *,
    cve_id: str = "CVE-2024-12345",
    vuln_status: str | None = "Analyzed",
    score: Any = 6.0,
    confidentiality_impact: Any = "LOW",
    metric_type: str = "Primary",
    description_en: str | None = "Test vulnerability description.",
) -> dict[str, Any]:
    """Будує валідну структуру відповіді NVD API 2.0 для тестів."""
    cve_obj: dict[str, Any] = {"id": cve_id}

    if vuln_status is not None:
        cve_obj["vulnStatus"] = vuln_status

    if description_en is not None:
        cve_obj["descriptions"] = [
            {"lang": "es", "value": "Descripción en español."},
            {"lang": "en", "value": description_en},
        ]

    if vuln_status not in (None, "Rejected") and score is not None:
        cvss_data: dict[str, Any] = {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "baseScore": score,
        }
        if confidentiality_impact is not None:
            cvss_data["confidentialityImpact"] = confidentiality_impact

        cve_obj["metrics"] = {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": metric_type,
                    "cvssData": cvss_data,
                }
            ]
        }

    return {"vulnerabilities": [{"cve": cve_obj}]}


@pytest.fixture
def sample_nvd_payload() -> dict[str, Any]:
    """Повертає базовий payload, який за правилом варіанта 12 має дати decision='review'."""
    return make_nvd_payload(
        cve_id="CVE-2024-12345",
        vuln_status="Analyzed",
        score=6.0,
        confidentiality_impact="LOW",
    )
