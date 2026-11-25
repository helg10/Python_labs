from typing import Any

import pytest

from labs.lab04 import analysis


def _payload(
    *,
    cve_id: str = "CVE-2024-12345",
    vuln_status: str | None = "Analyzed",
    score: Any = 7.5,
    impact: Any = "LOW",
    description: str | None = "Test desc",
) -> dict[str, Any]:
    """Формує тестовий словник відповіді NVD API 2.0 для заданих параметрів."""

    cve: dict[str, Any] = {"id": cve_id}
    if vuln_status is not None:
        cve["vulnStatus"] = vuln_status
    if description is not None:
        cve["descriptions"] = [{"lang": "en", "value": description}]
    if impact is not None or score is not None:
        cvss_data: dict[str, Any] = {"version": "3.1", "baseScore": score}
        if impact is not None:
            cvss_data["confidentialityImpact"] = impact
        cve["metrics"] = {"cvssMetricV31": [{"type": "Primary", "cvssData": cvss_data}]}
    return {"vulnerabilities": [{"cve": cve}]}


def test_extract_record_not_found() -> None:
    """Перевіряє, що extract_record повертає None при порожньому списку vulnerabilities."""
    assert analysis.extract_record({"vulnerabilities": []}, "CVE-2024-12345") is None


def test_extract_record_ok() -> None:
    """Перевіряє коректне вилучення статусу, оцінки CVSS v3.1 та confidentialityImpact."""
    rec = analysis.extract_record(_payload(score=6.5, impact="LOW"), "CVE-2024-12345")
    assert rec is not None
    assert rec["vuln_status"] == "Analyzed"
    assert rec["cvss_v31"]["score"] == 6.5
    assert rec["cvss_v31"]["confidentialityImpact"] == "LOW"


def test_extract_record_id_mismatch() -> None:
    """Перевіряє, що невідповідність cve.id запитаному cve_id викликає ValueError."""
    with pytest.raises(ValueError):
        analysis.extract_record(_payload(cve_id="CVE-2024-99999"), "CVE-2024-12345")


@pytest.mark.parametrize("bad_score", [True, False, "7.0"])
def test_invalid_base_score_type_error(bad_score: Any) -> None:
    """Перевіряє, що нечислові або bool значення baseScore викликають TypeError."""
    with pytest.raises(TypeError):
        analysis.extract_record(_payload(score=bad_score), "CVE-2024-12345")


@pytest.mark.parametrize("bad_score", [-0.1, 10.1, float("nan"), float("inf")])
def test_invalid_base_score_value_error(bad_score: Any) -> None:
    """Перевіряє, що числа поза [0, 10], NaN та inf у baseScore викликають ValueError."""
    with pytest.raises(ValueError):
        analysis.extract_record(_payload(score=bad_score), "CVE-2024-12345")


@pytest.mark.parametrize(
    ("score", "impact", "expected"),
    [
        (6.0, "LOW", "review"),
        (9.0, "LOW", "review"),
        (5.9, "LOW", "other"),
        (7.5, "HIGH", "other"),
        (7.5, None, "insufficient_data"),
    ],
)
def test_build_report_variant_12(
    score: float, impact: str | None, expected: str
) -> None:
    """Перевіряє підсумкові рішення build_report для варіанта 12 за score та impact."""
    rec = {
        "vuln_status": "Analyzed",
        "description": "Desc",
        "cvss_v31": {"score": score, "confidentialityImpact": impact},
    }
    report = analysis.build_report(rec, "CVE-2024-12345", 12)
    assert report["decision"] == expected


def test_build_report_not_found_and_rejected() -> None:
    """Перевіряє рішення not_found для None та rejected для статусу Rejected."""
    assert analysis.build_report(None, "CVE-2024-12345", 12)["decision"] == "not_found"
    rejected_rec = {"vuln_status": "Rejected", "description": None, "cvss_v31": None}
    assert (
        analysis.build_report(rejected_rec, "CVE-2024-12345", 12)["decision"]
        == "rejected"
    )


def test_build_report_unsupported_variant() -> None:
    """Перевіряє, що непідтримуваний номер варіанта викликає ValueError."""
    with pytest.raises(ValueError):
        analysis.build_report(None, "CVE-2024-12345", 1)
