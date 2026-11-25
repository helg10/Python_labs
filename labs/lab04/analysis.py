"""Перевірка даних NVD, вибір оцінки CVSS v3.1 та формування звіту за варіантом."""

import math
from typing import Any

VALID_CONFIDENTIALITY_IMPACTS: frozenset[str] = frozenset({"NONE", "LOW", "HIGH"})
VARIANT_RULES: dict[int, dict[str, Any]] = {
    12: {
        "threshold": 6.0,
        "field": "confidentialityImpact",
        "expected": "LOW",
    }
}


def _is_not_empty_str(value: Any) -> bool:
    """Перевіряє, що значення є непорожнім рядком."""
    return isinstance(value, str) and bool(value.strip())


def _extract_optional_not_empty_str(container: dict[str, Any], key: str) -> str | None:
    """Повертає значення ключа, якщо його немає — None; якщо є, але некоректне — ValueError."""
    if key not in container:
        return None
    val = container[key]
    if not _is_not_empty_str(val):
        raise ValueError(f"Поле {key} має бути непорожнім рядком.")
    return val


def _validate_finite_score(value: Any) -> float:
    """Перевіряє, що baseScore є скінченним числом у діапазоні [0, 10], але не bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("Поле baseScore має бути числом (не bool).")
    score = float(value)
    if not math.isfinite(score) or not (0.0 <= score <= 10.0):
        raise ValueError(
            "Поле baseScore має бути скінченним числом у діапазоні від 0 до 10."
        )
    return score


def _extract_english_description(cve_obj: dict[str, Any]) -> str | None:
    """Повертає перший непорожній англійський опис або None."""
    if "descriptions" not in cve_obj:
        return None

    descriptions = cve_obj["descriptions"]
    if not isinstance(descriptions, list):
        raise TypeError("Поле descriptions має бути списком.")

    for item in descriptions:
        if not isinstance(item, dict):
            raise TypeError("Елемент descriptions має бути об'єктом.")
        lang = item.get("lang")
        value = item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise TypeError("Поля lang і value в descriptions мають бути рядками.")
        if lang == "en" and value.strip():
            return value

    return None


def _extract_cvss_v31_data(cve_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Обирає метрику CVSS v3.1 (пріоритет Primary, інакше перший елемент) або повертає None."""
    if "metrics" not in cve_obj:
        return None

    metrics = cve_obj["metrics"]
    if not isinstance(metrics, dict):
        raise TypeError("Поле metrics має бути об'єктом.")

    if "cvssMetricV31" not in metrics:
        return None

    metric_list = metrics["cvssMetricV31"]
    if not isinstance(metric_list, list):
        raise TypeError("Поле cvssMetricV31 має бути списком.")

    if len(metric_list) == 0:
        return None

    for metric in metric_list:
        if not isinstance(metric, dict):
            raise TypeError("Елемент cvssMetricV31 має бути об'єктом.")

    selected_metric: dict[str, Any] | None = None
    for metric in metric_list:
        if metric.get("type") == "Primary":
            selected_metric = metric
            break
    if selected_metric is None:
        selected_metric = metric_list[0]

    if "cvssData" not in selected_metric or not isinstance(
        selected_metric["cvssData"], dict
    ):
        raise ValueError(
            "У вибраній оцінці CVSS v3.1 відсутній або некоректний об'єкт cvssData."
        )

    cvss_data = selected_metric["cvssData"]

    if "baseScore" not in cvss_data:
        raise ValueError("У cvssData відсутнє обов'язкове поле baseScore.")
    score = _validate_finite_score(cvss_data["baseScore"])

    version = _extract_optional_not_empty_str(cvss_data, "version")
    if version is not None and version != "3.1":
        raise ValueError(f"Неочікувана версія CVSS у cvssData: {version!r}")

    vector = _extract_optional_not_empty_str(cvss_data, "vectorString")
    source = _extract_optional_not_empty_str(selected_metric, "source")

    impact_value: str | None
    if "confidentialityImpact" not in cvss_data:
        impact_value = None
    else:
        raw_impact = cvss_data["confidentialityImpact"]
        if (
            not isinstance(raw_impact, str)
            or raw_impact not in VALID_CONFIDENTIALITY_IMPACTS
        ):
            raise ValueError(
                "Некоректне значення поля confidentialityImpact у cvssData."
            )
        impact_value = raw_impact

    return {
        "cvss_version": version,
        "score": score,
        "score_source": source,
        "vector": vector,
        "confidentialityImpact": impact_value,
    }


def extract_record(payload: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None, якщо запис не знайдено.

    Формат внутрішнього запису (коли запис знайдено):
    - "vuln_status": str | None
    - "description": str | None
    - "cvss_v31": dict[str, Any] | None (містить cvss_version, score, score_source,
      vector, confidentialityImpact) або None, якщо оцінка не аналізується чи відсутня.
    """
    if not isinstance(payload, dict):
        raise TypeError("Відповідь NVD має бути словником.")

    if "vulnerabilities" not in payload or not isinstance(
        payload["vulnerabilities"], list
    ):
        raise ValueError(
            "У відповіді NVD відсутній або некоректний список vulnerabilities."
        )

    vulnerabilities = payload["vulnerabilities"]
    if len(vulnerabilities) == 0:
        return None

    if len(vulnerabilities) != 1:
        raise ValueError(
            "Очікується не більше одного елемента у vulnerabilities для точного cveId."
        )

    item = vulnerabilities[0]
    if (
        not isinstance(item, dict)
        or "cve" not in item
        or not isinstance(item["cve"], dict)
    ):
        raise ValueError("Елемент vulnerabilities має містити об'єкт cve.")

    cve_obj = item["cve"]
    actual_id = cve_obj.get("id")
    if not isinstance(actual_id, str) or actual_id != cve_id:
        raise ValueError(
            "Ідентифікатор cve.id у відповіді не збігається із запитаним cve_id."
        )

    vuln_status = _extract_optional_not_empty_str(cve_obj, "vulnStatus")
    description = _extract_english_description(cve_obj)

    if vuln_status == "Rejected" or vuln_status is None:
        return {
            "vuln_status": vuln_status,
            "description": description,
            "cvss_v31": None,
        }

    cvss_v31 = _extract_cvss_v31_data(cve_obj)
    return {
        "vuln_status": vuln_status,
        "description": description,
        "cvss_v31": cvss_v31,
    }


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосовує правило варіанта (зокрема варіанта 12) та формує словник звіту."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        raise ValueError(f"Непідтримуваний номер варіанта: {variant!r}.")

    rule_cfg = VARIANT_RULES[variant]
    rule_report = {
        "threshold": rule_cfg["threshold"],
        "field": rule_cfg["field"],
        "expected": rule_cfg["expected"],
    }

    if record is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": None,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule_report,
            "observed": None,
            "decision": "not_found",
        }

    if not isinstance(record, dict):
        raise TypeError("Внутрішній запис має бути словником або None.")

    vuln_status = record.get("vuln_status")
    description = record.get("description")

    if vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule_report,
            "observed": None,
            "decision": "rejected",
        }

    if vuln_status is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule_report,
            "observed": None,
            "decision": "insufficient_data",
        }

    cvss_v31 = record.get("cvss_v31")
    if cvss_v31 is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule_report,
            "observed": None,
            "decision": "insufficient_data",
        }

    if not isinstance(cvss_v31, dict):
        raise TypeError(
            "Поле cvss_v31 у внутрішньому записі має бути словником або None."
        )

    score = _validate_finite_score(cvss_v31.get("score"))
    observed = cvss_v31.get(rule_report["field"])

    if observed is None:
        decision = "insufficient_data"
    elif score >= rule_report["threshold"] and observed == rule_report["expected"]:
        decision = "review"
    else:
        decision = "other"

    return {
        "cve_id": cve_id,
        "variant": variant,
        "description": description,
        "vuln_status": vuln_status,
        "cvss_version": cvss_v31.get("cvss_version"),
        "score": score,
        "score_source": cvss_v31.get("score_source"),
        "vector": cvss_v31.get("vector"),
        "rule": rule_report,
        "observed": observed,
        "decision": decision,
    }
