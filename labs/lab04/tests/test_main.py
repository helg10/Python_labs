"""Тести CLI-логіки labs.lab04.main."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from labs.lab04 import api_client
from labs.lab04 import main as main_mod
from labs.lab04.tests.conftest import make_nvd_payload


def test_main_local_input_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sample_file = tmp_path / "nvd.json"
    payload = make_nvd_payload(
        cve_id="CVE-2024-55555",
        vuln_status="Analyzed",
        score=6.0,
        confidentiality_impact="LOW",
    )
    sample_file.write_text(json.dumps(payload), encoding="utf-8")

    def fail_if_called(_: str) -> dict[str, Any]:
        raise AssertionError(
            "fetch_response не має викликатися при використанні --input"
        )

    monkeypatch.setattr(api_client, "fetch_response", fail_if_called)

    exit_code = main_mod.main(["--cve", "CVE-2024-55555", "--input", str(sample_file)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    parsed = json.loads(captured.out)
    assert parsed["cve_id"] == "CVE-2024-55555"
    assert parsed["variant"] == 12
    assert parsed["decision"] == "review"


def test_main_invalid_cve_format_returns_exit_code_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main_mod.main(["--cve", "cve-2024-12345"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "CVE-[0-9]{4}-[0-9]{4,}" in captured.err


@pytest.mark.parametrize("bad_variant", [True, False, 0, 16])
def test_main_invalid_variant_number_returns_exit_code_2(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    bad_variant: Any,
) -> None:
    monkeypatch.setattr(main_mod, "VARIANT_NUMBER", bad_variant)

    exit_code = main_mod.main(["--cve", "CVE-2024-12345"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert captured.err.strip() != ""


def test_main_api_client_error_returns_exit_code_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_fetch(_: str) -> dict[str, Any]:
        raise api_client.ApiClientError("Мережева помилка")

    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)

    exit_code = main_mod.main(["--cve", "CVE-2024-12345"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "Мережева помилка" in captured.err


def test_main_missing_input_file_returns_exit_code_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_file = tmp_path / "does_not_exist.json"

    exit_code = main_mod.main(["--cve", "CVE-2024-12345", "--input", str(missing_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() != ""
