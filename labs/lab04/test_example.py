# import pytest

# def reaches_limit(count, limit):
#     return count >= limit

# @pytest.mark.parametrize("count, expected", [(2, False), (3, True), (4, True)])
# def test_reaches_limit(count, expected):
#     assert reaches_limit(count, 3) is expected

import pytest

# @pytest.fixture
# def sample_payload():
#   return {"status": "ok", "items": [1, 2, 3]}


def parse_positive(x: int) -> int:
    if x < 0:
        raise ValueError("Число має бути невід'ємним")
    return x * 2


def test_output_and_error(capsys, tmp_path):
    print("Готово")
    captured = capsys.readouterr()
    assert captured.out.strip() == "Готово"

    temp_file = tmp_path / "notes.txt"
    temp_file.write_text("привіт", encoding="utf-8")
    assert temp_file.read_text(encoding="utf-8") == "привіт"


def test_negative_input():
    with pytest.raises(ValueError):
        parse_positive(-4)
