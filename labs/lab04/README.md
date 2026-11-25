# Аналіз вразливостей CVE (NVD API 2.0)

CLI-інструмент для отримання даних про вразливості з NVD API 2.0 або з локального JSON-файлу та формування звіту за правилами **варіанта 12** (CVSS v3.1).

## Встановлення залежностей

Робота виконується у віртуальному середовищі `.venv` з кореня репозиторію (`Python_labs`).

### Створення та активація віртуального середовища

```bash
python -m venv .venv
source .venv/bin/activate
```

### Встановлення необхідних бібліотек

```bash
pip install -r requirements.txt
```

## Логіка варіанта 12

* **Поріг оцінки (`threshold`):** `6.0` (`baseScore >= 6.0` за CVSS v3.1)
* **Поле для перевірки (`field`):** `confidentialityImpact`
* **Очікуване значення (`expected`):** `"LOW"`

Якщо вразливість проаналізована, оцінка CVSS v3.1 не менша за `6.0` і `confidentialityImpact == "LOW"`, у звіті формується рішення `"review"`. В інших випадках результат залежить від статусу та повноти даних (`"not_found"`, `"rejected"`, `"insufficient_data"`, `"other"`).
## Загальна логіка формування звіту
Після отримання даних (`--input` або NVD API) модуль `analysis.py` вилучає запис за `cve_id` та застосовує правила **варіанта 12** (`threshold: 6.0`, `field: "confidentialityImpact"`, `expected: "LOW"`).

### Коли яке рішення (`decision`) формується

* **`"not_found"`** — у відповіді немає запису для вказаного `cve_id` (`vulnerabilities` порожній або цільовий CVE відсутній).
* **`"rejected"`** — запис знайдено, але його статус `vulnStatus` має значення `"Rejected"` (вразливість відхилена/анульована в NVD).
* **`"insufficient_data"`** — запис існує і не відхилений, але бракує даних для оцінки за правилом (наприклад, відсутня метрика CVSS v3.1, немає `baseScore` або відсутнє значення `confidentialityImpact`).
* **`"review"`** — дані повні, `baseScore` не менше `6.0` (з урахуванням порога `6.0`), а значення `confidentialityImpact` дорівнює `"LOW"`.
* **`"other"`** — дані повні, запис не відхилений, але умови правила варіанта 12 не виконані (наприклад, `baseScore` менше `6.0` або `confidentialityImpact` відрізняється від `"LOW"`).

### Формат вихідного JSON-звіту

У разі успішного завершення (`exit code = 0`) у `stdout` виводиться єдиний JSON-об'єкт такої структури:

```json
{
  "cve_id": "CVE-2024-12345",
  "variant": 12,
  "decision": "review",
  "score": 6.0,
  "observed": "LOW",
  "rule": {
    "threshold": 6.0,
    "field": "confidentialityImpact",
    "expected": "LOW"
  }
}
```

### Формат вхідного JSON (приклад необробленої відповіді від NVD API)
```json
{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-10-26T00:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2099-10001",
        "sourceIdentifier": "training@example.invalid",
        "published": "2026-01-01T00:00:00.000",
        "lastModified": "2026-10-26T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
          {
            "lang": "en",
            "value": "Synthetic vulnerability for offline API testing."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH",
                "availabilityImpact": "HIGH",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
              }
            }
          ]
        },
        "references": []
      }
    }
  ]
}

```

## Структура каталогу

```text
labs/lab04/
├── __init__.py
├── api_client.py       # GET-запити до NVD API, таймаути, обробка статусів і JSON
├── analysis.py         # Вилучення запису, валідація даних і правила варіанта 12
├── main.py             # CLI-інтерфейс, коди виходу, stdout / stderr
├── data/
│   └── nvd_sample.json # Приклад відповіді NVD API
└── tests/              # Тестування за допомогою бібліотеки pytest
    ├── __init__.py
    ├── conftest.py
    ├── test_api_client.py
    ├── test_analysis.py
    └── test_main.py
```

## Запуск
Усі команди виконуються з кореня репозиторію (Python_labs). Ось їхній перелік:

### Запит до NVD API
```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

### Робота з локальним JSON-файлом
```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

## Коди завершення та потоки виводу
- `0` - звіт сформовано; у `stdout` виводиться один JSON-об'єкт, `stderr` порожній
- `1` — помилка отримання, читання або валідації даних (`ApiClientError`, проблеми з файлом, битий JSON, `ValueError`); пояснення виводиться в `stderr`.
- `2` — помилка аргументів CLI або некоректне значення `VARIANT_NUMBER`; повідомлення виводиться в `stderr`.

## Запуск тестів
```bash
python -m pytest labs/lab04/tests
```

