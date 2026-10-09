import argparse
import csv
import logging
import re
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

# --- Створення іменованого логера для модуля ---
logger = logging.getLogger(__name__)

# --- Константи для роботи зі шляхами ---
BASE_DIR = Path(__file__).resolve().parent

DEFAULT_LOG_PATH = BASE_DIR / "data" / "data_v12" / "mail_headers.log"
DEFAULT_KEYWORD_PATH = BASE_DIR / "data" / "data_v12" / "suspicious_keywords.txt"
DEFAULT_OUT_CSV = BASE_DIR / "reports" / "phishing_report.csv"

# Регулярний вираз для пошуку e-mail домену
EMAIL_DOMAIN_REGEX = re.compile(r"[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})")


# --- Моделі даних та Enum ---
@dataclass
class EmailHeader:
    raw_block: str
    message_id: str | None = None
    from_raw: str | None = None
    from_domain: str | None = None
    return_path_raw: str | None = None
    return_path_domain: str | None = None
    reply_to_raw: str | None = None
    reply_to_domain: str | None = None
    subject: str | None = None
    received_chain: list[str] = field(default_factory=list)


class ThreatScore(IntEnum):
    """Вагові бали за виявлення аномалії в листах."""

    FROM_RETURN_PATH_MISMATCH = 35
    FROM_REPLY_TO_MISMATCH = 30
    SUSPICIOUS_KEYWORD_MATCH = 20
    EXCESSIVE_RECEIVED_HOPS = 15


class RiskLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @staticmethod
    def evaluate(score: int) -> str:
        if score >= 50:
            return RiskLevel.HIGH
        elif score >= 20:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


@dataclass
class PhishingAnalysisResult:
    message_id: str
    from_domain: str
    risk_score: int
    risk_level: str
    detected_anomalies: list[str] = field(default_factory=list)
    found_keywords: list[str] = field(default_factory=list)
    received_hops_count: int = 0


# --- Функції парсингу ---
def extract_domain(header_value: str | None) -> str | None:
    if not header_value:
        return None
    match = EMAIL_DOMAIN_REGEX.search(header_value)
    return match.group(1).lower() if match else None


def log_blocks(log_content: str) -> list[str]:
    """Розділяє текст логу за маркером --- MESSAGE ---"""
    blocks = log_content.split("--- MESSAGE ---")
    return [b.strip() for b in blocks if b.strip()]


def get_header_value(header_name: str, block: str) -> str | None:
    pattern = rf"^{header_name}:\s*(.+)$"
    match = re.search(pattern, block, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None


def get_all_received(block: str) -> list[str]:
    pattern = r"^Received:\s*(.+)$"
    matches = re.findall(pattern, block, re.MULTILINE | re.IGNORECASE)
    return [m.strip() for m in matches]


def parse_email_block(raw_block: str) -> EmailHeader:
    from_raw = get_header_value("From", raw_block)
    return_path_raw = get_header_value("Return-Path", raw_block)
    reply_to_raw = get_header_value("Reply-To", raw_block)

    return EmailHeader(
        raw_block=raw_block,
        message_id=get_header_value("Message-ID", raw_block),
        from_raw=from_raw,
        from_domain=extract_domain(from_raw),
        return_path_raw=return_path_raw,
        return_path_domain=extract_domain(return_path_raw),
        reply_to_raw=reply_to_raw,
        reply_to_domain=extract_domain(reply_to_raw),
        subject=get_header_value("Subject", raw_block),
        received_chain=get_all_received(raw_block),
    )


def parse_mail_log(log_path: Path) -> list[EmailHeader]:
    """Зчитує файл логу та повертає список розпарсених EmailHeader"""
    if not log_path.exists():
        raise FileNotFoundError(f"Файл логу не знайдено за шляхом: {log_path}")

    with open(log_path, "r", encoding="utf-8") as f:
        content = f.read()

    blocks = log_blocks(content)
    parsed_headers = [parse_email_block(block) for block in blocks]
    logger.info(f"Успішно розпарсено {len(parsed_headers)} листів з логу.")
    return parsed_headers


# --- Аналіз та аналітика ---
def load_suspicious_keywords(file_path: Path) -> set[str]:
    """Зчитує файл стоп-слів та повертає set із ключовими словами у нижньому регістрі."""
    if not file_path.exists():
        logger.warning(
            f"Файл стоп-слів не знайдено за шляхом {file_path}. Використовується порожній словник."
        )
        return set()

    with open(file_path, "r", encoding="utf-8") as f:
        keywords = {line.strip().lower() for line in f if line.strip()}

    logger.info(f"Завантажено {len(keywords)} стоп-слів.")
    return keywords


def analyze_email_header(
    header: EmailHeader, keywords: set[str], max_hops_threshold: int = 3
) -> PhishingAnalysisResult:
    """Проводить комплексний аналіз EmailHeader на ознаки фішингу"""
    score = 0
    anomalies = []
    found_kw = []

    msg_id = header.message_id or "UNKNOWN_ID"

    # 1. Перевірка невідповідності доменів
    if (
        header.from_domain
        and header.return_path_domain
        and header.from_domain != header.return_path_domain
    ):
        score += ThreatScore.FROM_RETURN_PATH_MISMATCH
        msg = f"Return-Path mismatch: '{header.from_domain}' vs '{header.return_path_domain}'"
        anomalies.append(msg)
        logger.debug(f"[{msg_id}] {msg}")

    if (
        header.from_domain
        and header.reply_to_domain
        and header.from_domain != header.reply_to_domain
    ):
        score += ThreatScore.FROM_REPLY_TO_MISMATCH
        msg = f"Reply-To mismatch: '{header.from_domain}' vs '{header.reply_to_domain}'"
        anomalies.append(msg)
        logger.debug(f"[{msg_id}] {msg}")

    # 2. Пошук стоп-слів у Subject
    if header.subject:
        subject_lower = header.subject.lower()
        for kw in keywords:
            pattern = rf"\b{re.escape(kw)}\b"
            if re.search(pattern, subject_lower):
                found_kw.append(kw)

        if found_kw:
            score += ThreatScore.SUSPICIOUS_KEYWORD_MATCH * len(found_kw)
            anomalies.append(
                f"Suspicious subject keywords found: {', '.join(found_kw)}"
            )
            logger.debug(f"[{msg_id}] Знайдено стоп-слова в Subject: {found_kw}")

    # 3. Перевірка кількості hops
    hops_count = len(header.received_chain)
    if hops_count > max_hops_threshold:
        score += ThreatScore.EXCESSIVE_RECEIVED_HOPS
        msg = f"Excessive Received hops ({hops_count} > {max_hops_threshold})"
        anomalies.append(msg)
        logger.debug(f"[{msg_id}] {msg}")

    risk_lvl = RiskLevel.evaluate(score)

    if risk_lvl == RiskLevel.HIGH:
        logger.warning(
            f"HIGH RISK EMAIL detected! Message-ID: {msg_id}, Score: {score}"
        )

    return PhishingAnalysisResult(
        message_id=msg_id,
        from_domain=header.from_domain or "UNKNOWN_DOMAIN",
        risk_score=score,
        risk_level=risk_lvl,
        detected_anomalies=anomalies,
        found_keywords=found_kw,
        received_hops_count=hops_count,
    )


# --- Логування та звітність ---
def setup_logging(debug_mode: bool) -> None:
    """Налаштовує систему логування модуля logging"""
    log_level = logging.DEBUG if debug_mode else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def generate_csv_report(
    results: list[PhishingAnalysisResult], output_path: Path
) -> None:
    """Записує результати аналізу листів у CSV-файл."""
    fieldnames = [
        "message_id",
        "from_domain",
        "risk_score",
        "risk_level",
        "received_hops_count",
        "found_keywords",
        "detected_anomalies",
    ]

    try:
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for res in results:
                writer.writerow(
                    {
                        "message_id": res.message_id,
                        "from_domain": res.from_domain,
                        "risk_score": res.risk_score,
                        "risk_level": res.risk_level,
                        "received_hops_count": res.received_hops_count,
                        "found_keywords": ", ".join(res.found_keywords)
                        if res.found_keywords
                        else "None",
                        "detected_anomalies": " | ".join(res.detected_anomalies)
                        if res.detected_anomalies
                        else "None",
                    }
                )
        logger.info(f"Звіт успішно збережено до: {output_path}")

    except (OSError, csv.Error) as e:
        logger.error(f"Помилка при записі CSV-звіту: {e}")


# --- CLI та резолвінг шляхів ---
def setup_argparser() -> argparse.ArgumentParser:
    """Створює об'єкт-парсер для CLI аргументів"""
    parser = argparse.ArgumentParser(
        description="Утиліта для оцінки поштових логів на наявність ознак фішингу"
    )

    parser.add_argument(
        "-l",
        "--mail-log",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="Шлях до файлу з дампами хедерів листів",
    )
    parser.add_argument(
        "-s",
        "--suspicious-keywords",
        type=Path,
        default=DEFAULT_KEYWORD_PATH,
        help="Шлях до txt-файлу зі словником стоп-слів",
        dest="sus_words",
    )
    parser.add_argument(
        "-o",
        "--out-csv",
        type=Path,
        default=DEFAULT_OUT_CSV,
        help="Шлях для збереження CSV-звіту",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Ввімкнути розширений рівень логування (DEBUG)",
    )

    return parser


def resolve_path(provided_path: Path) -> Path:
    """Перетворює відносний шлях на абсолютний відносно BASE_DIR та резолвить його"""
    if not provided_path.is_absolute():
        return (BASE_DIR / provided_path).resolve()
    return provided_path.resolve()


def resolve_paths(args: argparse.Namespace) -> None:
    """Нормалізує всі шляхи у переданих аргументах CLI"""
    args.mail_log = resolve_path(args.mail_log)
    args.sus_words = resolve_path(args.sus_words)
    args.out_csv = resolve_path(args.out_csv)


def output_path_validate(csv_path: Path) -> Path:
    """Створює проміжну папку, якщо її не існує"""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    return csv_path


# --- Головний потік виконання ---
if __name__ == "__main__":
    parser = setup_argparser()
    args = parser.parse_args()

    # 1. Ініціалізація логування
    setup_logging(args.debug)

    # 2. Підготовка шляхів
    resolve_paths(args)
    output_path_validate(args.out_csv)

    # 3. Виконання аналізу
    try:
        parsed_emails = parse_mail_log(args.mail_log)
        keywords = load_suspicious_keywords(args.sus_words)

        analysis_results = [
            analyze_email_header(header, keywords) for header in parsed_emails
        ]

        # 4. Генерація звіту
        generate_csv_report(analysis_results, args.out_csv)

    except Exception as err:
        logger.critical(
            f"Критична помилка виконання скрипта: {err}", exc_info=args.debug
        )
