import json
import logging
import sqlite3
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database
from labs.lab03.schemas import CategoryCreate, RecordCreate

BASE_DIR = Path(__file__).resolve().parent
SEED_PATH = BASE_DIR / "data" / "seed.json"

logger = logging.getLogger(__name__)

def seed_database() -> None:
    initialize_database()
    
    if not SEED_PATH.exists():
        logger.error(f"Файл seed.json не знайдено: {SEED_PATH}. Нових даних в базу не записано")
        return

    data = json.loads(SEED_PATH.read_text(encoding="utf-8"))

    # Валідація через моделі
    categories = [CategoryCreate(**cat) for cat in data.get("categories", [])]
    records = [RecordCreate(**rec) for rec in data.get("records", [])]

    with get_connection() as conn:
        # Перевірка, чи вже є дані
        cursor = conn.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] > 0:
            logger.warning("База даних вже містить дані. Повторне заповнення не виконано (дублікатів не створено).")
            return

        try:
            with conn:
                for idx, cat in enumerate(categories, start=1):
                    conn.execute(
                        "INSERT INTO categories (id, name) VALUES (?, ?)",
                        (idx, cat.name),
                    )
                for rec in records:
                    conn.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (rec.code, rec.title, rec.category_id, rec.value, rec.status),
                    )
            print("Початкові дані успішно завантажено в базу даних.")
        except sqlite3.Error as e:
            print(f"Помилка транзакції при заповненні бази: {e}")
            raise


if __name__ == "__main__":
    seed_database()