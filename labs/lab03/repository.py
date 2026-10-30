import sqlite3
from contextlib import closing
from pathlib import Path

# Власний виняток та методи для запиту в бд даних


class ConnectionFailed(Exception):
    """## Помилка з'єднання
    Викликається тоді, коли з'єднання не вдале. Не вдалим вважається з'єднання,
    в результаті якого отримано помилку sqlite3.Error або ж виконання команди нижче неуспішне:
    ` PRAGMA foreign_keys = ON `"""


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Відкрити з'єднання з базою та налаштувати його."""
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.row_factory = sqlite3.Row
        return connection
    except sqlite3.Error as e:
        connection.close()
        raise ConnectionFailed(
            f"Не вдалося підготувати правильне підключення для роботи з БД: {e}"
        )


def get_categories(db_path: Path) -> list[dict]:
    with closing(get_connection(db_path)) as conn:
        cursor = conn.execute("SELECT id, name FROM categories ORDER BY id ASC")
        return [dict(row) for row in cursor.fetchall()]


def create_category(db_path: Path, name: str) -> dict:
    with closing(get_connection(db_path)) as conn:
        with conn:
            cursor = conn.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            cat_id = cursor.lastrowid
        return {"id": cat_id, "name": name}


def delete_category(db_path: Path, category_id: int) -> bool:
    with closing(get_connection(db_path)) as conn:
        with conn:
            cursor = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        return cursor.rowcount > 0


def get_record_by_id(db_path: Path, record_id: int) -> dict | None:
    with closing(get_connection(db_path)) as conn:
        with conn:
            cursor = conn.execute(
                """
                SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name as category_name
                FROM records r
                JOIN categories c ON r.category_id = c.id
                WHERE r.id = ?
                """,
                (record_id,),
            )
            row = cursor.fetchone()
        return dict(row) if row else None


def get_filtered_records(
    db_path: Path,
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    max_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    with get_connection(db_path) as conn:
        query = """
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name as category_name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE 1=1
        """
        params = []

        if category_id is not None:
            query += " AND r.category_id = ?"
            params.append(category_id)

        if status is not None:
            query += " AND r.status = ?"
            params.append(status)

        if min_value is not None:
            query += " AND r.value >= ?"
            params.append(min_value)

        if max_value is not None:
            query += " AND r.value <= ?"
            params.append(max_value)

        if q is not None:
            query += " AND instr(r.title, ?) > 0"
            params.append(q)

        query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]


def create_record(db_path: Path, data: dict) -> dict:
    with get_connection(db_path) as conn:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO records(code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    data["code"],
                    data["title"],
                    data["category_id"],
                    data["value"],
                    data["status"],
                ),
            )
            record_id = cursor.lastrowid
        return get_record_by_id(db_path, record_id)


def update_record(db_path: Path, record_id: int, data: dict) -> dict | None:
    with closing(get_connection(db_path)) as conn:
        with conn:
            cursor = conn.execute(
                """
                UPDATE records
                SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                WHERE id = ?
                """,
                (
                    data["code"],
                    data["title"],
                    data["category_id"],
                    data["value"],
                    data["status"],
                    record_id,
                ),
            )
        if cursor.rowcount == 0:
            return None
    return get_record_by_id(db_path, record_id)


def delete_record(db_path: Path, record_id: int) -> bool:
    with closing(get_connection(db_path)) as conn:
        with conn:
            cursor = conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        return cursor.rowcount > 0


def create_records_bulk(db_path: Path, records_list: list[dict]) -> list[dict]:
    with closing(get_connection(db_path)) as conn:
        with conn:
            inserted_ids = []
            for item in records_list:
                cursor = conn.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        item["code"],
                        item["title"],
                        item["category_id"],
                        item["value"],
                        item["status"],
                    ),
                )
                inserted_ids.append(cursor.lastrowid)
        result = []
        for rid in inserted_ids:
            cursor = conn.execute(
                """
                SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name AS category_name
                FROM records r
                JOIN categories c ON r.category_id = c.id
                WHERE r.id = ?
                """,
                (rid,),
            )
            row = cursor.fetchone()
            if row:
                result.append(dict(row))
        return result
