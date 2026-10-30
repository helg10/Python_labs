import sqlite3
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, status as http_status
from labs.lab03 import repository
from labs.lab03.database import DATABASE_PATH
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace
from labs.lab03.config import THRESHOLD

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[RecordRead])
def get_records(
    category_id: int | None = Query(default=None, gt=0),
    status: Literal["new", "in_progress", "done"] | None = None,
    min_value: float | None = Query(default=None, ge=0, le=THRESHOLD),
    max_value: float | None = Query(default=None, ge=0, le=THRESHOLD),
    q: str | None = Query(default=None, min_length=1, max_length=120),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    if category_id is not None:
        cats = repository.get_categories(DATABASE_PATH)
        if not any(c["id"] == category_id for c in cats):
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND, detail="Такої категорії не існує."
                    )

    return repository.get_filtered_records(
        DATABASE_PATH,
        category_id=category_id,
        status=status,
        min_value=min_value,
        max_value=max_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/{record_id}", response_model=RecordRead)
def get_record(record_id: int):
    if record_id <= 0:
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Некоректний ID."
        )
    record = repository.get_record_by_id(DATABASE_PATH, record_id)
    if not record:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND, detail="Запис не знайдено"
        )
    return record


@router.post("", response_model=RecordRead, status_code=http_status.HTTP_201_CREATED)
def create_record(payload: RecordCreate):
    cats = repository.get_categories(DATABASE_PATH)
    if not any(c["id"] == payload.category_id for c in cats):
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND, detail="Вказана категорія не існує"
        )

    try:
        return repository.create_record(DATABASE_PATH, payload.model_dump())
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail="Дублікат унікального поля (code)",
        )


@router.put("/{record_id}", response_model=RecordRead)
def replace_record(record_id: int, payload: RecordReplace):
    if record_id <= 0:
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Некоректний ID"
        )

    cats = repository.get_categories(DATABASE_PATH)
    if not any(c["id"] == payload.category_id for c in cats):
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            details="Вказана категорія не існує",
        )

    try:
        updated = repository.update_record(
            DATABASE_PATH, record_id, payload.model_dump()
        )
        if not updated:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND, detail="Запис не знайдено"
            )
        return updated
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT, detail="Конфлікт унікальності коду"
        )


@router.delete("/{record_id}", status_code=http_status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int):
    if record_id <= 0:
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Некоректний ID."
        )
    success = repository.delete_record(DATABASE_PATH, record_id)
    if not success:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND, detail="Запис не знайдено"
        )


@router.post(
    "/bulk", response_model=list[RecordRead], status_code=http_status.HTTP_201_CREATED
)
def create_records_bulk(payload: list[RecordCreate]):
    if not (1 <= len(payload) <= 100):
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Пакет має містити від 1 до 100 елементів.",
        )

    cats = repository.get_categories(DATABASE_PATH)
    cat_ids = {c["id"] for c in cats}

    seen_codes = set()
    for item in payload:
        if item.category_id not in cat_ids:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Категорії з id={item.category_id} не існує.",
            )
        if item.code in seen_codes:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=f"Дублікат коду {item.code} всередині пакета.",
            )
        seen_codes.add(item.code)

    try:
        dicts = [p.model_dump() for p in payload]
        return repository.create_records_bulk(DATABASE_PATH, dicts)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail="Конфлікт унікальності коду в базі даних.",
        )
