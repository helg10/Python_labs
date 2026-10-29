import sqlite3

from fastapi import APIRouter, HTTPException, status
from labs.lab03 import repository
from labs.lab03.database import DATABASE_PATH
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.get("", response_model=list[CategoryRead])
def list_categories():
    return repository.get_categories(DATABASE_PATH)


@router.post("", response_model=CategoryRead, status_code=status.HTTP_201_CREATED)
def create_category(payload: CategoryCreate):
    try:
        return repository.create_category(DATABASE_PATH, payload.name)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Категорія з такою назвою вже існує або порушено обмеження.",
        )


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(category_id: int):
    if category_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, details="Некоректний ID."
        )

    cats = repository.get_categories(DATABASE_PATH)
    exists = any(c["id"] == category_id for c in cats)
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Категорію не знайдено."
        )

    try:
        success = repository.delete_category(DATABASE_PATH, category_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Неможливо видалити категорію, яка містить записи (ON DELETE RESTRICT).",
            )
    except sqlite3.Error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Категорія містить записи або пов'язана іншими обмеженнями.",
        )
