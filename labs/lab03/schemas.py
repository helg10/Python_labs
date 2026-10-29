# Перевірка даних
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CategoryCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )
    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    id: int = Field(gt=0)


class RecordCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )
    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(ge=0, le=100, allow_inf_nan=False)
    status: Literal["new", "in_progress", "done"]


class RecordReplace(RecordCreate):
    pass


class RecordRead(RecordCreate):
    id: int = Field(gt=0)
    category_name: str = Field(min_length=2, max_length=40)
