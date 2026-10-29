import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from labs.lab03.config import SUBJECT_AREA, THRESHOLD, UNIT
from labs.lab03.routers import categories, records
from labs.lab03.seed import seed_database
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Налаштування логера
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)  # цим логером можна скористатися в іншій програмі


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Запуск вебзастосунку uvicorn")
    seed_database()
    yield


app = FastAPI(
    title=f"Lab 03 API - {SUBJECT_AREA}",
    description=f"Сервіс обліку (Варіант 12). Одиниця вимірювання: {UNIT}, поріг: {THRESHOLD}.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/student")
def get_student():
    return {"student": STUDENT_NAME, "group": GROUP_NAME, "variant": VARIANT_NUMBER}
