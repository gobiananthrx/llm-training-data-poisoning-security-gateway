from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.datasets import router as datasets_router
from app.api.verification import router as verification_router
from app.api.health import router as health_router
from app.core.config import settings
from app.db.database import engine
from app.db.models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Shutdown
    await engine.dispose()


app = FastAPI(
    title="Dataset Security Gateway API",
    version="0.1.0",
    description="Cloud-ready pre-training dataset security gateway.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api")
app.include_router(datasets_router, prefix="/api")
app.include_router(verification_router, prefix="/api")


@app.get("/")
async def root():
    return {"service": "dataset-security-gateway", "version": "0.1.0"}
