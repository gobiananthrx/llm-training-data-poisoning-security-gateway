from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.datasets import router as datasets_router
from app.api.verification import router as verification_router
from app.api.health import router as health_router
from app.api.ws import router as ws_router
from app.core.config import settings
from app.core.redis import close_redis
from app.db.database import engine
from app.db.models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure tables are created if running without prior migration
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Shutdown: Clean up connections
    await close_redis()
    await engine.dispose()


app = FastAPI(
    title="Dataset Security Gateway API",
    version="1.0.0",
    description="Post-Quantum Provenance Attestation and Multi-Agent Adversarial Threat Intelligence Gateway",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.environment == "development" else settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api")
app.include_router(datasets_router, prefix="/api")
app.include_router(verification_router, prefix="/api")
app.include_router(ws_router, prefix="/api")


@app.get("/")
async def root():
    return {
        "service": "llm-training-data-poisoning-security-gateway",
        "status": "online",
        "version": "1.0.0",
        "cryptography": "ML-DSA-65 (NIST FIPS 204)",
    }
