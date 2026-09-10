import json
import logging
from typing import Any
import redis.asyncio as aioredis
from app.core.config import settings

logger = logging.getLogger("gateway.redis")

# Default Redis URL if not specified
REDIS_URL = getattr(settings, "redis_url", "redis://localhost:6379/0")

_redis_client: aioredis.Redis | None = None
_in_memory_cache: dict[str, Any] = {}


async def get_redis() -> aioredis.Redis | None:
    global _redis_client
    if _redis_client is None:
        try:
            client = aioredis.from_url(
                REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=2,
            )
            await client.ping()
            _redis_client = client
            logger.info("Connected to Redis successfully.")
        except Exception as exc:
            logger.warning(f"Redis unavailable ({exc}). Using in-memory fallback for ephemeral state.")
            _redis_client = None
    return _redis_client


async def close_redis() -> None:
    global _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.aclose()
        except Exception:
            pass
        _redis_client = None


async def set_ephemeral_state(key: str, data: dict[str, Any], expire_seconds: int = 3600) -> None:
    """
    Store ephemeral job/pipeline state in Redis, falling back to memory.
    """
    client = await get_redis()
    serialized = json.dumps(data)
    if client is not None:
        try:
            await client.set(key, serialized, ex=expire_seconds)
            return
        except Exception as exc:
            logger.warning(f"Redis write error ({exc}). Falling back to memory.")

    _in_memory_cache[key] = data


async def get_ephemeral_state(key: str) -> dict[str, Any] | None:
    """
    Retrieve ephemeral state.
    """
    client = await get_redis()
    if client is not None:
        try:
            val = await client.get(key)
            if val is not None:
                return json.loads(val)
        except Exception as exc:
            logger.warning(f"Redis read error ({exc}).")

    return _in_memory_cache.get(key)


async def publish_pipeline_event(channel: str, event: dict[str, Any]) -> None:
    """
    Publish event to Redis pub/sub channel.
    """
    client = await get_redis()
    if client is not None:
        try:
            await client.publish(channel, json.dumps(event))
        except Exception as exc:
            logger.warning(f"Redis publish error ({exc}).")
