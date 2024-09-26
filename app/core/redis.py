# app/core/redis.py

import redis.asyncio as redis
from app.core.config import settings

REDIS_URL = f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
print(f"Connecting to Redis at {REDIS_URL}")  # For debugging

redis_client = redis.from_url(
    REDIS_URL,
    encoding="utf-8",
    decode_responses=True
)
