# app/middleware/rate_limit.py

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from app.core.redis import redis_client

class RateLimiterMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        async with redis_client.client() as conn:
            request_count = await conn.get(client_ip)

            if request_count is None:
                await conn.set(client_ip, 1, ex=60)  # Limit to 60 requests per minute
            elif int(request_count) >= 60:
                return Response("Too Many Requests", status_code=429)
            else:
                await conn.incr(client_ip)

        response = await call_next(request)
        return response
