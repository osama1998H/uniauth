# app/main.py
import logging
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from app.middleware.rate_limit import RateLimiterMiddleware


from app.api.v1.api import api_router
from app.core.config import settings

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

try:
    app = FastAPI(title=settings.PROJECT_NAME)

    app.add_middleware(RateLimiterMiddleware)


    # Set CORS policies
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Adjust in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router, prefix=settings.API_V1_STR)
except Exception as e:
    logger.exception("Failed to start the application.")
    raise e
