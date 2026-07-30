from fastapi import FastAPI

from app.api.router import router
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="AI-powered Threat Detection & Security Analytics Platform"
)


app.include_router(router) 
