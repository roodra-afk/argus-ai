from fastapi import FastAPI

from app.api.router import router

app = FastAPI(
    title="Argus API",
    version="0.1.0",
    description="AI-powered Threat Detection & Security Analytics Platform"
)


app.include_router(router) 
