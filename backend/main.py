from fastapi import FastAPI

app = FastAPI(
    title="Argus API",
    version="0.1.0",
    description="AI-powered Threat Detection & Security Analytics Platform"
)


@app.get("/")
def root():
    return {
        "message": "Argus API is running"
    }
