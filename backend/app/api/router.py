from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def root():
    return {
        "message": "Argus API is running"
    }
