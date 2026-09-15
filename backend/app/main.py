from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(
    title="SQL Injection Risk Detection Assistant — API",
    description=(
        "Defensive security tool for authorized testing. Discovers input "
        "surfaces (forms, fields, URL parameters) on a target page; does "
        "not exploit or submit anything."
    ),
    version="0.1.0-phase1",
)

app.include_router(router, prefix="/api/v1", tags=["discovery"])


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
