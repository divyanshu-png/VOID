import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router
from app.core import config
from app.core.sandbox import active_backend, docker_available

app = FastAPI(title="VOID - Autonomous Security Review Agent", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "VOID-backend",
        "model": "stub (no LLM)" if config.STUB_LLM else config.GEMINI_MODEL,
        "stub_llm": config.STUB_LLM,
        "api_key_configured": bool(config.GEMINI_API_KEY),
        "endpoint": "vertex-ai" if config.USE_VERTEXAI else "gemini-api",
        "oracle_mode": config.ORACLE_MODE,
        "max_retries": config.MAX_RETRIES,
        "sandbox": active_backend(),
        "docker_image_ready": docker_available(),
    }


# Serve the built web UI (frontend/dist) at / when it exists.
_dist = config.ROOT_DIR / "frontend" / "dist"
if _dist.exists():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="ui")


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT, reload=True)
