from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..config import Settings
from ..github.adapter import GitHubRepositoryAdapter
from ..github.client import GitHubAppClient
from ..services.reviews import ReviewService
from .webhooks import router as webhook_router
from .reviews import router as reviews_router


def create_app(settings: Settings | None = None, review_service: ReviewService | None = None) -> FastAPI:
    app = FastAPI(title="ClearMerge API", version="0.1.0")
    app.state.settings = settings or Settings.from_env()
    if review_service is None:
        github_adapter = None
        if app.state.settings.github_app_id and app.state.settings.private_key():
            github_adapter = GitHubRepositoryAdapter(GitHubAppClient(app.state.settings))
        review_service = ReviewService(app.state.settings, github=github_adapter)
    app.state.review_service = review_service

    @app.middleware("http")
    async def limit_webhook_body(request: Request, call_next):
        if request.url.path == "/webhooks/github":
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > app.state.settings.max_webhook_body_bytes:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz():
        return {"status": "ready", "worker_mode": app.state.settings.review_worker_mode}

    app.include_router(webhook_router)
    app.include_router(reviews_router)
    return app


app = create_app()
