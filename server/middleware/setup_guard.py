"""
SetupGuardMiddleware

Intercepts all requests before routing and redirects to /setup when the
platform has not been configured yet (secret_key is still the default value,
or .env does not exist).

Rules:
  - /setup*                → always allowed (the wizard itself)
  - /health                → always allowed (load-balancer probes)
  - /setup/generate-key    → always allowed (called by wizard JS)
  - API requests           → return 503 JSON instead of HTML redirect
  - Everything else        → 302 redirect to /setup
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp


class SetupGuardMiddleware(BaseHTTPMiddleware):

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Always let through: setup routes, health check, static assets
        if (
            path.startswith("/setup")
            or path == "/health"
            or path.startswith("/static")
        ):
            return await call_next(request)

        from server.api.setup import setup_needed
        if not setup_needed():
            return await call_next(request)

        # Setup required — differentiate between browser and API clients
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse("/setup", status_code=302)

        # API / programmatic client
        return JSONResponse(
            {
                "error": "not_configured",
                "message": (
                    "Discoverykastle has not been configured yet. "
                    "Open the server URL in a browser to complete setup."
                ),
            },
            status_code=503,
        )
