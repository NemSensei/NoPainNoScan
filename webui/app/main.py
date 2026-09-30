"""main.py - Minimal FastAPI application for the NoPainNoScan web UI.

Agent 1 scope: proves the foundation works.
  GET /            -> Jinja index listing the registered checks.
  GET /api/checks  -> JSON dump of the registry.
  GET /api/health  -> simple liveness probe.

Static files are mounted at /static. On startup the SQLite DB is initialised.
Run locally with:  python -m app.main   (binds 127.0.0.1 only)
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import HOST, PORT, STATIC_DIR, TEMPLATES_DIR
from .campaigns.store import init_db
from .scanner.registry import list_checks

app = FastAPI(title="NoPainNoScan Web UI", version="0.1.0")

# Static assets and templates.
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# >>> agent3 routes
from .parsers.routes import router as parsers_router  # noqa: E402
app.include_router(parsers_router)
# <<< agent3 routes


@app.on_event("startup")
def _startup() -> None:
    """Ensure the database schema exists before serving requests."""
    init_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    """Render the index page listing every registered check."""
    return templates.TemplateResponse(
        request,
        "index.html",
        {"checks": list_checks()},
    )


@app.get("/api/health")
def health() -> dict:
    """Liveness probe."""
    return {"status": "ok"}


@app.get("/api/checks")
def api_checks() -> JSONResponse:
    """Return the full registry as JSON (the contract for other agents)."""
    return JSONResponse([c.to_dict() for c in list_checks()])


def run() -> None:
    """Launch uvicorn bound to localhost only."""
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False)


if __name__ == "__main__":
    run()
