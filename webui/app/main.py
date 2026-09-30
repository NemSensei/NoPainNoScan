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

# >>> agent2 routes
from .scanner.routes import router as scanner_router  # noqa: E402
app.include_router(scanner_router)
# <<< agent2 routes

# Static assets and templates.
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# >>> agent3 routes
from .parsers.routes import router as parsers_router  # noqa: E402
app.include_router(parsers_router)
# <<< agent3 routes

# >>> agent5 routes
from .reports.routes import router as reports_router  # noqa: E402
app.include_router(reports_router)
# <<< agent5 routes


@app.on_event("startup")
def _startup() -> None:
    """Ensure the database schema exists before serving requests."""
    init_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    """Render the home page (campaigns workspace).

    The template loads campaigns client-side via /api/campaigns; the ``checks``
    context is retained for backwards compatibility and simply ignored there.
    """
    return templates.TemplateResponse(
        request,
        "index.html",
        {"checks": list_checks()},
    )


# >>> agent4 routes
# HTML page routes for the front-end (Agent 4). These only render templates;
# all dynamic data is fetched client-side from the JSON/SSE APIs of Agents 2/3.
@app.get("/scan", response_class=HTMLResponse)
def page_scan(request: Request) -> HTMLResponse:
    """Dynamic scan-launch form + live SSE progress."""
    return templates.TemplateResponse(request, "scan.html", {})


@app.get("/dashboard", response_class=HTMLResponse)
def page_dashboard(request: Request) -> HTMLResponse:
    """Campaign results dashboard (reads /api/campaigns/{id}/results)."""
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.get("/history", response_class=HTMLResponse)
def page_history(request: Request) -> HTMLResponse:
    """Run history + simple comparison for the active campaign."""
    return templates.TemplateResponse(request, "history.html", {})


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def page_run(request: Request, run_id: int) -> HTMLResponse:
    """Single-run view: parsed findings + streamed output log."""
    return templates.TemplateResponse(request, "run.html", {"run_id": run_id})


@app.get("/checks", response_class=HTMLResponse)
def page_checks(request: Request) -> HTMLResponse:
    """Reference grid of every registered check."""
    return templates.TemplateResponse(request, "checks.html", {"checks": list_checks()})
# <<< agent4 routes


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
