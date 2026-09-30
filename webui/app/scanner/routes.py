"""routes.py - API endpoints for run execution + streaming (Agent 2).

Exposes an APIRouter (prefix ``/api``) wired into app.main:

    POST /api/campaigns            create a campaign            -> {id}
    GET  /api/campaigns            list campaigns               -> [ ... ]
    POST /api/runs                 create + launch a run        -> {run_id, status}
    GET  /api/runs/{run_id}        current status (mem|store)   -> { ... }
    GET  /api/runs/{run_id}/stream Server-Sent Events log feed  -> text/event-stream
    POST /api/runs/{run_id}/cancel terminate a running job      -> {run_id, cancelled}

Result parsing (Agent 3), the front-end (Agent 4) and export (Agent 5) are out
of scope here. This module only starts work and reports live progress.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..campaigns.store import (
    create_campaign, list_campaigns, get_campaign, get_run,
)
from . import jobs
from .runner import TargetValidationError

router = APIRouter(prefix="/api", tags=["runs"])


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class CampaignCreate(BaseModel):
    name: str
    client: Optional[str] = None
    notes: Optional[str] = None


class RunCreate(BaseModel):
    campaign_id: int
    check_id: str
    target: str
    # params is keyed by argument `dest` (target/username/password/domain/...).
    params: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Campaign endpoints (minimal - enough to create runs against)
# --------------------------------------------------------------------------- #
@router.post("/campaigns")
def api_create_campaign(body: CampaignCreate) -> dict:
    """Create a campaign and return its id."""
    campaign_id = create_campaign(body.name, client=body.client, notes=body.notes)
    return {"id": campaign_id}


@router.get("/campaigns")
def api_list_campaigns() -> list[dict]:
    """List all campaigns, newest first."""
    return list_campaigns()


# --------------------------------------------------------------------------- #
# Run endpoints
# --------------------------------------------------------------------------- #
@router.post("/runs")
async def api_create_run(body: RunCreate) -> dict:
    """Create, persist and launch a run; return its run_id and status.

    400 on invalid target, 404 on unknown check, 404 on unknown campaign.
    """
    if get_campaign(body.campaign_id) is None:
        raise HTTPException(status_code=404, detail=f"campaign {body.campaign_id} not found")
    try:
        run_id = await jobs.start_job(
            campaign_id=body.campaign_id,
            check_id=body.check_id,
            target=body.target,
            params=body.params,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown check '{body.check_id}'")
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job = jobs.get_job(run_id)
    return {"run_id": run_id, "status": job.status if job else "unknown"}


@router.get("/runs/{run_id}")
def api_get_run(run_id: int) -> dict:
    """Return the current status of a run (live job first, store fallback)."""
    status = jobs.run_status(run_id)
    if status is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")
    return status


@router.post("/runs/{run_id}/cancel")
async def api_cancel_run(run_id: int) -> dict:
    """Cancel a running job. cancelled=False if it was not active."""
    if get_run(run_id) is None and jobs.get_job(run_id) is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")
    cancelled = await jobs.cancel_job(run_id)
    return {"run_id": run_id, "cancelled": cancelled}


# --------------------------------------------------------------------------- #
# SSE log stream
# --------------------------------------------------------------------------- #
def _sse(event: str, data: dict[str, Any]) -> str:
    """Format one Server-Sent Event frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _event_stream(run_id: int):
    """Async generator yielding SSE frames for a run's log feed."""
    job = jobs.get_job(run_id)

    if job is None:
        # Not tracked in memory (e.g. after a restart): replay from the store
        # as a single terminal frame so the client is not left hanging.
        row = get_run(run_id)
        if row is None:
            yield _sse("error", {"run_id": run_id, "detail": "run not found"})
            return
        yield _sse("status", {"run_id": run_id, "status": row.get("status")})
        yield _sse("end", {
            "run_id": run_id,
            "status": row.get("status"),
            "exit_code": row.get("exit_code"),
            "error": None,
        })
        return

    q = jobs.subscribe(job)
    try:
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=15.0)
            except asyncio.TimeoutError:
                # Keep the connection alive through proxies / idle periods.
                yield ": keep-alive\n\n"
                continue
            kind = msg.get("type")
            if kind == "log":
                yield _sse("log", {"line": msg["line"]})
            elif kind == "status":
                yield _sse("status", {"run_id": run_id, "status": msg["status"]})
            elif kind == "end":
                yield _sse("end", {
                    "run_id": run_id,
                    "status": msg.get("status"),
                    "exit_code": msg.get("exit_code"),
                    "error": msg.get("error"),
                })
                break
    finally:
        jobs.unsubscribe(job, q)


@router.get("/runs/{run_id}/stream")
async def api_stream_run(run_id: int) -> StreamingResponse:
    """Stream a run's logs live via Server-Sent Events (text/event-stream).

    Frames:
        event: status  data: {"run_id", "status"}
        event: log      data: {"line"}
        event: end      data: {"run_id", "status", "exit_code", "error"}
    A ``: keep-alive`` comment is emitted on idle to hold the connection open.
    """
    return StreamingResponse(
        _event_stream(run_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
