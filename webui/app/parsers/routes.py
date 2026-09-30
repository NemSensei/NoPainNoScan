"""routes.py - API endpoints exposing the parsed scan results (Agent 3).

These read-only endpoints turn stored runs/campaigns into the structured JSON
described in ``outputs.py``. They are the contract the dashboard front-end
(Agent 4) and the final report (Agent 5) consume.

    GET /api/runs/{run_id}/results
        parse_run() for that run. 404 if the run id is unknown.

    GET /api/campaigns/{campaign_id}/results
        parse_campaign() aggregating every run of the campaign.

Optional query filters on both endpoints:
    ?service=smb          keep only findings of that service (repeatable)
    ?severity=critical    keep only findings of that severity (repeatable)
Filtering never changes the reported counters/totals (those describe the full
scan); it only narrows the returned ``findings`` list.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

from ..campaigns.store import get_run
from .outputs import SEVERITY_ORDER, parse_campaign, parse_run

router = APIRouter(prefix="/api", tags=["results"])


def _filter_findings(findings: list[dict[str, Any]],
                     services: Optional[list[str]],
                     severities: Optional[list[str]]) -> list[dict[str, Any]]:
    """Return the subset of findings matching the given service/severity sets."""
    svc_set = {s.lower() for s in services} if services else None
    sev_set = {s.lower() for s in severities} if severities else None
    out = findings
    if svc_set is not None:
        out = [f for f in out if f.get("service", "").lower() in svc_set]
    if sev_set is not None:
        out = [f for f in out if f.get("severity", "").lower() in sev_set]
    return out


@router.get("/runs/{run_id}/results")
def run_results(
    run_id: int,
    service: Optional[list[str]] = Query(default=None),
    severity: Optional[list[str]] = Query(
        default=None,
        description=f"One of: {', '.join(SEVERITY_ORDER)}",
    ),
) -> dict[str, Any]:
    """Structured findings for a single run (looked up in the store)."""
    run = get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")

    result = parse_run(run.get("output_dir"), run.get("check_id", ""))
    # Echo store metadata useful to the UI.
    result["run_id"] = run_id
    result["campaign_id"] = run.get("campaign_id")
    result["status"] = run.get("status")
    result["target"] = run.get("target")

    if service or severity:
        result["findings"] = _filter_findings(result["findings"], service, severity)
    return result


@router.get("/campaigns/{campaign_id}/results")
def campaign_results(
    campaign_id: int,
    service: Optional[list[str]] = Query(default=None),
    severity: Optional[list[str]] = Query(
        default=None,
        description=f"One of: {', '.join(SEVERITY_ORDER)}",
    ),
) -> dict[str, Any]:
    """Aggregated structured findings for a whole campaign."""
    result = parse_campaign(campaign_id)
    if service or severity:
        result["findings"] = _filter_findings(result["findings"], service, severity)
    return result
