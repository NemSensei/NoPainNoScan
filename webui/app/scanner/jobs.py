"""jobs.py - In-memory async job registry + log pub/sub (Agent 2).

Ties the runner primitives to persistence and live streaming:

    * a Job holds the live state of one run (status, exit code, a bounded log
      buffer, the subprocess handle, the asyncio task, and its SSE subscribers);
    * JOBS maps run_id -> Job for every run started this process lifetime;
    * start_job() persists a run (store.create_run), flips it to running, spawns
      the child via runner, fans log lines out to subscribers, and on completion
      writes the terminal status/exit_code back to the store;
    * subscribe()/unsubscribe() implement a per-subscriber asyncio.Queue used by
      the SSE endpoint; each new subscriber first replays the buffered lines so a
      late viewer still sees the whole run;
    * cancel_job() terminates the child process.

The run_id is the single identity shared between memory and the DB: it is the
primary key returned by store.create_run() and the key of the JOBS dict. While a
job is active its authoritative status lives on the Job; once evicted (or after a
server restart) the store row is the source of truth.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from ..campaigns.store import create_run, update_run_status, get_run
from ..config import new_run_dir
from . import runner
from .registry import get_check

# Terminal statuses (no further transitions expected).
_TERMINAL = {"done", "failed", "cancelled"}

# How many log lines to retain per job for late-subscriber replay.
_LOG_BUFFER_MAX = 5000


# --------------------------------------------------------------------------- #
# Job model
# --------------------------------------------------------------------------- #
@dataclass
class Job:
    """Live state of a single run."""
    run_id: int
    campaign_id: int
    check_id: str
    target: str
    command: list[str] = field(default_factory=list)
    run_dir: Optional[str] = None
    status: str = "queued"
    exit_code: Optional[int] = None
    error: Optional[str] = None
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=_LOG_BUFFER_MAX))
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    process: Optional[asyncio.subprocess.Process] = None
    task: Optional[asyncio.Task] = None

    def snapshot(self) -> dict[str, Any]:
        """JSON-friendly view of the current job state (no heavy fields)."""
        return {
            "run_id": self.run_id,
            "campaign_id": self.campaign_id,
            "check_id": self.check_id,
            "target": self.target,
            "status": self.status,
            "exit_code": self.exit_code,
            "error": self.error,
            "run_dir": self.run_dir,
            "command": self.command,
            "log_lines": len(self.logs),
        }


# Process-wide registry: run_id -> Job.
JOBS: dict[int, Job] = {}


# --------------------------------------------------------------------------- #
# Pub/sub helpers
# --------------------------------------------------------------------------- #
def _publish(job: Job, message: dict[str, Any]) -> None:
    """Fan a message out to every current subscriber (non-blocking)."""
    for q in list(job.subscribers):
        try:
            q.put_nowait(message)
        except asyncio.QueueFull:  # pragma: no cover - queues are unbounded
            pass


def _emit_log(job: Job, line: str) -> None:
    """Buffer a log line and publish it live."""
    job.logs.append(line)
    _publish(job, {"type": "log", "line": line})


def _emit_end(job: Job) -> None:
    """Publish the terminal event describing how the job finished."""
    _publish(job, {
        "type": "end",
        "run_id": job.run_id,
        "status": job.status,
        "exit_code": job.exit_code,
        "error": job.error,
    })


def subscribe(job: Job) -> asyncio.Queue:
    """Register a new subscriber queue and prime it with backlog + state.

    The returned queue immediately contains: a ``status`` event, every buffered
    log line, and - if the job already finished - the terminal ``end`` event.
    Runs synchronously (no await) so no line can slip in between registration
    and replay.
    """
    q: asyncio.Queue = asyncio.Queue()
    q.put_nowait({"type": "status", "run_id": job.run_id, "status": job.status})
    for line in list(job.logs):
        q.put_nowait({"type": "log", "line": line})
    if job.status in _TERMINAL:
        q.put_nowait({
            "type": "end",
            "run_id": job.run_id,
            "status": job.status,
            "exit_code": job.exit_code,
            "error": job.error,
        })
    else:
        job.subscribers.add(q)
    return q


def unsubscribe(job: Job, q: asyncio.Queue) -> None:
    """Remove a subscriber queue (idempotent)."""
    job.subscribers.discard(q)


# --------------------------------------------------------------------------- #
# Job lifecycle
# --------------------------------------------------------------------------- #
def _finalize(job: Job, status: str, exit_code: Optional[int],
              error: Optional[str] = None) -> None:
    """Set terminal state on the job and persist it to the store."""
    job.status = status
    job.exit_code = exit_code
    if error:
        job.error = error
    update_run_status(job.run_id, status=status, exit_code=exit_code, finished=True)
    _emit_end(job)


async def _run(job: Job) -> None:
    """Task body: stream the child process, then write the terminal status."""
    try:
        job.process = await runner.spawn(job.command)
        async for line in runner.iter_output(job.process):
            _emit_log(job, line)
        await job.process.wait()
        code = job.process.returncode
        status = "done" if code == 0 else "failed"
        _finalize(job, status, code)
    except asyncio.CancelledError:
        # cancel_job() already terminated the process; record the outcome.
        _emit_log(job, "[job cancelled]")
        code = job.process.returncode if job.process else None
        _finalize(job, "cancelled", code)
        raise
    except Exception as exc:  # noqa: BLE001 - surface any launch/runtime error
        _emit_log(job, f"[runner error] {exc}")
        _finalize(job, "failed", None, error=str(exc))


async def start_job(campaign_id: int, check_id: str, target: str,
                    params: Optional[dict[str, Any]] = None) -> int:
    """Create, persist and launch a run. Returns its run_id.

    Flow:
        1. resolve + validate the check and target;
        2. build the argv list and allocate a per-run output directory;
        3. persist the run row (store.create_run) -> run_id;
        4. tool pre-flight: if a required tool is missing, mark the run failed
           WITHOUT spawning anything;
        5. otherwise flip to running and spawn the streaming task.

    Raises:
        KeyError:               unknown check_id.
        TargetValidationError:  invalid/empty target.
    """
    params = dict(params or {})

    check_def = get_check(check_id)
    if check_def is None:
        raise KeyError(check_id)

    runner.validate_target(target)
    params["target"] = target

    run_dir = new_run_dir(check_id)
    command = runner.build_command(check_def, params, run_dir)

    run_id = create_run(
        campaign_id=campaign_id,
        check_id=check_id,
        target=target,
        params_json=json.dumps(params),
        output_dir=str(run_dir),
        status="queued",
    )

    job = Job(
        run_id=run_id,
        campaign_id=campaign_id,
        check_id=check_id,
        target=target,
        command=command,
        run_dir=str(run_dir),
        status="queued",
    )
    JOBS[run_id] = job

    # --- Tool pre-flight: hard-fail on missing required tools, no spawn. ---
    missing_required, missing_optional = runner.check_tools(check_def)
    for tool in missing_optional:
        _emit_log(job, f"[warning] optional tool not found on PATH: {tool} "
                        "(related feature will be skipped)")
    if missing_required:
        msg = ("Missing required tool(s): " + ", ".join(missing_required)
               + ". Install them before running this check.")
        _emit_log(job, f"[error] {msg}")
        job.status = "failed"
        job.error = msg
        update_run_status(run_id, status="failed", finished=True)
        _emit_end(job)
        return run_id

    # --- Launch. ---
    job.status = "running"
    update_run_status(run_id, status="running", started=True)
    _publish(job, {"type": "status", "run_id": run_id, "status": "running"})
    job.task = asyncio.create_task(_run(job))
    return run_id


async def cancel_job(run_id: int) -> bool:
    """Terminate a running job's process. Returns True if a live job was hit."""
    job = JOBS.get(run_id)
    if job is None or job.status in _TERMINAL:
        return False
    if job.process is not None and job.process.returncode is None:
        try:
            job.process.terminate()
        except ProcessLookupError:  # pragma: no cover - already gone
            pass
    if job.task is not None:
        job.task.cancel()
    return True


# --------------------------------------------------------------------------- #
# Status lookup (memory first, store fallback)
# --------------------------------------------------------------------------- #
def get_job(run_id: int) -> Optional[Job]:
    """Return the live Job for run_id, or None if not tracked in memory."""
    return JOBS.get(run_id)


def run_status(run_id: int) -> Optional[dict[str, Any]]:
    """Return a status dict from the live job, falling back to the store.

    None means the run_id is unknown both in memory and in the database.
    """
    job = JOBS.get(run_id)
    if job is not None:
        snap = job.snapshot()
        snap["source"] = "memory"
        return snap
    row = get_run(run_id)
    if row is None:
        return None
    row["source"] = "store"
    return row
