"""store.py - SQLite persistence for campaigns and runs.

Uses the stdlib sqlite3 module (no ORM). Schema creation is idempotent
(CREATE TABLE IF NOT EXISTS) so init_db() can be called safely at every startup.

Two tables:
    campaigns  - a named engagement (client + notes).
    runs       - one execution of one check inside a campaign.

The `status` field is a free string for now (queued/running/done/failed);
Agent 2 owns the actual transitions. CRUD helpers here return plain dicts.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..config import DB_PATH, ensure_dirs


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    client      TEXT,
    created_at  TEXT    NOT NULL,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id  INTEGER NOT NULL,
    check_id     TEXT    NOT NULL,
    target       TEXT    NOT NULL,
    params_json  TEXT,
    output_dir   TEXT,
    status       TEXT    NOT NULL DEFAULT 'queued',
    started_at   TEXT,
    finished_at  TEXT,
    exit_code    INTEGER,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_runs_campaign ON runs(campaign_id);
"""


def _now() -> str:
    """UTC ISO-8601 timestamp string."""
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Connection / init
# --------------------------------------------------------------------------- #
def get_conn(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Open a connection with Row factory and FK enforcement enabled."""
    ensure_dirs()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Create tables if they do not exist yet (idempotent migration)."""
    conn = get_conn(db_path)
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Campaign CRUD
# --------------------------------------------------------------------------- #
def create_campaign(name: str, client: Optional[str] = None,
                    notes: Optional[str] = None) -> int:
    """Insert a campaign, return its new id."""
    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO campaigns (name, client, created_at, notes) "
            "VALUES (?, ?, ?, ?)",
            (name, client, _now(), notes),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_campaigns() -> list[dict[str, Any]]:
    """Return all campaigns, newest first."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM campaigns ORDER BY created_at DESC, id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_campaign(campaign_id: int) -> Optional[dict[str, Any]]:
    """Return one campaign as dict, or None."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def add_note(campaign_id: int, note: str) -> None:
    """Append a timestamped note to a campaign's notes field."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT notes FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"campaign {campaign_id} not found")
        prev = row["notes"] or ""
        stamped = f"[{_now()}] {note}"
        merged = f"{prev}\n{stamped}" if prev else stamped
        conn.execute(
            "UPDATE campaigns SET notes = ? WHERE id = ?", (merged, campaign_id)
        )
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Run CRUD
# --------------------------------------------------------------------------- #
def create_run(campaign_id: int, check_id: str, target: str,
               params_json: Optional[str] = None,
               output_dir: Optional[str] = None,
               status: str = "queued") -> int:
    """Insert a run row, return its new id."""
    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO runs "
            "(campaign_id, check_id, target, params_json, output_dir, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (campaign_id, check_id, target, params_json, output_dir, status),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def update_run_status(run_id: int, status: str,
                      exit_code: Optional[int] = None,
                      started: bool = False, finished: bool = False) -> None:
    """Update a run's status and, optionally, timestamps / exit code.

    Pass started=True to stamp started_at, finished=True to stamp finished_at.
    exit_code is written only when provided (not None).
    """
    conn = get_conn()
    try:
        sets = ["status = ?"]
        params: list[Any] = [status]
        if started:
            sets.append("started_at = ?")
            params.append(_now())
        if finished:
            sets.append("finished_at = ?")
            params.append(_now())
        if exit_code is not None:
            sets.append("exit_code = ?")
            params.append(exit_code)
        params.append(run_id)
        conn.execute(
            f"UPDATE runs SET {', '.join(sets)} WHERE id = ?", params
        )
        conn.commit()
    finally:
        conn.close()


def fail_stale_running_runs() -> int:
    """Mark every run still 'running'/'queued' in the DB as failed.

    Called at startup: jobs live in memory only, so after a server restart
    those rows would stay 'running' forever (no live process is attached
    anymore, and cancel_job() refuses unknown run_ids).
    """
    conn = get_conn()
    try:
        cur = conn.execute(
            "UPDATE runs SET status = 'failed', finished_at = ? "
            "WHERE status IN ('queued', 'running')",
            (_now(),),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def get_run(run_id: int) -> Optional[dict[str, Any]]:
    """Return one run as dict, or None."""
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_runs(campaign_id: int) -> list[dict[str, Any]]:
    """Return all runs of a campaign, newest first."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM runs WHERE campaign_id = ? ORDER BY id DESC",
            (campaign_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
