"""config.py - Centralized configuration for the NoPainNoScan web UI.

All paths are derived from this file's location so the app works regardless of
the current working directory. Deployment is strictly local, mono-user, no auth:
the server binds to 127.0.0.1 only.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
# .../webui/app/config.py  ->  APP_DIR = .../webui/app
APP_DIR = Path(__file__).resolve().parent
# .../webui
WEBUI_DIR = APP_DIR.parent
# Project root = where the standalone check_*.py scripts live (repo root).
PROJECT_ROOT = WEBUI_DIR.parent

# Per-run workspaces live under webui/data (one -o directory per run).
DATA_DIR = WEBUI_DIR / "data"
# SQLite database file.
DB_PATH = DATA_DIR / "nopainnoscan.db"

# Static assets + Jinja templates.
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"

# --------------------------------------------------------------------------- #
# Network binding (local only — never expose this UI)
# --------------------------------------------------------------------------- #
HOST = "127.0.0.1"
PORT = 8000


def ensure_dirs() -> None:
    """Create the data directory if missing (idempotent)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def new_run_dir(check_id: str) -> Path:
    """Return (and create) a fresh unique output directory for one run.

    Layout: webui/data/<check_id>_<YYYYmmdd_HHMMSS_micro>/
    The microsecond suffix guarantees uniqueness even for back-to-back runs.
    """
    ensure_dirs()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    run_dir = DATA_DIR / f"{check_id}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def script_path(script_filename: str) -> Path:
    """Return the absolute path to a standalone check script by filename."""
    return PROJECT_ROOT / script_filename
