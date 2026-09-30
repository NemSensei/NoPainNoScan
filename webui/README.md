# NoPainNoScan Web UI

Local, mono-user FastAPI interface for the NoPainNoScan pentest toolkit.
**Binds to 127.0.0.1 only, no authentication** — never expose it on a network.

## Stack

FastAPI + Jinja2 + HTMX + Alpine.js (via CDN) + SQLite (stdlib `sqlite3`).

## Layout

```
webui/
├── app/
│   ├── main.py            # FastAPI app: index, /api/checks, /api/health, static mount
│   ├── config.py          # Paths (PROJECT_ROOT, DATA_DIR, DB_PATH), HOST/PORT, run-dir helper
│   ├── scanner/
│   │   └── registry.py    # CheckDefinition model + REGISTRY (13 checks + discovery) + lookups
│   ├── campaigns/
│   │   └── store.py       # SQLite schema + CRUD (campaigns, runs)
│   ├── parsers/           # (Agent 3) output parsing
│   ├── reports/           # (Agent 5) HTML report integration
│   ├── templates/         # base.html + index.html
│   └── static/            # static assets
├── data/                  # SQLite DB + per-run output workspaces
└── requirements-web.txt
```

## Run

```bash
cd webui
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-web.txt

# from the webui/ directory:
python -m app.main
# or:
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then open http://127.0.0.1:8000/ (check list) or GET http://127.0.0.1:8000/api/checks (JSON).

## Contracts for other agents

- **Registry** (`app/scanner/registry.py`): `CheckDefinition` describes every
  runnable script (id, script filename, label, description, `supports_creds`,
  `required_tools`, `optional_tools`, `needs_root`, and typed `arguments`).
  Use `list_checks()` / `get_check(id)`. Metadata only — no execution here.
- **Store** (`app/campaigns/store.py`): `init_db()`, plus CRUD for `campaigns`
  and `runs`. The `runs.status` field is a free string (queued/running/done/
  failed); transition logic belongs to the execution engine (Agent 2).
- **Config** (`app/config.py`): `PROJECT_ROOT` (repo root, where check_*.py
  live), `DATA_DIR`, `DB_PATH`, `HOST`/`PORT`, `new_run_dir(check_id)`,
  `script_path(filename)`.

## Status

**Agent 1 — foundations laid.** Skeleton, registry, SQLite store, config, and a
minimal working app are in place. Execution engine, parsers, front-end and
report export are handled by later agents.
