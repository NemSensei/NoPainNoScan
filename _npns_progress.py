"""_npns_progress.py — shared progress emitter for NoPainNoScan scripts.

Standalone scripts at the project root import this helper to emit machine-readable
progress lines on stdout. The web UI's job runner parses them to drive a per-run
progress bar; on a plain CLI run the lines are harmless (and can be filtered).

Because a script launched as ``python3 /path/check_xxx.py`` puts its own directory
first on ``sys.path``, this sibling module imports with no PYTHONPATH/cwd setup.
Every script guards the import with try/except so it still runs if this file is
absent (progress simply becomes a no-op).

Line format (one JSON object per line):

    @@PROGRESS {"step": 2, "steps": 4, "label": "...", "host": 7, "hosts": 20}

``host``/``hosts`` are optional and describe sub-progress within a step (only
emitted by scripts that loop over hosts in Python; tool-delegated steps omit them).
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Optional

_STEP_RE = re.compile(r"STEP\s+(\d+)")

#: Prefix the runner matches on. Kept here so producer and consumer agree.
PREFIX = "@@PROGRESS "

#: Progress lines are only useful to the web UI. The runner sets this env var so
#: they are emitted there and NEVER pollute an interactive CLI run.
_ENV_FLAG = "NPNS_PROGRESS"


def emit_progress(
    step: int,
    steps: int,
    label: Optional[str] = None,
    host: Optional[int] = None,
    hosts: Optional[int] = None,
) -> None:
    """Write one progress line to stdout (only when enabled). Never raises."""
    if not os.environ.get(_ENV_FLAG):
        return
    try:
        payload: dict = {"step": int(step), "steps": int(steps)}
        if label:
            payload["label"] = str(label)
        if host is not None:
            payload["host"] = int(host)
        if hosts is not None:
            payload["hosts"] = int(hosts)
        sys.stdout.write(PREFIX + json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    except Exception:
        # Progress is best-effort; never let it break a scan.
        pass


def step_number(step_name: Optional[str], default: int = 0) -> int:
    """Extract the integer N from a 'STEP N — ...' label, else `default`."""
    m = _STEP_RE.search(step_name or "")
    return int(m.group(1)) if m else default
