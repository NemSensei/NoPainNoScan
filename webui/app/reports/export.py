"""export.py - Campaign / run report generation and export (Agent 5).

This module turns the flat scan outputs produced by the standalone check
scripts into a self-contained HTML report (and, best-effort, a PDF).

Rendering engine
----------------
Rather than re-implementing the HTML layer, we reuse the authoritative
``generate_report.py`` living at the project root. We *import* its pure
functions (``collect`` -> ``get_criticals`` -> ``generate_html``) instead of
shelling out to ``python3 generate_report.py``. Importing is chosen because:

  * ``generate_report.py`` guards its CLI behind ``if __name__ == "__main__"``,
    so importing it has no side effects.
  * We get real Python exceptions instead of having to parse a subprocess's
    stdout / exit code, and we do not depend on a ``python3`` binary being on
    PATH inside the server's environment.
  * We keep full control of the *input directory* we feed it, which is the
    crux of the multi-run aggregation problem below.

Multi-run aggregation strategy
------------------------------
``generate_report.py`` scans ONE directory recursively and, for every known
output filename (e.g. ``smb_unsigned.txt``), picks a single file. A campaign
however has one ``output_dir`` per run, and two runs of the *same* service
(e.g. two SMB scans on different subnets) both write ``smb_unsigned.txt``.

We therefore build a fresh aggregation directory under
``DATA_DIR/reports/<campaign_id>/aggregate/`` and copy every ``done`` run's
outputs into it, resolving name collisions **non-destructively**:

  * text files (``*.txt`` and any other utf-8-decodable file): the colliding
    file's lines are *unioned* into the canonical file (order preserved,
    duplicates dropped) so findings from every run are merged, never lost;
  * ``ports_summary.json`` and other ``{host: [ports]}`` JSON: the dicts are
    deep-merged (port lists unioned per host);
  * anything that cannot be merged (binary / unparseable JSON) is preserved
    verbatim under a suffixed name (``name.dup_run<id>.ext``) so nothing is
    destroyed, while not shadowing the canonical file in the recursive glob.

An empty campaign (no runs, or no ``done`` run with usable output) yields an
empty aggregation directory, which ``collect()`` turns into a clean "nothing
scanned" report -- no crash.
"""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..campaigns.store import get_campaign, get_run, list_runs
from ..config import DATA_DIR, PROJECT_ROOT

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
REPORTS_DIR = DATA_DIR / "reports"

#: Install hint surfaced to the caller when no PDF backend is available.
PDF_INSTALL_HINT = (
    "PDF export requires an optional backend. Install one of:\n"
    "  pip install -r webui/requirements-report-optional.txt   (weasyprint)\n"
    "or install the 'wkhtmltopdf' system package. "
    "The HTML report was produced instead."
)


# --------------------------------------------------------------------------- #
# Result type
# --------------------------------------------------------------------------- #
@dataclass
class ReportResult:
    """Outcome of a report build.

    Attributes:
        path:          the file actually produced on disk.
        fmt:           the format actually produced ("html" or "pdf").
        requested_fmt: the format the caller asked for.
        pdf_available: whether a PDF backend was found (only meaningful when a
                       PDF was requested).
        message:       human-readable note (e.g. the install hint when a PDF
                       was requested but could not be produced).
    """

    path: Path
    fmt: str
    requested_fmt: str
    pdf_available: bool = False
    message: str = ""


# --------------------------------------------------------------------------- #
# generate_report.py import (lazy, cached)
# --------------------------------------------------------------------------- #
_gen_mod: Any = None


def _load_generator() -> Any:
    """Import the project-root ``generate_report`` module (cached)."""
    global _gen_mod
    if _gen_mod is not None:
        return _gen_mod
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    _gen_mod = importlib.import_module("generate_report")
    return _gen_mod


# --------------------------------------------------------------------------- #
# Aggregation helpers
# --------------------------------------------------------------------------- #
def _read_text(path: Path) -> Optional[str]:
    """Return the file's text, or None if it is not utf-8/text-decodable."""
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return None


def _merge_text(dest: Path, src_text: str) -> None:
    """Union the lines of ``src_text`` into the existing ``dest`` file."""
    existing = dest.read_text(encoding="utf-8", errors="replace").splitlines()
    seen = set(existing)
    merged = list(existing)
    for line in src_text.splitlines():
        if line not in seen:
            merged.append(line)
            seen.add(line)
    dest.write_text("\n".join(merged) + ("\n" if merged else ""),
                    encoding="utf-8")


def _merge_json(dest: Path, src_text: str) -> bool:
    """Deep-merge a ``{host: [ports]}``-style JSON file. True on success.

    Deux formes gérées par hôte : ``[ports]`` (ancien format) et
    ``{"tcp": [...], "udp": [...]}`` (nouveau format, protocole préservé) —
    les dicts sont fusionnés récursivement, sinon la valeur d'un run
    écraserait celle des runs précédents (perte silencieuse de ports).
    """
    try:
        a = json.loads(dest.read_text(encoding="utf-8", errors="replace"))
        b = json.loads(src_text)
    except (json.JSONDecodeError, OSError):
        return False
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False

    def _union(dst: Any, src: Any) -> Any:
        if isinstance(dst, dict) and isinstance(src, dict):
            for k, v in src.items():
                dst[k] = _union(dst[k], v) if k in dst else v
            return dst
        if isinstance(dst, list) and isinstance(src, list):
            seen = set(dst)
            return dst + [x for x in src if x not in seen]
        return src

    _union(a, b)
    dest.write_text(json.dumps(a), encoding="utf-8")
    return True


def _absorb_run(run_id: int, src_dir: Path, dst_dir: Path) -> int:
    """Copy every file of ``src_dir`` (recursively) into flat ``dst_dir``.

    Returns the number of source files processed. Name collisions are merged
    non-destructively (see module docstring).
    """
    if not src_dir.exists() or not src_dir.is_dir():
        return 0
    count = 0
    for src in sorted(src_dir.rglob("*")):
        if not src.is_file():
            continue
        count += 1
        dest = dst_dir / src.name
        if not dest.exists():
            shutil.copy2(src, dest)
            continue
        # Collision: merge non-destructively.
        text = _read_text(src)
        if text is None:
            # Binary / undecodable: preserve verbatim under a suffixed name.
            suffixed = dst_dir / f"{src.stem}.dup_run{run_id}{src.suffix}"
            i = 1
            while suffixed.exists():
                suffixed = dst_dir / f"{src.stem}.dup_run{run_id}_{i}{src.suffix}"
                i += 1
            shutil.copy2(src, suffixed)
            continue
        if src.suffix.lower() == ".json":
            if _merge_json(dest, text):
                continue
            # Unmergeable JSON: preserve verbatim so nothing is lost.
            suffixed = dst_dir / f"{src.stem}.dup_run{run_id}{src.suffix}"
            i = 1
            while suffixed.exists():
                suffixed = dst_dir / f"{src.stem}.dup_run{run_id}_{i}{src.suffix}"
                i += 1
            shutil.copy2(src, suffixed)
            continue
        _merge_text(dest, text)
    return count


def _campaign_report_dir(campaign_id: int) -> Path:
    return REPORTS_DIR / str(campaign_id)


def _fresh_dir(path: Path) -> Path:
    """Remove ``path`` if present and recreate it empty."""
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _aggregate_campaign(campaign_id: int) -> tuple[Path, int, int]:
    """Build the aggregation dir for a campaign.

    Returns (aggregate_dir, n_runs_absorbed, n_files_absorbed). Only runs with
    status == 'done' and a real, existing output_dir contribute.
    """
    agg = _fresh_dir(_campaign_report_dir(campaign_id) / "aggregate")
    runs = list_runs(campaign_id)
    n_runs = 0
    n_files = 0
    for run in runs:
        if (run.get("status") or "").lower() != "done":
            continue
        out = run.get("output_dir")
        if not out:
            continue
        src = Path(out)
        got = _absorb_run(int(run["id"]), src, agg)
        if got:
            n_runs += 1
            n_files += got
    return agg, n_runs, n_files


# --------------------------------------------------------------------------- #
# HTML rendering
# --------------------------------------------------------------------------- #
def _render_html(scan_dir: Path, name: str) -> str:
    """Render the report HTML for the contents of ``scan_dir``."""
    gen = _load_generator()
    d = gen.collect(scan_dir)
    crits = gen.get_criticals(d)
    return gen.generate_html(d, crits, name, str(scan_dir.resolve()))


def _slugify(value: str) -> str:
    keep = "".join(c if (c.isalnum() or c in "-_") else "_" for c in value)
    return keep.strip("_") or "report"


# --------------------------------------------------------------------------- #
# PDF conversion (best-effort)
# --------------------------------------------------------------------------- #
def pdf_backend() -> Optional[str]:
    """Return the name of an available PDF backend, or None.

    Order of preference: weasyprint (pure-python, high fidelity) then the
    ``wkhtmltopdf`` binary.
    """
    try:
        importlib.import_module("weasyprint")
        return "weasyprint"
    except Exception:  # noqa: BLE001 - any import failure means "not usable"
        pass
    if shutil.which("wkhtmltopdf"):
        return "wkhtmltopdf"
    return None


def _html_to_pdf(html: str, html_path: Path, pdf_path: Path) -> bool:
    """Convert HTML to PDF using whichever backend is available. True on ok."""
    backend = pdf_backend()
    if backend == "weasyprint":
        try:
            weasyprint = importlib.import_module("weasyprint")
            weasyprint.HTML(string=html, base_url=str(html_path.parent)).write_pdf(
                str(pdf_path)
            )
            return pdf_path.exists() and pdf_path.stat().st_size > 0
        except Exception:  # noqa: BLE001 - degrade to "unavailable"
            return False
    if backend == "wkhtmltopdf":
        try:
            proc = subprocess.run(
                ["wkhtmltopdf", "--quiet", str(html_path), str(pdf_path)],
                capture_output=True,
                timeout=120,
            )
            return (
                proc.returncode == 0
                and pdf_path.exists()
                and pdf_path.stat().st_size > 0
            )
        except Exception:  # noqa: BLE001
            return False
    return False


# --------------------------------------------------------------------------- #
# Core builder
# --------------------------------------------------------------------------- #
def _build(scan_dir: Path, out_dir: Path, name: str,
           fmt: str, basename: str) -> ReportResult:
    """Render HTML from ``scan_dir`` and materialise it in ``out_dir``.

    Always writes the HTML. If ``fmt == 'pdf'`` and a backend is available,
    also writes and returns the PDF; otherwise degrades to the HTML file with
    ``pdf_available == False``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    fmt = (fmt or "html").lower()

    html = _render_html(scan_dir, name)
    html_path = out_dir / f"{basename}.html"
    html_path.write_text(html, encoding="utf-8")

    if fmt != "pdf":
        return ReportResult(path=html_path, fmt="html", requested_fmt="html")

    pdf_path = out_dir / f"{basename}.pdf"
    if _html_to_pdf(html, html_path, pdf_path):
        return ReportResult(
            path=pdf_path, fmt="pdf", requested_fmt="pdf",
            pdf_available=True,
            message="PDF generated.",
        )
    return ReportResult(
        path=html_path, fmt="html", requested_fmt="pdf",
        pdf_available=False,
        message=PDF_INSTALL_HINT,
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def build_campaign_report_result(campaign_id: int, name: Optional[str] = None,
                                 fmt: str = "html") -> ReportResult:
    """Build a campaign report and return the full :class:`ReportResult`.

    Raises ValueError if the campaign id is unknown.
    """
    campaign = get_campaign(campaign_id)
    if campaign is None:
        raise ValueError(f"campaign {campaign_id} not found")

    report_name = name or campaign.get("name") or f"Campaign {campaign_id}"
    agg, _n_runs, _n_files = _aggregate_campaign(campaign_id)
    basename = f"campaign_{campaign_id}_{_slugify(report_name)}"
    return _build(agg, _campaign_report_dir(campaign_id), report_name, fmt, basename)


def build_campaign_report(campaign_id: int, name: Optional[str] = None,
                          fmt: str = "html") -> Path:
    """Aggregate a campaign's run outputs, generate the report, return its path.

    The produced file lives under ``DATA_DIR/reports/<campaign_id>/``. When a
    PDF is requested but no backend is available, the returned path is the
    HTML file (see :func:`build_campaign_report_result` for the PDF flag).
    """
    return build_campaign_report_result(campaign_id, name=name, fmt=fmt).path


def build_run_report_result(run_id: int, name: Optional[str] = None,
                            fmt: str = "html") -> ReportResult:
    """Build a single-run report and return the full :class:`ReportResult`.

    Raises ValueError if the run id is unknown.
    """
    run = get_run(run_id)
    if run is None:
        raise ValueError(f"run {run_id} not found")

    report_name = name or f"Run {run_id} ({run.get('check_id', '?')})"
    out_dir = REPORTS_DIR / "runs" / str(run_id)
    # A single run needs no cross-run merge: point the generator straight at
    # the run's own output_dir (recursive glob handles nested files).
    out = run.get("output_dir")
    scan_dir = _fresh_dir(out_dir / "aggregate")
    if out:
        _absorb_run(run_id, Path(out), scan_dir)
    basename = f"run_{run_id}_{_slugify(run.get('check_id', 'report'))}"
    return _build(scan_dir, out_dir, report_name, fmt, basename)


def build_run_report(run_id: int, name: Optional[str] = None,
                     fmt: str = "html") -> Path:
    """Generate a report for one run, return the produced file path."""
    return build_run_report_result(run_id, name=name, fmt=fmt).path
