"""outputs.py - Turn raw NoPainNoScan scan outputs into structured JSON.

Agent 3 scope: the DATA LAYER of the dashboard. This module reads the flat
`*.txt` / `*.json` files produced by the standalone check scripts and normalises
them into a stable JSON schema the front-end (Agent 4) and report (Agent 5)
consume. It does NOT run scans (Agent 2) and does NOT render HTML.

The file-name conventions, the recursive globbing and the line/JSON reading
helpers below are extracted and adapted from ``generate_report.py`` (the
original, authoritative parsing logic at the project root) so the two stay in
sync. Rather than importing that CLI script (which pulls in a large HTML layer
and is not import-safe), the small pieces we need are copied here and credited.

Public API
----------
    parse_run(output_dir, check_id) -> dict
        Summary + findings for a single run's output directory.
    parse_campaign(campaign_id)     -> dict
        Aggregate of every run in a campaign (global counters, findings,
        alive hosts, top ports).

Both are defensive: a missing/empty directory, absent files or malformed JSON
never raise — the relevant section is simply returned empty and marked
``scanned: false``.

Normalised finding
------------------
    {
        "service":  "smb",              # check id the finding belongs to
        "title":    "SMB signing disabled",
        "severity": "high",             # info | low | medium | high | critical
        "hosts":    ["10.0.0.1", ...],  # affected entries (IPs, or the raw
                                        #   lines when the source is not host
                                        #   based: share paths, hashes, ...)
        "count":    2,                  # len(hosts) — convenience for the UI
        "detail":   "NTLM relay possible",
    }
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from ..campaigns.store import get_campaign, list_runs
from ..scanner.registry import get_check


# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
# Ordered from most to least severe. Used for sorting and empty-counter init.
SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _empty_counts() -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    counts["total"] = 0
    return counts


# --------------------------------------------------------------------------- #
# File helpers  (adapted from generate_report.py: find_file / read_lines / jload)
# --------------------------------------------------------------------------- #
def _find_file(base: Path, name: str) -> Optional[Path]:
    """Most-recent file called ``name`` anywhere under ``base`` (or None)."""
    try:
        hits = sorted(base.rglob(name), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return None
    return hits[0] if hits else None


def _find_files(base: Path, pattern: str) -> list[Path]:
    """All files matching ``pattern`` under ``base``, sorted (may be empty)."""
    try:
        return sorted(base.rglob(pattern))
    except OSError:
        return []


def _read_lines(path: Optional[Path]) -> list[str]:
    """Non-empty, non-comment stripped lines of ``path`` (or [] if absent)."""
    if not path or not path.exists():
        return []
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    return [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


def _jload(path: Optional[Path]) -> Any:
    """Parse JSON at ``path`` (returns None on missing file or bad JSON)."""
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Weakness -> severity mapping
# --------------------------------------------------------------------------- #
# Each spec: (filename_or_glob, title, severity, detail).
# Files are globbed recursively inside a run's output directory; a spec whose
# file has at least one line becomes one finding, its ``hosts`` = those lines.
#
# The mapping is derived from generate_report.get_criticals() (critical/warning)
# and refined onto a 5-level scale. Rationale, in short:
#   critical -> direct compromise / RCE / valid creds / auth bypass
#   high     -> exploitable weakness, usually needing one more step
#               (relay, offline crack, unauth read/write)
#   medium   -> meaningful misconfiguration / notable attack surface
#   low      -> minor hardening gap / interesting endpoint
#   info     -> inventory / enumeration, no weakness by itself
_FINDING_SPECS: dict[str, list[tuple[str, str, str, str]]] = {
    "discovery": [
        # Discovery is pure inventory; its data lives in `inventory`, not here.
    ],
    "smb": [
        ("smb_unsigned.txt",     "SMB signing disabled",        "high",
         "SMB signing not enforced - NTLM relay possible"),
        ("smb_v1.txt",           "SMBv1 enabled",               "critical",
         "Legacy SMBv1 exposed - EternalBlue / MS17-010 risk"),
        ("smb_shares_write.txt", "Writable SMB share",          "high",
         "Write access to a share (payload drop / data tampering)"),
        ("smb_shares_null.txt",  "Null-session share access",   "medium",
         "Shares listable/readable without authentication"),
        ("sysvol_files.txt",     "Sensitive SYSVOL/NETLOGON file", "medium",
         "Potential secrets in SYSVOL/NETLOGON (e.g. GPP cpassword)"),
        ("smb_spider.txt",       "Interesting file (share spider)", "medium",
         "Interesting file discovered while spidering shares"),
        ("smb_shares_read.txt",  "Readable SMB share",          "info",
         "Authenticated read access to a share"),
    ],
    "ldap": [
        ("ldap_nullbind.txt",    "Anonymous LDAP bind",         "high",
         "Directory readable without credentials (null bind)"),
        ("ldap_signing.txt",     "LDAP signing/CB not enforced", "high",
         "LDAP signing/channel binding not enforced - NTLM relay to LDAP (RBCD / ADCS ESC8)"),
        ("ldap_delegation.txt",  "Unconstrained delegation",    "critical",
         "Delegation abuse can lead to domain compromise"),
        ("ldap_laps.txt",        "LAPS password readable",      "critical",
         "Local admin password readable via LAPS by this account"),
        ("ldap_gmsa.txt",        "gMSA secret readable",        "critical",
         "gMSA managed password/NT hash readable by this account"),
        ("ldap_asrep_hashes.txt","AS-REP roastable hash",       "high",
         "AS-REP hash captured - offline crackable (hashcat -m 18200)"),
        ("ldap_kerberoast_hashes.txt", "Kerberoastable hash",   "high",
         "TGS-REP/SPN hash captured - offline crackable (hashcat -m 13100)"),
        # ldap_no_preauth.txt = PASSWD_NOTREQD (password optional), NOT Kerberos
        # pre-auth disabled (that is AS-REP roasting, above / check_kerberos).
        ("ldap_no_preauth.txt",  "PASSWD_NOTREQD account",      "medium",
         "Password optional on account - empty-password / spray candidate"),
        ("ldap_descriptions.txt","User description to review",  "medium",
         "User description field - often contains cleartext passwords"),
        ("ldap_adcs.txt",        "AD CS present",               "medium",
         "AD CS enumerated via LDAP - check templates with Certipy (ESC1-ESC8)"),
    ],
    "rdp": [
        ("rdp_login_success.txt","Successful RDP login",        "critical",
         "Valid credentials grant interactive desktop access"),
        ("rdp_no_nla.txt",       "RDP without NLA",             "medium",
         "No Network Level Authentication - pre-auth attack surface"),
    ],
    "ssh": [
        ("ssh_login_success.txt","Successful SSH login",        "critical",
         "Valid credentials accepted over SSH"),
        ("ssh_weak_algos.txt",   "Weak SSH algorithms",         "medium",
         "Deprecated ciphers/KEX/MAC offered"),
        ("ssh_password_auth.txt","SSH password authentication", "low",
         "Password auth enabled - exposed to spraying/brute force"),
    ],
    "http": [
        ("http_adcs.txt",        "ADCS web endpoint",           "critical",
         "AD CS web enrollment - ESC1/ESC8 / relay potential"),
        ("http_webdav.txt",      "WebDAV enabled",              "medium",
         "WebDAV exposed - upload / NTLM coercion surface"),
        ("http_owa.txt",         "OWA endpoint",                "low",
         "Outlook Web Access - password spraying surface"),
        ("http_rdweb.txt",       "RDWeb endpoint",              "low",
         "RD Web Access - credential spraying surface"),
        ("http_adfs.txt",        "ADFS endpoint",               "low",
         "AD FS - credential spraying / federation surface"),
        ("http_wsus.txt",        "WSUS endpoint",               "low",
         "WSUS - potential update MITM surface"),
    ],
    "mssql": [
        ("mssql_default_creds.txt",  "MSSQL default credentials", "critical",
         "Default SA/known credentials accepted"),
        ("mssql_cmdexec.txt",        "MSSQL xp_cmdshell (RCE)",   "critical",
         "Command execution via xp_cmdshell"),
        ("mssql_linked_servers.txt", "MSSQL linked server",       "medium",
         "Linked server - lateral movement / privilege chaining"),
        ("mssql_accessible.txt",     "Accessible MSSQL instance", "info",
         "Reachable MSSQL instance"),
    ],
    "dns": [
        ("dns_axfr_success.txt", "DNS zone transfer (AXFR)",    "high",
         "Full zone transfer allowed - internal topology disclosure"),
    ],
    "ftp": [
        ("ftp_writable.txt",     "Writable FTP path",           "critical",
         "Anonymous/authenticated write to FTP (payload drop)"),
        ("ftp_anonymous.txt",    "Anonymous FTP access",        "high",
         "Anonymous read access to FTP"),
        ("ftp_login_success.txt","FTP credential login",        "high",
         "Valid credentials accepted over FTP"),
    ],
    "snmp": [
        ("snmp_accessible.txt",  "SNMP accessible (community)",  "high",
         "Readable via SNMP community string - info disclosure"),
    ],
    "ipmi": [
        ("ipmi_cipher0.txt",       "IPMI cipher-zero bypass",    "critical",
         "Authentication bypass (CVE-2013-4786)"),
        ("ipmi_anonymous.txt",     "IPMI anonymous auth",        "critical",
         "Anonymous authentication allowed"),
        ("ipmi_default_creds.txt", "IPMI default credentials",   "critical",
         "Default BMC credentials accepted"),
        ("ipmi_hashes.txt",        "IPMI RAKP hash captured",    "high",
         "RAKP hash captured - offline crackable (hashcat -m 7300)"),
    ],
    "winrm": [
        ("winrm_accessible.txt", "WinRM authenticated access",  "critical",
         "Valid credentials grant remote command execution"),
    ],
    "kerberos": [
        ("kerberos_asrep_hashes.txt", "AS-REP roastable hash",   "high",
         "AS-REP hash captured - offline crackable (hashcat -m 18200)"),
        ("kerberos_spn_hashes.txt",   "Kerberoastable hash",     "high",
         "TGS-REP/SPN hash captured - offline crackable (hashcat -m 13100)"),
    ],
}

# Extra files whose mere presence proves a check ran (even with zero findings),
# so parse_run can report scanned=True with an empty findings list.
_MARKER_FILES: dict[str, list[str]] = {
    "discovery": ["hosts_alive.txt", "ports_summary.json"],
    "smb":       ["smb_hosts_info.txt", "smb_summary.txt"],
    "ldap":      ["ldap_domain_info.txt", "ldap_summary.txt", "ldap_users.txt"],
    "rdp":       ["rdp_results.txt", "rdp_summary.txt"],
    "ssh":       ["ssh_banners.txt", "ssh_summary.txt"],
    "http":      ["http_titles.txt", "http_summary.txt"],
    "mssql":     ["mssql_hosts_info.txt", "mssql_summary.txt"],
    "dns":       ["dns_soa.txt", "dns_summary.txt"],
    "ftp":       ["ftp_banners.txt", "ftp_summary.txt"],
    "snmp":      ["snmp_accessible.txt", "snmp_summary.txt", "snmp_communities.txt"],
    "ipmi":      ["ipmi_hosts_info.txt", "ipmi_summary.txt"],
    "winrm":     ["winrm_hosts_info.txt", "winrm_summary.txt"],
    "kerberos":  ["kerberos_valid_users.txt", "kerberos_summary.txt"],
}


# --------------------------------------------------------------------------- #
# Finding builders
# --------------------------------------------------------------------------- #
def _make_finding(service: str, title: str, severity: str,
                  hosts: list[str], detail: str) -> dict[str, Any]:
    return {
        "service": service,
        "title": title,
        "severity": severity,
        "hosts": hosts,
        "count": len(hosts),
        "detail": detail,
    }


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most severe first, then largest, then by title (stable, deterministic)."""
    return sorted(
        findings,
        key=lambda f: (_SEV_RANK.get(f["severity"], 99), -f["count"], f["title"]),
    )


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = _empty_counts()
    for f in findings:
        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1
        counts["total"] += 1
    return counts


def _service_inventory(base: Path, check_id: str) -> dict[str, Any]:
    """Per-service extra context (counts that are not weaknesses)."""
    inv: dict[str, Any] = {}

    if check_id == "discovery":
        alive = _read_lines(_find_file(base, "hosts_alive.txt"))
        svcs = ["dc", "smb", "ldap", "rdp", "winrm", "ssh", "http",
                "mssql", "dns", "kerberos", "ftp", "snmp", "ipmi"]
        by_service = {
            s: len(_read_lines(_find_file(base, f"hosts_{s}.txt"))) for s in svcs
        }
        ports = _jload(_find_file(base, "ports_summary.json"))
        top_ports: list[list[Any]] = []
        if isinstance(ports, dict):
            cnt = Counter(p for plist in ports.values()
                          if isinstance(plist, list) for p in plist)
            top_ports = [[port, n] for port, n in cnt.most_common(15)]
        inv = {
            "hosts_alive": alive,
            "hosts_alive_count": len(alive),
            "by_service": by_service,
            "top_ports": top_ports,
        }

    elif check_id == "ldap":
        # Exclure les dumps bruts `*.raw.txt` (sortie nxc/ldapsearch non parsée) :
        # ils matchent le glob mais regonfleraient le compteur.
        users = sum(len(_read_lines(f)) for f in _find_files(base, "ldap_users*.txt")
                    if not f.name.endswith(".raw.txt"))
        groups = sum(len(_read_lines(f)) for f in _find_files(base, "ldap_groups*.txt")
                     if not f.name.endswith(".raw.txt"))
        inv = {"users_count": users, "groups_count": groups}

    elif check_id == "ssh":
        inv = {"ssh_hosts": len(_read_lines(_find_file(base, "ssh_banners.txt")))}

    elif check_id == "http":
        inv = {"web_services": len(_read_lines(_find_file(base, "http_titles.txt")))}

    elif check_id == "kerberos":
        inv = {"valid_users": len(_read_lines(_find_file(base, "kerberos_valid_users.txt")))}

    return inv


def _collect_findings(base: Path, check_id: str) -> list[dict[str, Any]]:
    """Build the finding list for one check inside directory ``base``."""
    findings: list[dict[str, Any]] = []
    for filename, title, severity, detail in _FINDING_SPECS.get(check_id, []):
        if "*" in filename or "?" in filename:
            hosts: list[str] = []
            for f in _find_files(base, filename):
                hosts.extend(_read_lines(f))
        else:
            hosts = _read_lines(_find_file(base, filename))
        if hosts:
            findings.append(_make_finding(check_id, title, severity, hosts, detail))
    return _sort_findings(findings)


def _is_scanned(base: Path, check_id: str) -> bool:
    """True if any file proving this check ran exists under ``base``."""
    candidates = list(_MARKER_FILES.get(check_id, []))
    candidates += [spec[0] for spec in _FINDING_SPECS.get(check_id, [])]
    for name in candidates:
        if "*" in name or "?" in name:
            if _find_files(base, name):
                return True
        elif _find_file(base, name):
            return True
    return False


# --------------------------------------------------------------------------- #
# Public: single run
# --------------------------------------------------------------------------- #
def parse_run(output_dir: Optional[str], check_id: str) -> dict[str, Any]:
    """Parse one run's output directory into structured findings.

    Args:
        output_dir: absolute/relative path to the run's output dir (or None).
        check_id:   registry id of the check that produced it.

    Returns a dict:
        {
          "check_id":   str,
          "service":    str,            # == check_id
          "label":      str,            # registry label (or check_id)
          "output_dir": str | None,
          "scanned":    bool,
          "counts":     {severity: int, "total": int},
          "findings":   [ <finding>, ... ],
          "inventory":  { ...service specific... },
        }
    Never raises: an unusable directory yields scanned=False and empty sections.
    """
    check = get_check(check_id)
    label = check.label if check else check_id

    result: dict[str, Any] = {
        "check_id": check_id,
        "service": check_id,
        "label": label,
        "output_dir": output_dir,
        "scanned": False,
        "counts": _empty_counts(),
        "findings": [],
        "inventory": {},
    }

    if not output_dir:
        return result
    base = Path(output_dir)
    if not base.exists() or not base.is_dir():
        return result

    try:
        result["scanned"] = _is_scanned(base, check_id)
        findings = _collect_findings(base, check_id)
        result["findings"] = findings
        result["counts"] = _count_by_severity(findings)
        result["inventory"] = _service_inventory(base, check_id)
    except Exception:  # defensive: never let parsing crash the API
        # Keep whatever was gathered; report as scanned if a dir existed.
        pass

    return result


# --------------------------------------------------------------------------- #
# Public: whole campaign
# --------------------------------------------------------------------------- #
def _merge_top_ports(port_lists: list[list[list[Any]]]) -> list[list[Any]]:
    """Merge several [[port, count], ...] lists into one, summed & re-ranked."""
    merged: Counter = Counter()
    for pl in port_lists:
        for entry in pl:
            try:
                port, n = entry[0], int(entry[1])
            except (IndexError, TypeError, ValueError):
                continue
            merged[port] += n
    return [[port, n] for port, n in merged.most_common(15)]


def parse_campaign(campaign_id: int) -> dict[str, Any]:
    """Aggregate every run of a campaign into one dashboard payload.

    Returns a dict:
        {
          "campaign_id":       int,
          "campaign":          <campaign row> | None,
          "scanned":           bool,           # any run produced output
          "totals":            {severity: int, "total": int},
          "hosts_alive":       [str, ...],     # union across discovery runs
          "hosts_alive_count": int,
          "top_ports":         [[port, count], ...],
          "services":          { check_id: {
                                    "label": str,
                                    "scanned": bool,
                                    "counts": {severity: int, "total": int},
                                    "run_ids": [int, ...],
                                } },
          "findings":          [ <finding + "run_id">, ... ],   # sorted
          "runs":              [ { "run_id","check_id","status",
                                   "scanned","counts" }, ... ],
        }
    Never raises: an unknown/empty campaign yields scanned=False, empty sections.
    """
    result: dict[str, Any] = {
        "campaign_id": campaign_id,
        "campaign": None,
        "scanned": False,
        "totals": _empty_counts(),
        "hosts_alive": [],
        "hosts_alive_count": 0,
        "top_ports": [],
        "services": {},
        "findings": [],
        "runs": [],
    }

    try:
        result["campaign"] = get_campaign(campaign_id)
        runs = list_runs(campaign_id)
    except Exception:
        return result

    all_findings: list[dict[str, Any]] = []
    alive_union: list[str] = []
    alive_seen: set[str] = set()
    port_lists: list[list[list[Any]]] = []

    for run in runs:
        run_id = run.get("id")
        check_id = run.get("check_id", "")
        output_dir = run.get("output_dir")
        status = run.get("status")

        parsed = parse_run(output_dir, check_id)

        if parsed["scanned"]:
            result["scanned"] = True

        # Tag findings with their run and collect them.
        for f in parsed["findings"]:
            tagged = dict(f)
            tagged["run_id"] = run_id
            all_findings.append(tagged)

        # Per-service rollup.
        svc = result["services"].setdefault(check_id, {
            "label": parsed["label"],
            "scanned": False,
            "counts": _empty_counts(),
            "run_ids": [],
        })
        svc["scanned"] = svc["scanned"] or parsed["scanned"]
        svc["run_ids"].append(run_id)
        for sev in SEVERITY_ORDER + ["total"]:
            svc["counts"][sev] += parsed["counts"].get(sev, 0)

        # Discovery inventory feeds campaign-level alive hosts + ports.
        inv = parsed.get("inventory", {})
        for host in inv.get("hosts_alive", []):
            if host not in alive_seen:
                alive_seen.add(host)
                alive_union.append(host)
        if inv.get("top_ports"):
            port_lists.append(inv["top_ports"])

        result["runs"].append({
            "run_id": run_id,
            "check_id": check_id,
            "status": status,
            "scanned": parsed["scanned"],
            "counts": parsed["counts"],
        })

    result["findings"] = _sort_findings(all_findings)
    result["totals"] = _count_by_severity(all_findings)
    result["hosts_alive"] = alive_union
    result["hosts_alive_count"] = len(alive_union)
    result["top_ports"] = _merge_top_ports(port_lists)

    return result
