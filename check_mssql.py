#!/usr/bin/env python3
"""check_mssql.py - MSSQL enumeration and default credential testing"""

import argparse
import shutil
import subprocess
import os
import sys
import re
import shlex
import tempfile
from datetime import datetime
from pathlib import Path

from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, confirm_step, set_total_steps, enable_auto_accept,
                         emit_progress, nxc_is_admin, nxc_login_ok, strip_ansi)


set_total_steps(3)


def run(cmd, timeout=120):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1


def resolve_targets(target_arg):
    """Return (hosts_file_path, list_of_hosts).
    Accepts: path to existing file, single IP, or CIDR range.
    """
    p = Path(target_arg)
    if p.exists() and p.is_file():
        hosts = [h.strip() for h in p.read_text().splitlines() if h.strip()]
        return str(p), hosts

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='mssql_targets_')
    tmp.write(target_arg + "\n")
    tmp.close()
    return tmp.name, [target_arg]


def write_sorted(path: Path, lines: list):
    """Write deduplicated, sorted lines to file."""
    path.write_text("\n".join(sorted(set(l for l in lines if l.strip()))) + "\n")


DEFAULT_CREDS = [
    ("sa", ""),
    ("sa", "sa"),
    ("sa", "Password1"),
    ("sa", "password"),
    ("sa", "admin"),
    ("sa", "123456"),
]


def step_hosts_info(hosts_file: str, out_dir: Path) -> list:
    """Collect unauthenticated version/hostname info; return list of live IPs."""
    log_step("STEP 1 — MSSQL version and instance info")
    out_file = out_dir / "mssql_hosts_info.txt"

    if not confirm_step("STEP 1 — MSSQL version/instance info", f"nxc mssql {hosts_file}"):
        out_file.write_text("# Skipped by user request\n")
        return []

    stdout, _, _ = run(f"nxc mssql {shlex.quote(hosts_file)} 2>/dev/null", timeout=180)
    # nxc colore sa sortie même pipée : sans strip_ansi, les regex de parsing
    # peuvent rater les lignes (faux négatifs).
    lines = [l for l in strip_ansi(stdout).splitlines() if l.strip()]

    if lines:
        out_file.write_text("\n".join(lines) + "\n")
        log_ok(f"Saved host info → {out_file} ({len(lines)} lines)")
    else:
        out_file.write_text("# No MSSQL hosts responded\n")
        log_warn("No MSSQL hosts responded or nxc produced no output")

    # (\S+) : le premier token après MSSQL est la cible (IP **ou hostname** —
    # les fichiers cibles peuvent contenir des hostnames, supportés par nxc).
    alive = list(dict.fromkeys(
        m.group(1) for l in lines
        for m in [re.search(r'MSSQL\s+(\S+)', l)] if m
    ))
    return alive


def step_default_creds(hosts_file: str, out_dir: Path) -> list:
    """Test default SA credentials; return list of (ip, user, pass, raw_line) hits."""
    log_step("STEP 2 — Default credential testing")
    successes = []

    if not confirm_step("STEP 2 — Default credential testing", f"nxc mssql {hosts_file} -u sa -p ***  ({len(DEFAULT_CREDS)} default cred pair(s))"):
        (out_dir / "mssql_default_creds.txt").write_text("# Skipped by user request\n")
        return successes

    for user, pwd in DEFAULT_CREDS:
        display_pwd = pwd or "<empty>"
        log_info(f"Testing {user}:{display_pwd}")
        stdout, _, _ = run(
            f"nxc mssql {shlex.quote(hosts_file)} -u {shlex.quote(user)} -p {shlex.quote(pwd)} --no-bruteforce 2>/dev/null",
            timeout=180,
        )
        for line in strip_ansi(stdout).splitlines():
            # nxc_login_ok (helper commun) au lieu du littéral "Pwn3d!" :
            # un hit de cred = login valide ([+]), pas forcément admin ; et
            # les builds nxc récents marquent "(admin)" au lieu de "(Pwn3d!)".
            if nxc_login_ok(line):
                m = re.search(r'MSSQL\s+(\S+)', line)
                if m:
                    ip = m.group(1)
                    log_ok(f"[CRITICAL] Default creds work on {ip} — {user}:{display_pwd}")
                    successes.append((ip, user, pwd, line.strip()))

    out_file = out_dir / "mssql_default_creds.txt"
    if successes:
        write_sorted(out_file, [f"{ip}\t{user}\t{pwd}\t{raw}" for ip, user, pwd, raw in successes])
        log_ok(f"[CRITICAL] {len(successes)} default cred hit(s) → {out_file}")
    else:
        out_file.write_text("# No default credentials succeeded\n")
        log_warn("No default credentials succeeded")

    return successes


def build_cred_str(username, password, ntlm_hash, domain):
    """Build nxc credential fragment."""
    parts = []
    if username:
        parts.append(f"-u {shlex.quote(username)}")
    if ntlm_hash:
        parts.append(f"-H {shlex.quote(ntlm_hash)}")
    elif password is not None:
        parts.append(f"-p {shlex.quote(password)}")
    if domain:
        parts.append(f"-d {shlex.quote(domain)}")
    return " ".join(parts)


def step_authenticated(hosts_file: str, out_dir: Path,
                       username, password, ntlm_hash, domain,
                       default_hits: list):
    """Perform authenticated MSSQL checks using explicit creds or first default hit."""
    log_step("STEP 3 — Authenticated checks")

    if not confirm_step("STEP 3 — Authenticated checks", "nxc mssql queries: version/sysadmin, database list, xp_cmdshell 'whoami', linked servers"):
        for fname in ("mssql_accessible.txt", "mssql_cmdexec.txt", "mssql_linked_servers.txt"):
            (out_dir / fname).write_text("# Skipped by user request\n")
        return

    # Prefer explicit creds; fall back to first successful default hit.
    # Determine the auth mode ONCE so every query below uses the same mode as
    # the login that actually succeeded:
    #   - explicit creds  -> local auth unless a domain was supplied
    #   - default SA hits -> local SQL auth (built-in sa account) => --local-auth
    if username:
        user, pwd, h, dom = username, password, ntlm_hash, domain
        use_local_auth = not dom
    elif default_hits:
        user, pwd, h, dom = default_hits[0][1], default_hits[0][2], None, None
        use_local_auth = True
    else:
        log_warn("No credentials available — skipping authenticated checks")
        return

    creds = build_cred_str(user, pwd, h, dom)
    auth = " --local-auth" if use_local_auth else ""
    hf = shlex.quote(hosts_file)
    accessible_lines = []
    cmdexec_lines = []
    linked_lines = []

    log_info(f"Querying instance info as {user}")
    q1 = "SELECT @@version, system_user, is_srvrolemember('sysadmin')"
    stdout, _, _ = run(f"nxc mssql {hf} {creds}{auth} -q \"{q1}\" 2>/dev/null", timeout=180)
    for line in strip_ansi(stdout).splitlines():
        if "[+]" in line or "sysadmin" in line.lower() or "@@version" in line.lower():
            accessible_lines.append(line.strip())

    log_info(f"Listing databases as {user}")
    q2 = "SELECT name FROM sys.databases"
    stdout, _, _ = run(f"nxc mssql {hf} {creds}{auth} -q \"{q2}\" 2>/dev/null", timeout=180)
    accessible_lines.extend(l.strip() for l in strip_ansi(stdout).splitlines() if l.strip())

    log_info(f"Testing xp_cmdshell (whoami) as {user}")
    stdout, _, _ = run(f"nxc mssql {hf} {creds}{auth} -x 'whoami' 2>/dev/null", timeout=180)
    # xp_cmdshell = RCE : ne remonter que si nxc confirme l'exécution via le marqueur
    # admin/Pwn3d!. Un simple [+] = login SA valide mais xp_cmdshell peut être désactivé
    # ou le compte non-sysadmin ; l'ancien "\\" ramassait aussi la ligne d'auth et tout
    # DOMAIN\user → faux positif critique.
    exec_hosts = [line.strip() for line in strip_ansi(stdout).splitlines() if nxc_is_admin(line)]
    if exec_hosts:
        for line in exec_hosts:
            m = re.search(r'MSSQL\s+(\S+)', line)
            if m:
                log_ok(f"[CRITICAL] xp_cmdshell works on {m.group(1)} as {user}")
        cmdexec_lines.extend(exec_hosts)
        # Joindre la sortie réelle de la commande (lignes hors statut nxc) comme preuve.
        cmdexec_lines.extend(
            l.strip() for l in stdout.splitlines()
            if l.strip() and not re.search(r'\[\+\]|\[-\]|\[\*\]', l)
        )

    log_info(f"Checking linked servers as {user}")
    q3 = "SELECT name FROM sys.servers"
    stdout, _, _ = run(f"nxc mssql {hf} {creds}{auth} -q \"{q3}\" 2>/dev/null", timeout=180)
    linked_lines.extend(l.strip() for l in strip_ansi(stdout).splitlines() if l.strip())

    acc_file = out_dir / "mssql_accessible.txt"
    if accessible_lines:
        write_sorted(acc_file, accessible_lines)
        log_ok(f"Accessible hosts/data → {acc_file}")
    else:
        acc_file.write_text("# No accessible hosts with provided credentials\n")

    cmd_file = out_dir / "mssql_cmdexec.txt"
    if cmdexec_lines:
        write_sorted(cmd_file, cmdexec_lines)
        log_ok(f"[CRITICAL] xp_cmdshell results → {cmd_file}")
    else:
        cmd_file.write_text("# xp_cmdshell not available or no execution succeeded\n")

    lnk_file = out_dir / "mssql_linked_servers.txt"
    if linked_lines:
        write_sorted(lnk_file, linked_lines)
        log_ok(f"Linked servers → {lnk_file}")
    else:
        lnk_file.write_text("# No linked servers found or query returned no results\n")


def write_summary(out_dir: Path, alive: list, default_hits: list,
                  username, domain, start_time: datetime):
    """Write human-readable mssql_summary.txt."""
    duration = (datetime.now() - start_time).seconds
    prefix = (domain + "\\") if domain else ""
    lines = [
        "=" * 60,
        "  MSSQL SCAN SUMMARY",
        f"  Date    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Duration: {duration}s",
        f"  Output  : {out_dir}",
        "=" * 60,
        "",
        f"[*] Hosts responding on MSSQL: {len(alive)}",
        *[f"    - {ip}" for ip in alive],
        "",
    ]

    if default_hits:
        lines.append(f"[CRITICAL] Default credentials found on {len(default_hits)} host(s):")
        for ip, user, pwd, _ in default_hits:
            lines.append(f"    - {ip}  {user}:{pwd or '<empty>'}")
    else:
        lines.append("[*] No default credentials succeeded")

    lines += [
        "",
        f"[*] Authenticated as: {prefix}{username}" if username
        else "[*] No explicit credentials provided",
        "",
        "Output files:",
        "  mssql_hosts_info.txt      — version / instance info",
        "  mssql_default_creds.txt   — [CRITICAL] default SA creds",
        "  mssql_accessible.txt      — authenticated access results",
        "  mssql_cmdexec.txt         — [CRITICAL] xp_cmdshell results",
        "  mssql_linked_servers.txt  — linked server configurations",
        "  mssql_summary.txt         — this file",
        "",
        "=" * 60,
    ]

    summary_file = out_dir / "mssql_summary.txt"
    summary_file.write_text("\n".join(lines) + "\n")
    log_ok(f"Summary → {summary_file}")


def main():
    parser = argparse.ArgumentParser(
        description="check_mssql.py — MSSQL enumeration and default credential testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 check_mssql.py -t hosts_mssql.txt
  python3 check_mssql.py -t 192.168.1.10 -u sa -p Password1
  python3 check_mssql.py -t 10.0.0.0/24 -u admin -H aad3b435b51404eeaad3b435b51404ee:abc123 -d CORP
""",
    )
    parser.add_argument("-t", "--target",   required=True,
                        help="File with IPs, single IP, or CIDR range")
    parser.add_argument("-o", "--output",   default=None,
                        help="Output directory (default: ./mssql_results_<timestamp>)")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-H", "--hash",     help="NTLM hash LM:NT")
    parser.add_argument("-d", "--domain",   help="Domain")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Non-interactive: accept all steps (for automation/UI)")
    args = parser.parse_args()
    if getattr(args, "yes", False):
        enable_auto_accept()

    start_time = datetime.now()
    out_dir = Path(args.output) if args.output else Path(f"./mssql_results_{start_time.strftime('%Y%m%d_%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{C.BOLD}MSSQL — Enumeration & Default Creds Check{C.ENDC}")
    print(f"{C.DIM}{RULE}{C.ENDC}")
    log_info(f"Target  : {args.target}")
    log_info(f"Output  : {out_dir.resolve()}")
    if args.username:
        prefix = (args.domain + "\\") if args.domain else ""
        log_info(f"User    : {prefix}{args.username}")

    if not shutil.which("nxc"):
        log_err("nxc not found in PATH — install NetExec (https://github.com/Pennyw0rth/NetExec)")
        sys.exit(1)

    # -u seul : nxc demanderai le mot de passe sur stdin et pendrait jusqu'au
    # timeout à chaque requête → refuser proprement dès le départ.
    if args.username and args.password is None and not args.hash:
        log_err("-u given without -p/-H: provide a password or a hash (use '' for an empty password)")
        sys.exit(1)

    hosts_file, hosts_list = resolve_targets(args.target)
    if not hosts_list:
        log_warn("Target file is empty — nothing to scan")
        sys.exit(0)
    log_info(f"Targets : {len(hosts_list)} host(s)/range(s)")

    alive = step_hosts_info(hosts_file, out_dir)

    default_hits = []
    if not args.username and not args.hash:
        default_hits = step_default_creds(hosts_file, out_dir)
    else:
        log_info("Explicit credentials provided — skipping default credential testing")
        (out_dir / "mssql_default_creds.txt").write_text(
            "# Default cred test skipped — explicit credentials provided\n"
        )

    if args.username or args.hash or default_hits:
        step_authenticated(
            hosts_file, out_dir,
            args.username, args.password, args.hash, args.domain,
            default_hits,
        )
    else:
        log_warn("No credentials available — skipping authenticated checks")
        for fname in ("mssql_accessible.txt", "mssql_cmdexec.txt", "mssql_linked_servers.txt"):
            (out_dir / fname).write_text("# Skipped — no credentials\n")

    write_summary(out_dir, alive, default_hits, args.username, args.domain, start_time)

    print(f"\n{C.BOLD}MSSQL Scan Complete{C.ENDC}")
    print(f"{C.DIM}{RULE}{C.ENDC}\n")
    log_ok(f"Results in: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
