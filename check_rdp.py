#!/usr/bin/env python3
"""check_rdp.py - RDP enumeration and NLA checks"""

import argparse, subprocess, os, sys, re, ipaddress, shlex
from datetime import datetime
from pathlib import Path

from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, confirm_step, set_total_steps, enable_auto_accept,
                         emit_progress, nxc_is_admin, nxc_login_ok)


set_total_steps(3)

def run(cmd, timeout=300):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def resolve_targets(target_arg):
    """Return a list of IP strings from file path, single IP, or CIDR."""
    # File path
    p = Path(target_arg)
    if p.is_file():
        return [
            line.strip()
            for line in p.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    # CIDR
    if "/" in target_arg:
        try:
            net = ipaddress.ip_network(target_arg, strict=False)
            return [str(h) for h in net.hosts()]
        except ValueError:
            log_err(f"Invalid CIDR: {target_arg}")
            sys.exit(1)

    # Single IP / hostname
    return [target_arg]


def write_hosts_file(targets, out_dir):
    """Write targets to a temporary hosts file and return its path."""
    hosts_file = out_dir / "hosts_rdp_tmp.txt"
    hosts_file.write_text("\n".join(targets) + "\n")
    return hosts_file


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

# Example nxc rdp output line:
# RDP         10.10.10.1      3389   DC01   [*] Windows 10 or Windows Server 2016 Build 14393 (name:DC01) (domain:lab.local) (nla:True)
NXC_LINE_RE = re.compile(
    r"RDP\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\d+\s+(?P<hostname>\S+)\s+.*?"
    r"\(name:(?P<name>[^)]*)\).*?"
    r"\(domain:(?P<domain>[^)]*)\).*?"
    r"\(nla:(?P<nla>\w+)\)",
    re.IGNORECASE,
)

OS_RE = re.compile(
    r"RDP\s+\S+\s+\d+\s+\S+\s+\[\*\]\s+(?P<os>[^\(]+?)\s+(?:Build\s+\d+\s+)?\(",
    re.IGNORECASE,
)

RDP_IP_RE = re.compile(r"RDP\s+(?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)


def parse_nxc_output(stdout):
    """Parse nxc rdp unauthenticated output.

    Returns list of dicts: {ip, hostname, os, nla_enabled}
    """
    results = []
    for line in stdout.splitlines():
        m = NXC_LINE_RE.search(line)
        if not m:
            continue
        os_m = OS_RE.search(line)
        os_str = os_m.group("os").strip() if os_m else "Unknown"
        nla_enabled = m.group("nla").lower() == "true"
        results.append({
            "ip": m.group("ip"),
            "hostname": m.group("hostname"),
            "os": os_str,
            "nla_enabled": nla_enabled,
        })
    return results


def parse_auth_output(stdout):
    """Parse nxc rdp authenticated output.

    En RDP, un simple ``[+]`` signifie seulement que les creds sont VALIDES (NLA les
    accepte) — l'ouverture de session peut quand même être refusée (droits "Remote
    Desktop Users"). Seul le marqueur ``(Pwn3d!)``/``(admin)`` garantit qu'on peut
    réellement se connecter. On sépare donc les deux pour ne pas remonter de faux
    positif critique.

    Returns:
        (admin_ips, valid_only_ips): IPs avec accès réel vs IPs creds-valides-seules.
    """
    admin_ips, valid_ips = [], []
    for line in stdout.splitlines():
        m = RDP_IP_RE.search(line)
        if not m:
            continue
        ip = m.group("ip")
        if nxc_is_admin(line):
            admin_ips.append(ip)
        elif nxc_login_ok(line):
            valid_ips.append(ip)
    admin = list(dict.fromkeys(admin_ips))
    # creds valides mais SANS accès admin (exclut ceux déjà classés admin)
    valid_only = [ip for ip in dict.fromkeys(valid_ips) if ip not in admin]
    return admin, valid_only


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def _build_cred_args(hosts_file, username, password, ntlm_hash, domain):
    """Build nxc rdp command parts for credential-based scanning."""
    parts = [f"nxc rdp {hosts_file}", f"-u {shlex.quote(username)}"]
    if ntlm_hash:
        parts.append(f"-H {shlex.quote(ntlm_hash)}")
    elif password:
        parts.append(f"-p {shlex.quote(password)}")
    if domain:
        parts.append(f"-d {shlex.quote(domain)}")
    return parts

def step1_nla_check(hosts_file, out_dir):
    """Run unauthenticated nxc rdp scan and extract NLA / OS info."""
    log_step("STEP 1 — NLA & OS Detection (no credentials)")

    if not confirm_step("STEP 1 — NLA & OS Detection", f"nxc rdp {hosts_file}"):
        (out_dir / "rdp_no_nla.txt").write_text("")
        (out_dir / "rdp_results.txt").write_text("# Skipped by user request\n")
        return []

    cmd = f"nxc rdp {hosts_file}"
    log_info(f"Running: {cmd}")
    stdout, stderr, rc = run(cmd, timeout=600)

    if rc != 0 and not stdout:
        log_warn(f"nxc returned code {rc}. stderr: {stderr[:200]}")

    # Save raw output
    raw_out = out_dir / "rdp_nxc_raw.txt"
    raw_out.write_text(stdout + "\n" + stderr)

    results = parse_nxc_output(stdout)

    if not results:
        log_warn("No parseable RDP hosts found in nxc output.")
        # Still write empty files so downstream scripts don't break
        (out_dir / "rdp_no_nla.txt").write_text("")
        (out_dir / "rdp_results.txt").write_text("# No RDP hosts detected\n")
        return []

    # rdp_results.txt — full info
    results_lines = ["# IP | Hostname | OS | NLA"]
    for r in results:
        nla_str = "NLA:enabled" if r["nla_enabled"] else "NLA:DISABLED"
        results_lines.append(f"{r['ip']}\t{r['hostname']}\t{r['os']}\t{nla_str}")
    (out_dir / "rdp_results.txt").write_text("\n".join(results_lines) + "\n")

    # rdp_no_nla.txt — attack surface
    no_nla = sorted({r["ip"] for r in results if not r["nla_enabled"]})
    (out_dir / "rdp_no_nla.txt").write_text("\n".join(no_nla) + ("\n" if no_nla else ""))

    log_ok(f"Scanned {len(results)} host(s). NLA disabled on {len(no_nla)} host(s).")
    for r in results:
        marker = f"{C.WARN}NLA:DISABLED{C.ENDC}" if not r["nla_enabled"] else "NLA:enabled"
        log_info(f"  {r['ip']:15s}  {r['hostname']:20s}  {r['os'][:40]:40s}  {marker}")

    return results


def step2_auth_check(hosts_file, out_dir, username, password, ntlm_hash, domain):
    """Attempt authenticated RDP login with supplied credentials."""
    log_step("STEP 2 — Authenticated RDP Check")

    if not confirm_step("STEP 2 — Authenticated RDP Check", f"nxc rdp {hosts_file} -u {username} ..."):
        (out_dir / "rdp_login_success.txt").write_text("")
        return []

    cmd = " ".join(_build_cred_args(hosts_file, username, password, ntlm_hash, domain))
    log_info(f"Running: {cmd}")
    stdout, stderr, rc = run(cmd, timeout=600)

    # Save raw output for troubleshooting / manual review.
    (out_dir / "rdp_auth_raw.txt").write_text(stdout + "\n" + stderr)

    admin, valid_only = parse_auth_output(stdout)

    # rdp_login_success.txt = accès RÉEL uniquement (marqueur admin/Pwn3d!).
    # C'est ce fichier que le rapport remonte en 🔴 critique.
    success_file = out_dir / "rdp_login_success.txt"
    success_file.write_text("\n".join(sorted(admin)) + ("\n" if admin else ""))

    # Fichier d'info : creds valides mais session non garantie (droits RDP manquants).
    valid_file = out_dir / "rdp_valid_creds.txt"
    valid_file.write_text("\n".join(sorted(valid_only)) + ("\n" if valid_only else ""))

    if admin:
        log_ok(f"[CRITICAL] Interactive RDP access (admin) on {len(admin)} host(s):")
        for ip in admin:
            log_ok(f"  {ip}")
    else:
        log_warn("No interactive RDP access (no admin/Pwn3d! marker).")
    if valid_only:
        log_info(f"{len(valid_only)} host(s) with VALID creds but no confirmed session "
                 f"(check RDP logon rights) → {valid_file}")
        for ip in valid_only:
            log_info(f"  {ip}")

    return admin


def step3_screenshot(hosts_file, out_dir, username, password, ntlm_hash, domain):
    """Capture RDP screenshots for hosts where credentials work."""
    log_step("STEP 3 — RDP Screenshots")

    if not confirm_step("STEP 3 — RDP Screenshots", f"nxc rdp {hosts_file} -u {username} ... --screenshot --screentime 3"):
        return

    parts = _build_cred_args(hosts_file, username, password, ntlm_hash, domain)
    parts.append("--screenshot --screentime 3")
    cmd = " ".join(parts)
    log_info(f"Running: {cmd}")
    stdout, stderr, rc = run(cmd, timeout=900)

    # nxc saves screenshots next to its logs; note the path in summary
    if rc == 0:
        log_ok("Screenshot command completed (check nxc logs for saved files).")
    else:
        log_warn(f"Screenshot command finished with rc={rc}. Some hosts may have failed.")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_summary(out_dir, targets, results, successes, has_creds):
    """Write human-readable rdp_summary.txt."""
    lines = [
        RULE,
        "RDP Check Summary",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        RULE,
        f"  Targets scanned  : {len(targets)}",
        f"  Hosts detected   : {len(results)}",
    ]

    if results:
        no_nla = [r for r in results if not r["nla_enabled"]]
        nla_ok  = [r for r in results if r["nla_enabled"]]
        lines += [
            f"  NLA disabled     : {len(no_nla)}  <-- potential attack vector",
            f"  NLA enabled      : {len(nla_ok)}",
        ]
        if no_nla:
            lines.append("\n  Hosts with NLA disabled:")
            for r in no_nla:
                lines.append(f"    - {r['ip']:15s}  {r['hostname']}  ({r['os']})")

    if has_creds:
        lines += [
            f"\n  Auth successes   : {len(successes)}",
        ]
        if successes:
            lines.append("\n  Successful logins:")
            for ip in successes:
                lines.append(f"    - {ip}")

    lines += [
        "\n  Output files:",
        f"    {out_dir / 'rdp_results.txt'}",
        f"    {out_dir / 'rdp_no_nla.txt'}",
    ]
    if has_creds:
        lines.append(f"    {out_dir / 'rdp_login_success.txt'}")
    lines.append(RULE)

    summary_path = out_dir / "rdp_summary.txt"
    summary_path.write_text("\n".join(lines) + "\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="check_rdp.py — RDP enumeration and NLA/auth checks",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True,
                        help="File with IPs, single IP, or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("-o", "--output",
                        help="Output directory (default: ./rdp_results_<timestamp>)")
    parser.add_argument("-u", "--username", help="Username for auth check")
    parser.add_argument("-p", "--password", help="Password for auth check")
    parser.add_argument("-H", "--hash",     help="NTLM hash LM:NT for auth check")
    parser.add_argument("-d", "--domain",   help="Domain for auth check")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Non-interactive: accept all steps (for automation/UI)")
    return parser.parse_args()


def main():
    args = parse_args()
    if getattr(args, "yes", False):
        enable_auto_accept()

    # --- Output directory ---
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output) if args.output else Path(f"rdp_results_{timestamp}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Output directory: {out_dir.resolve()}")

    # --- Dependency check ---
    if not tool_exists("nxc"):
        log_err("nxc (NetExec) not found. Install it: pip install netexec")
        sys.exit(1)

    # --- Resolve targets ---
    targets = resolve_targets(args.target)
    if not targets:
        log_warn("Target list is empty. Nothing to scan.")
        sys.exit(0)
    log_info(f"Targets loaded: {len(targets)} host(s)")

    # Write hosts file for nxc
    hosts_file = write_hosts_file(targets, out_dir)

    has_creds = bool(args.username and (args.password or args.hash))

    # --- Step 1: NLA / OS ---
    results = step1_nla_check(hosts_file, out_dir)

    # --- Step 2 & 3: Auth (only if creds provided) ---
    successes = []
    if has_creds:
        successes = step2_auth_check(
            hosts_file, out_dir,
            args.username, args.password, args.hash, args.domain,
        )
        step3_screenshot(
            hosts_file, out_dir,
            args.username, args.password, args.hash, args.domain,
        )
    else:
        log_info("No credentials provided — skipping authenticated checks (Steps 2 & 3).")

    # --- Summary ---
    log_step("SUMMARY")
    summary = write_summary(out_dir, targets, results, successes, has_creds)
    print(summary)

    # Clean up tmp hosts file
    hosts_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
