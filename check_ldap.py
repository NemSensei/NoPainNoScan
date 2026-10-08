#!/usr/bin/env python3
"""check_ldap.py - LDAP null bind testing and AD enumeration"""

import argparse, subprocess, os, sys, re, shlex
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Colors & logging
# ---------------------------------------------------------------------------

from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, confirm_step, set_total_steps, enable_auto_accept,
                         emit_progress)


set_total_steps(5)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, timeout=600):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1


def write_file(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)

def parse_targets(target_arg: str) -> list[str]:
    """Accept: file path, single IP, or CIDR range (via nmap -sL)."""
    p = Path(target_arg)
    if p.is_file():
        lines = [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith('#')]
        if not lines:
            log_warn(f"Target file '{target_arg}' is empty.")
        return lines

    # Single IP or CIDR — expand with nmap if available
    if '/' in target_arg and tool_exists('nmap'):
        # $NF est entre parenthèses quand nmap résout un hostname : on les retire.
        out, _, _ = run(f"nmap -n -sL {shlex.quote(target_arg)} | awk '/Nmap scan report/{{print $NF}}'")
        ips = [l.strip().strip('()') for l in out.splitlines() if l.strip()]
        return ips if ips else [target_arg]

    return [target_arg]

# ---------------------------------------------------------------------------
# STEP 1 — rootDSE query
# ---------------------------------------------------------------------------

def query_rootdse(ip: str) -> str | None:
    """Return base DN (e.g. DC=corp,DC=local) or None."""
    cmd = (
        f"ldapsearch -x -H ldap://{ip} -b '' -s base '(objectClass=*)' "
        "defaultNamingContext namingContexts 2>/dev/null"
    )
    out, _, rc = run(cmd, timeout=15)
    if rc != 0 or not out:
        return None
    # Try defaultNamingContext first
    m = re.search(r'defaultNamingContext:\s*(.+)', out)
    if m:
        return m.group(1).strip()
    # Fallback to first namingContexts entry that looks like a domain
    m = re.search(r'namingContexts:\s*(DC=\S+)', out, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None

def step_rootdse(hosts: list[str], outdir: Path) -> dict[str, str]:
    """Query rootDSE for all hosts. Returns {ip: base_dn} (only reachable hosts)."""
    log_step("STEP 1 — rootDSE query (no credentials)")
    host_map: dict[str, str] = {}
    lines: list[str] = []

    if not confirm_step("STEP 1 — rootDSE query", f"ldapsearch -x -H ldap://<ip> -b '' -s base  (x{len(hosts)} host(s))"):
        write_file(outdir / "ldap_domain_info.txt", "# Skipped by user request\n")
        return host_map

    for ip in hosts:
        log_info(f"Querying rootDSE for {ip} ...")
        base_dn = query_rootdse(ip)
        if base_dn:
            log_ok(f"{ip} → {base_dn}")
            host_map[ip] = base_dn
            lines.append(f"{ip}\t{base_dn}")
        else:
            log_warn(f"{ip} → rootDSE query failed or no naming context found")
            lines.append(f"{ip}\tUNREACHABLE")

    write_file(outdir / "ldap_domain_info.txt", "\n".join(lines) + "\n")
    log_ok(f"Domain info saved to {outdir / 'ldap_domain_info.txt'}")
    return host_map

# ---------------------------------------------------------------------------
# STEP 2 — Null bind test
# ---------------------------------------------------------------------------

def test_nullbind(ip: str, base_dn: str) -> bool:
    """Return True if host allows null/anonymous bind."""
    cmd = (
        f"ldapsearch -x -H ldap://{ip} -D '' -w '' -b '{base_dn}' "
        "'(objectClass=person)' sAMAccountName cn 2>/dev/null | head -50"
    )
    out, _, _ = run(cmd, timeout=20)
    return bool(re.search(r'^dn:', out, re.MULTILINE))

def step_nullbind(host_map: dict[str, str], outdir: Path) -> list[str]:
    """Test null bind on all hosts. Returns list of vulnerable IPs."""
    log_step("STEP 2 — Null bind test (anonymous LDAP)")
    vulnerable: list[str] = []

    if not confirm_step("STEP 2 — Null bind test", f"ldapsearch -x -H ldap://<ip> -D '' -w '' -b '<base_dn>'  (x{len(host_map)} host(s))"):
        write_file(outdir / "ldap_nullbind.txt", "")
        return vulnerable

    for ip, base_dn in host_map.items():
        log_info(f"Testing null bind on {ip} ...")
        if test_nullbind(ip, base_dn):
            log_warn(f"{ip} — NULL BIND ALLOWED [CRITICAL]")
            vulnerable.append(ip)
        else:
            log_ok(f"{ip} — null bind refused (good)")

    content = "\n".join(sorted(vulnerable)) + ("\n" if vulnerable else "")
    write_file(outdir / "ldap_nullbind.txt", content)
    if vulnerable:
        log_warn(f"{len(vulnerable)} host(s) allow null bind → {outdir / 'ldap_nullbind.txt'}")
    else:
        log_ok("No hosts allow null bind.")
    return vulnerable

# ---------------------------------------------------------------------------
# STEP 3 — Null bind dump
# ---------------------------------------------------------------------------

def ldap_dump(ip: str, base_dn: str, obj_class: str, attrs: str) -> str:
    cmd = (
        f"ldapsearch -x -H ldap://{ip} -b '{base_dn}' "
        f"'(objectClass={obj_class})' {attrs} 2>/dev/null"
    )
    out, _, _ = run(cmd, timeout=60)
    return out

def step_nullbind_dump(vulnerable: list[str], host_map: dict[str, str], outdir: Path):
    if not vulnerable:
        return
    log_step("STEP 3 — Dumping AD objects via null bind")

    if not confirm_step("STEP 3 — Dump AD objects via null bind", f"ldapsearch -x -H ldap://<ip> -b '<base_dn>' (objectClass=user|group|computer)  (x{len(vulnerable)} host(s))"):
        return

    for ip in vulnerable:
        base_dn = host_map[ip]
        log_info(f"Dumping users from {ip} ...")
        users = ldap_dump(ip, base_dn, "user", "sAMAccountName cn userPrincipalName")
        write_file(outdir / f"ldap_users_{ip}.txt", users)
        log_ok(f"  Users → {outdir / f'ldap_users_{ip}.txt'}")

        log_info(f"Dumping groups from {ip} ...")
        groups = ldap_dump(ip, base_dn, "group", "cn member")
        write_file(outdir / f"ldap_groups_{ip}.txt", groups)
        log_ok(f"  Groups → {outdir / f'ldap_groups_{ip}.txt'}")

        log_info(f"Dumping computers from {ip} ...")
        computers = ldap_dump(ip, base_dn, "computer", "name dNSHostName")
        write_file(outdir / f"ldap_computers_{ip}.txt", computers)
        log_ok(f"  Computers → {outdir / f'ldap_computers_{ip}.txt'}")

# ---------------------------------------------------------------------------
# STEP 4 — Authenticated enumeration (nxc)
# ---------------------------------------------------------------------------

def build_cred_part(user: str, password: str | None, nt_hash: str | None) -> str:
    if nt_hash:
        return f"-u {shlex.quote(user)} -H {shlex.quote(nt_hash)}"
    return f"-u {shlex.quote(user)} -p {shlex.quote(password or '')}"

def step_auth_enum(hosts: list[str], user: str, password: str | None,
                   nt_hash: str | None, domain: str, outdir: Path):
    log_step("STEP 4 — Authenticated enumeration (nxc ldap)")
    targets = " ".join(shlex.quote(h) for h in hosts)
    cred = build_cred_part(user, password, nt_hash)

    if not confirm_step("STEP 4 — Authenticated enumeration", f"nxc ldap {targets} -u {user} ... --users/--groups/--password-not-required/--trusted-for-delegation/--admin-count"):
        return

    checks = [
        ("--users",                  "ldap_users.txt",       "Users"),
        ("--groups",                 "ldap_groups.txt",      "Groups"),
        # NB : PASSWD_NOTREQD ≠ "sans préauth Kerberos" (c'est --asreproast) —
        # ne pas diriger l'analyste vers un AS-REP roast impossible ici.
        ("--password-not-required",  "ldap_no_preauth.txt",  "Accounts with PASSWD_NOTREQD (password optional)"),
        ("--trusted-for-delegation", "ldap_delegation.txt",  "Accounts trusted for delegation"),
        ("--admin-count",            "ldap_admin_count.txt", "Accounts with adminCount=1"),
    ]

    for flag, filename, label in checks:
        log_info(f"Running nxc ldap {flag} ...")
        cmd = f"nxc ldap {targets} {cred} -d {shlex.quote(domain)} {flag} 2>/dev/null"
        out, _, rc = run(cmd, timeout=120)
        write_file(outdir / filename, out)
        if rc == 0 and out.strip():
            log_ok(f"  {label} → {outdir / filename}")
        else:
            log_warn(f"  {label} — no results or nxc error")

# ---------------------------------------------------------------------------
# STEP 5 — BloodHound collection
# ---------------------------------------------------------------------------

def step_bloodhound(hosts: list[str], user: str, password: str | None,
                    nt_hash: str | None, domain: str, outdir: Path,
                    host_map: dict[str, str] | None = None):
    log_step("STEP 5 — BloodHound collection")
    if not confirm_step("STEP 5 — BloodHound collection", f"bloodhound-python -u {user} -d {domain} -ns {hosts[0]} -c All --zip"):
        return
    bh_dir = outdir / "bloodhound"
    bh_dir.mkdir(parents=True, exist_ok=True)

    # host_map (STEP 1) identifie les vrais DC : préférer le premier à hosts[0],
    # qui n'est que la première cible brute du fichier.
    dc_ip = next(iter(host_map), hosts[0]) if host_map else hosts[0]
    cred = f"--hashes {shlex.quote(nt_hash)}" if nt_hash else f"-p {shlex.quote(password or '')}"

    cmd = (
        f"cd {shlex.quote(str(bh_dir))} && bloodhound-python "
        f"-u {shlex.quote(user)} {cred} -d {shlex.quote(domain)} -ns {shlex.quote(dc_ip)} -c All --zip"
    )
    log_info(f"Running bloodhound-python against {dc_ip} ...")
    out, err, rc = run(cmd, timeout=300)
    if rc == 0:
        log_ok(f"BloodHound data collected → {bh_dir}/")
    else:
        # stderr = seul diagnostic utile (creds, DC injoignable, ...) : l'afficher.
        log_warn(f"bloodhound-python exited with code {rc}: {(err or out).strip()[:300]}")
    # Save any stdout for reference
    if out.strip():
        write_file(bh_dir / "bloodhound_run.log", out)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_summary(outdir: Path, hosts: list[str], vulnerable_nb: list[str],
                  has_creds: bool):
    lines = [
        RULE,
        "LDAP Enumeration Summary",
        f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        RULE,
        f"Targets scanned  : {len(hosts)}",
        f"Hosts with null bind [CRITICAL]: {len(vulnerable_nb)}",
    ]
    if vulnerable_nb:
        lines.append("  Null-bind hosts:")
        for ip in sorted(vulnerable_nb):
            lines.append(f"    [CRITICAL] {ip}")

    lines += [
        "",
        f"Authenticated checks run: {'YES' if has_creds else 'NO'}",
        "",
        "Output files:",
        f"  {outdir}/ldap_domain_info.txt",
        f"  {outdir}/ldap_nullbind.txt",
    ]
    if has_creds:
        for f in ("ldap_users.txt", "ldap_groups.txt", "ldap_no_preauth.txt",
                  "ldap_delegation.txt", "ldap_admin_count.txt"):
            lines.append(f"  {outdir}/{f}")
    lines.append(RULE)

    summary = "\n".join(lines) + "\n"
    write_file(outdir / "ldap_summary.txt", summary)
    print("\n" + summary)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="check_ldap.py — LDAP null bind testing and AD enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s -t hosts_ldap.txt
  %(prog)s -t 192.168.1.10 -u admin -p 'Password1' -d corp.local
  %(prog)s -t 10.0.0.0/24 -u svc -H aad3b435b51404eeaad3b435b51404ee:abc123 -d lab.local
""",
    )
    p.add_argument("-t", "--target",   required=True,
                   help="Target: file of IPs, single IP, or CIDR")
    p.add_argument("-o", "--output",   default=None,
                   help="Output directory (default: ldap_results_<timestamp>)")
    p.add_argument("-u", "--username", default=None, help="Username")
    p.add_argument("-p", "--password", default=None, help="Password")
    p.add_argument("-H", "--hash",     default=None, help="NTLM hash LM:NT")
    p.add_argument("-d", "--domain",   default=None, help="Domain FQDN")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Non-interactive: accept all steps (for automation/UI)")
    return p.parse_args()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    if getattr(args, "yes", False):
        enable_auto_accept()

    # Output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output) if args.output else Path(f"ldap_results_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    log_ok(f"Output directory: {outdir.resolve()}")

    # Parse targets
    hosts = parse_targets(args.target)
    if not hosts:
        log_warn("No targets to process. Exiting.")
        sys.exit(0)
    log_info(f"Loaded {len(hosts)} target(s)")

    # Check required tools
    if not tool_exists("ldapsearch"):
        log_err("ldapsearch not found. Install ldap-utils (apt install ldap-utils).")
        sys.exit(1)

    # '' est un mot de passe valide en AD (comptes PASSWD_NOTREQD) : le tester
    # avec un simple `or` faisait sauter les étapes 4-5 pour -u svc -p '' .
    has_creds = bool(args.username and (args.password is not None or args.hash))

    # ---- STEP 1: rootDSE ----
    host_map = step_rootdse(hosts, outdir)

    # Auto-detect domain from rootDSE if not supplied
    domain = args.domain
    if not domain and host_map:
        for ip, base_dn in host_map.items():
            parts = re.findall(r'DC=([^,]+)', base_dn, re.IGNORECASE)
            if parts:
                domain = ".".join(parts)
                log_info(f"Auto-detected domain: {domain}")
                break

    # ---- STEP 2: Null bind test ----
    vulnerable_nb = step_nullbind(host_map, outdir)

    # ---- STEP 3: Null bind dump ----
    step_nullbind_dump(vulnerable_nb, host_map, outdir)

    # ---- STEP 4: Authenticated enum ----
    if has_creds:
        if not tool_exists("nxc"):
            log_warn("nxc not found — skipping authenticated enumeration.")
        elif not domain:
            log_warn("Domain not specified and could not be auto-detected — skipping nxc.")
        else:
            step_auth_enum(hosts, args.username, args.password, args.hash, domain, outdir)
    else:
        log_info("No credentials provided — skipping authenticated enumeration (Steps 4-5).")

    # ---- STEP 5: BloodHound ----
    if has_creds:
        if not tool_exists("bloodhound-python"):
            log_info("bloodhound-python not installed — skipping BloodHound collection.")
        elif not domain:
            log_warn("Domain unknown — skipping BloodHound collection.")
        else:
            step_bloodhound(hosts, args.username, args.password, args.hash, domain, outdir, host_map)

    # ---- Summary ----
    write_summary(outdir, hosts, vulnerable_nb, has_creds)

if __name__ == "__main__":
    main()
