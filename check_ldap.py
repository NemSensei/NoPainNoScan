#!/usr/bin/env python3
"""check_ldap.py - LDAP null bind testing and AD enumeration"""

import argparse, subprocess, sys, re
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Colors & logging
# ---------------------------------------------------------------------------

class C:
    HEADER = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN = '\033[92m'; WARN = '\033[93m'; FAIL = '\033[91m'
    ENDC = '\033[0m'; BOLD = '\033[1m'

def log_info(msg): print(f"{C.CYAN}[*]{C.ENDC} {msg}")
def log_ok(msg):   print(f"{C.GREEN}[+]{C.ENDC} {msg}")
def log_warn(msg): print(f"{C.WARN}[!]{C.ENDC} {msg}")
def log_err(msg):  print(f"{C.FAIL}[X]{C.ENDC} {msg}")
def log_step(msg): print(f"\n{C.HEADER}{C.BOLD}{'='*60}\n  {msg}\n{'='*60}{C.ENDC}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, timeout=600):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1

def tool_exists(name):
    out, _, rc = run(f"which {name}")
    return rc == 0

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
        out, _, _ = run(f"nmap -n -sL {target_arg} | awk '/Nmap scan report/{{print $NF}}'")
        ips = [l.strip() for l in out.splitlines() if l.strip()]
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
        return f"-u '{user}' -H '{nt_hash}'"
    return f"-u '{user}' -p '{password or ''}'"

def step_auth_enum(hosts: list[str], user: str, password: str | None,
                   nt_hash: str | None, domain: str, outdir: Path):
    log_step("STEP 4 — Authenticated enumeration (nxc ldap)")
    targets = " ".join(hosts)
    cred = build_cred_part(user, password, nt_hash)

    checks = [
        ("--users",                  "ldap_users.txt",       "Users"),
        ("--groups",                 "ldap_groups.txt",      "Groups"),
        ("--password-not-required",  "ldap_no_preauth.txt",  "Accounts without preauth (AS-REP roast)"),
        ("--trusted-for-delegation", "ldap_delegation.txt",  "Accounts trusted for delegation"),
        ("--admin-count",            "ldap_admin_count.txt", "Accounts with adminCount=1"),
    ]

    for flag, filename, label in checks:
        log_info(f"Running nxc ldap {flag} ...")
        cmd = f"nxc ldap {targets} {cred} -d '{domain}' {flag} 2>/dev/null"
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
                    nt_hash: str | None, domain: str, outdir: Path):
    log_step("STEP 5 — BloodHound collection")
    bh_dir = outdir / "bloodhound"
    bh_dir.mkdir(parents=True, exist_ok=True)

    dc_ip = hosts[0]
    cred = f"--hashes '{nt_hash}'" if nt_hash else f"-p '{password or ''}'"

    cmd = (
        f"cd '{bh_dir}' && bloodhound-python "
        f"-u '{user}' {cred} -d '{domain}' -ns {dc_ip} -c All --zip 2>/dev/null"
    )
    log_info(f"Running bloodhound-python against {dc_ip} ...")
    out, _, rc = run(cmd, timeout=300)
    if rc == 0:
        log_ok(f"BloodHound data collected → {bh_dir}/")
    else:
        log_warn(f"bloodhound-python exited with code {rc}. Check {bh_dir}/.")
    # Save any stdout for reference
    if out.strip():
        write_file(bh_dir / "bloodhound_run.log", out)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_summary(outdir: Path, hosts: list[str], vulnerable_nb: list[str],
                  has_creds: bool):
    lines = [
        "=" * 60,
        "  LDAP ENUMERATION SUMMARY",
        f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
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
    lines.append("=" * 60)

    summary = "\n".join(lines) + "\n"
    write_file(outdir / "ldap_summary.txt", summary)
    print(f"\n{C.BOLD}{summary}{C.ENDC}")

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
    return p.parse_args()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

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

    has_creds = bool(args.username and (args.password or args.hash))

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
            step_bloodhound(hosts, args.username, args.password, args.hash, domain, outdir)

    # ---- Summary ----
    write_summary(outdir, hosts, vulnerable_nb, has_creds)

if __name__ == "__main__":
    main()
