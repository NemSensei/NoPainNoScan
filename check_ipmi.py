#!/usr/bin/env python3
"""check_ipmi.py - IPMI vulnerability assessment (cipher zero, RAKP, default creds)"""

import argparse, subprocess, os, sys, re, ipaddress
from datetime import datetime
from pathlib import Path

class C:
    HEADER = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN = '\033[92m'; WARN = '\033[93m'; FAIL = '\033[91m'
    ENDC = '\033[0m'; BOLD = '\033[1m'

def log_info(msg): print(f"{C.CYAN}[*]{C.ENDC} {msg}")
def log_ok(msg):   print(f"{C.GREEN}[+]{C.ENDC} {msg}")
def log_warn(msg): print(f"{C.WARN}[!]{C.ENDC} {msg}")
def log_err(msg):  print(f"{C.FAIL}[X]{C.ENDC} {msg}")
def log_step(msg): print(f"\n{C.HEADER}{C.BOLD}{'='*60}\n  {msg}\n{'='*60}{C.ENDC}")

def run(cmd, timeout=30):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1

def tool_exists(name):
    out, _, rc = run(f"which {name}")
    return rc == 0


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def parse_targets(target_arg: str) -> list:
    """Return a flat list of IP strings from file, single IP, or CIDR."""
    targets = []

    # File
    p = Path(target_arg)
    if p.is_file():
        lines = p.read_text().splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            targets.extend(_expand(line))
        return targets

    # CIDR or single IP
    return _expand(target_arg)


def _expand(token: str) -> list:
    """Expand a CIDR or return a single IP string."""
    try:
        net = ipaddress.ip_network(token, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]
    except ValueError:
        # Maybe it's a hostname
        return [token]


# ---------------------------------------------------------------------------
# STEP 1 — IPMI presence / version probe
# ---------------------------------------------------------------------------

def check_ipmi_info(ip: str) -> tuple:
    """Return (output_str, is_present)."""
    cmd = f"ipmitool -I lanplus -H {ip} -U '' -P '' -C 3 chassis status 2>&1"
    out, err, rc = run(cmd, timeout=15)
    combined = (out + err).strip()
    # "Get Session Info command failed" or "chassis" output both indicate IPMI presence
    # A refused connection / no route means absent
    absent_markers = ["Unable to establish", "timed out", "TIMEOUT", "No route", "Connection refused"]
    present = rc == 0 or any(m.lower() not in combined.lower() for m in absent_markers)
    # More reliable: if we got any IPMI-layer response it's present
    ipmi_response = any(k in combined.lower() for k in [
        "chassis", "session", "unauthorized", "rakp", "authentication", "rmcp", "error"
    ])
    return combined, ipmi_response


# ---------------------------------------------------------------------------
# STEP 2 — Cipher Zero (CVE-2013-4786)
# ---------------------------------------------------------------------------

def check_cipher_zero(ip: str, username: str = "ADMIN") -> tuple:
    """Return (output_str, is_vulnerable)."""
    cmd = f"ipmitool -I lanplus -C 0 -H {ip} -U {username} -P anypassword chassis status 2>&1"
    out, err, rc = run(cmd, timeout=15)
    combined = (out + err).strip()
    # Success (rc==0 and actual chassis output) = vulnerable
    vulnerable = rc == 0 and any(k in combined.lower() for k in ["system power", "chassis", "power state"])
    return combined, vulnerable


# ---------------------------------------------------------------------------
# STEP 3 — Anonymous / null auth
# ---------------------------------------------------------------------------

def check_anonymous_auth(ip: str) -> tuple:
    """Return (output_str, is_vulnerable) — tries empty and 'anonymous' user."""
    results = []
    vulnerable = False

    for user in ['', 'anonymous']:
        label = f"user='{user}'"
        cmd = f"ipmitool -I lanplus -H {ip} -U '{user}' -P '' chassis status 2>&1"
        out, err, rc = run(cmd, timeout=15)
        combined = (out + err).strip()
        success = rc == 0 and any(k in combined.lower() for k in ["system power", "chassis", "power state"])
        results.append(f"  [{label}] rc={rc} -> {combined[:200]}")
        if success:
            vulnerable = True

    return "\n".join(results), vulnerable


# ---------------------------------------------------------------------------
# STEP 4 — RAKP hash capture
# ---------------------------------------------------------------------------

RAKP_USERS = ["ADMIN", "admin", "Administrator", "root", "USERID"]

def capture_rakp_hash(ip: str, usernames: list) -> list:
    """
    Attempt RAKP hash capture.
    Returns list of (username, hash_line) tuples for cracking.
    ipmitool with -vvv prints the RAKP exchange; we extract the HMAC/hash.
    If ipmipwner is available, use it instead.
    """
    hashes = []

    # Prefer ipmipwner if available
    if tool_exists("ipmipwner"):
        for user in usernames:
            cmd = f"ipmipwner --target {ip} --user {user} 2>&1"
            out, err, rc = run(cmd, timeout=30)
            combined = (out + err).strip()
            # ipmipwner outputs hashcat-ready hashes
            for line in combined.splitlines():
                if "$rakp$" in line or "RAKP" in line.upper():
                    hashes.append((user, line.strip()))
        return hashes

    # Fallback: use ipmitool -vvv and parse RAKP material from stderr
    for user in usernames:
        cmd = f"ipmitool -I lanplus -H {ip} -U '{user}' -P 'dummypassword' -vvv chassis status 2>&1"
        out, err, rc = run(cmd, timeout=20)
        combined = out + err

        # Look for RAKP 2 error — means server responded with HMAC material
        # The hash is not directly in ipmitool output, but we can note the
        # server acknowledged the user exists (RAKP 2 response without error).
        # Real hash capture requires a raw socket implementation or Metasploit.
        # We record what we can.
        if "rakp 2" in combined.lower():
            # Try to find hex data patterns that look like HMAC material
            hex_lines = re.findall(r'[0-9a-fA-F]{32,}', combined)
            hash_candidate = " ".join(hex_lines[:4]) if hex_lines else "(hash material present but not extracted)"
            hashes.append((user, f"RAKP2 response for user '{user}' on {ip}: {hash_candidate}"))
        elif "rakp 2 message indicates an error" not in combined.lower() and \
             "authentication" in combined.lower():
            hashes.append((user, f"Possible RAKP exchange for user '{user}' on {ip} (verify manually)"))

    return hashes


# ---------------------------------------------------------------------------
# STEP 5 — Default credentials
# ---------------------------------------------------------------------------

DEFAULT_CREDS = [
    ("ADMIN",         "ADMIN"),       # Supermicro
    ("admin",         "admin"),       # iDRAC / iLO
    ("root",          "calvin"),      # Dell iDRAC
    ("USERID",        "PASSW0RD"),    # IBM IMM
    ("admin",         "password"),
    ("Administrator", ""),
    ("root",          ""),
    ("admin",         ""),
]

def check_default_creds(ip: str, extra_user: str = None, extra_pass: str = None) -> list:
    """
    Try default credential pairs.
    Returns list of (user, password) that worked.
    """
    creds_to_try = list(DEFAULT_CREDS)
    if extra_user and extra_pass:
        creds_to_try.insert(0, (extra_user, extra_pass))
    elif extra_user:
        for p in ["", "admin", "ADMIN", "password", "calvin", "PASSW0RD"]:
            creds_to_try.insert(0, (extra_user, p))

    valid = []
    for user, passwd in creds_to_try:
        cmd = f"ipmitool -I lanplus -H {ip} -U '{user}' -P '{passwd}' chassis status 2>&1"
        out, err, rc = run(cmd, timeout=15)
        combined = (out + err).strip()
        if rc == 0 and any(k in combined.lower() for k in ["system power", "chassis", "power state"]):
            valid.append((user, passwd))
            log_ok(f"  {ip} — valid creds: {user}:{passwd}")

    return valid


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_file(path: Path, lines: list):
    """Write deduplicated, sorted lines to file."""
    unique = sorted(set(l for l in lines if l.strip()))
    path.write_text("\n".join(unique) + ("\n" if unique else ""))


def append_file(path: Path, text: str):
    with open(path, "a") as f:
        f.write(text + "\n")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_checks(targets: list, output_dir: Path, usernames: list, password: str = None):
    output_dir.mkdir(parents=True, exist_ok=True)

    f_info    = output_dir / "ipmi_hosts_info.txt"
    f_cipher0 = output_dir / "ipmi_cipher0.txt"
    f_anon    = output_dir / "ipmi_anonymous.txt"
    f_hashes  = output_dir / "ipmi_hashes.txt"
    f_defcred = output_dir / "ipmi_default_creds.txt"
    f_summary = output_dir / "ipmi_summary.txt"

    # Initialise files
    for f in [f_info, f_cipher0, f_anon, f_hashes, f_defcred, f_summary]:
        f.write_text("")

    stats = {
        "total": len(targets),
        "present": 0,
        "cipher0_vuln": 0,
        "anon_vuln": 0,
        "hashes_captured": 0,
        "default_creds": 0,
    }

    # ---- STEP 1 ----
    log_step("STEP 1/5 — IPMI presence probe")
    present_hosts = []
    for ip in targets:
        log_info(f"Probing {ip} ...")
        info_out, is_present = check_ipmi_info(ip)
        line = f"{ip} | present={is_present} | {info_out[:300].replace(chr(10), ' ')}"
        append_file(f_info, line)
        if is_present:
            present_hosts.append(ip)
            stats["present"] += 1
            log_ok(f"  {ip} — IPMI responded")
        else:
            log_warn(f"  {ip} — no IPMI response")

    if not present_hosts:
        log_warn("No IPMI hosts found. Exiting.")
        _write_summary(f_summary, stats, targets)
        return

    log_info(f"{len(present_hosts)} host(s) with IPMI presence, continuing checks.")

    # ---- STEP 2 ----
    log_step("STEP 2/5 — Cipher Zero vulnerability (CVE-2013-4786)")
    cipher0_vuln = []
    for ip in present_hosts:
        log_info(f"Testing cipher zero on {ip} ...")
        for user in usernames:
            out, vuln = check_cipher_zero(ip, user)
            if vuln:
                line = f"[CRITICAL] {ip} VULNERABLE to cipher zero (user={user})"
                append_file(f_cipher0, line)
                cipher0_vuln.append(ip)
                stats["cipher0_vuln"] += 1
                log_ok(f"  {ip} — CIPHER ZERO VULNERABLE with user={user}")
                break
            else:
                log_info(f"  {ip} user={user}: not vulnerable (or no response)")

    # ---- STEP 3 ----
    log_step("STEP 3/5 — Anonymous / null authentication")
    anon_vuln = []
    for ip in present_hosts:
        log_info(f"Testing anonymous auth on {ip} ...")
        out, vuln = check_anonymous_auth(ip)
        if vuln:
            line = f"[CRITICAL] {ip} ALLOWS anonymous/null authentication\n{out}"
            append_file(f_anon, line)
            anon_vuln.append(ip)
            stats["anon_vuln"] += 1
            log_ok(f"  {ip} — ANONYMOUS AUTH VULNERABLE")
        else:
            log_info(f"  {ip} — anonymous auth not successful")

    # ---- STEP 4 ----
    log_step("STEP 4/5 — RAKP hash capture")
    for ip in present_hosts:
        log_info(f"Attempting RAKP hash capture on {ip} ...")
        hashes = capture_rakp_hash(ip, usernames)
        if hashes:
            for user, hline in hashes:
                append_file(f_hashes, f"[CRITICAL] {ip} | user={user} | {hline}")
                stats["hashes_captured"] += 1
                log_ok(f"  {ip} — RAKP hash material for user={user}")
        else:
            log_info(f"  {ip} — no RAKP hash material captured")

    # ---- STEP 5 ----
    log_step("STEP 5/5 — Default credentials")
    for ip in present_hosts:
        log_info(f"Testing default credentials on {ip} ...")
        extra_user = usernames[0] if usernames else None
        valid = check_default_creds(ip, extra_user=extra_user, extra_pass=password)
        if valid:
            for user, passwd in valid:
                append_file(f_defcred, f"[CRITICAL] {ip} | {user}:{passwd}")
                stats["default_creds"] += 1

    # ---- SUMMARY ----
    _write_summary(f_summary, stats, targets, cipher0_vuln, anon_vuln)
    log_step("DONE")
    log_info(f"Results written to: {output_dir}")
    _print_summary(stats, output_dir)


def _write_summary(path: Path, stats: dict, targets: list,
                   cipher0: list = None, anon: list = None):
    lines = [
        "=" * 60,
        "  IPMI Vulnerability Assessment — Summary",
        f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        f"Targets scanned  : {stats['total']}",
        f"IPMI present     : {stats['present']}",
        f"Cipher Zero vuln : {stats['cipher0_vuln']}",
        f"Anon auth vuln   : {stats['anon_vuln']}",
        f"RAKP hashes      : {stats['hashes_captured']}",
        f"Default creds    : {stats['default_creds']}",
        "",
    ]
    if cipher0:
        lines += ["[CRITICAL] Cipher Zero vulnerable hosts:"] + [f"  - {h}" for h in cipher0] + [""]
    if anon:
        lines += ["[CRITICAL] Anonymous auth vulnerable hosts:"] + [f"  - {h}" for h in anon] + [""]
    path.write_text("\n".join(lines))


def _print_summary(stats: dict, output_dir: Path):
    print(f"\n{C.BOLD}{'='*60}")
    print(f"  Summary")
    print(f"{'='*60}{C.ENDC}")
    print(f"  Targets scanned  : {stats['total']}")
    print(f"  IPMI present     : {stats['present']}")
    c = C.FAIL if stats['cipher0_vuln'] else C.GREEN
    print(f"  {c}Cipher Zero vuln : {stats['cipher0_vuln']}{C.ENDC}")
    c = C.FAIL if stats['anon_vuln'] else C.GREEN
    print(f"  {c}Anon auth vuln   : {stats['anon_vuln']}{C.ENDC}")
    c = C.WARN if stats['hashes_captured'] else C.GREEN
    print(f"  {c}RAKP hashes      : {stats['hashes_captured']}{C.ENDC}")
    c = C.FAIL if stats['default_creds'] else C.GREEN
    print(f"  {c}Default creds    : {stats['default_creds']}{C.ENDC}")
    print(f"\n  Output dir: {output_dir}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="check_ipmi.py — IPMI vulnerability assessment (cipher zero, RAKP, default creds)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 check_ipmi.py -t hosts_ipmi.txt
  python3 check_ipmi.py -t 192.168.1.50
  python3 check_ipmi.py -t 192.168.1.0/24 -o /tmp/ipmi_out
  python3 check_ipmi.py -t 192.168.1.50 -u ADMIN -p ADMIN
        """,
    )
    p.add_argument("-t", "--target", required=True,
                   help="File with IPs (one per line), single IP, or CIDR")
    p.add_argument("-o", "--output",
                   default=f"./ipmi_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                   help="Output directory (default: ./ipmi_results_<timestamp>)")
    p.add_argument("-u", "--username",
                   default="ADMIN,admin,Administrator,root",
                   help="Comma-separated usernames to test (default: ADMIN,admin,Administrator,root)")
    p.add_argument("-p", "--password", default=None,
                   help="Password to test alongside default creds (optional)")
    return p.parse_args()


def main():
    args = parse_args()

    # Dependency check
    if not tool_exists("ipmitool"):
        log_err("ipmitool is not installed. Install it with: apt install ipmitool")
        log_warn("Some checks will not work without ipmitool.")

    # Parse usernames
    usernames = [u.strip() for u in args.username.split(",") if u.strip()]
    if not usernames:
        usernames = ["ADMIN", "admin", "Administrator", "root"]

    # Parse targets
    targets = parse_targets(args.target)
    if not targets:
        log_err(f"No targets found in: {args.target}")
        sys.exit(1)

    log_info(f"Loaded {len(targets)} target(s) from: {args.target}")
    log_info(f"Usernames to test: {', '.join(usernames)}")
    log_info(f"Output directory : {args.output}")

    run_checks(
        targets=targets,
        output_dir=Path(args.output),
        usernames=usernames,
        password=args.password,
    )


if __name__ == "__main__":
    main()
