#!/usr/bin/env python3
"""check_smb.py - SMB enumeration and vulnerability checks

Usage:
    python3 check_smb.py -t hosts_smb.txt
    python3 check_smb.py -t 192.168.1.0/24 -u admin -p 'P@ssw0rd' -d CORP

Workflow:
    1. SMB info + signing check (always, no creds needed)
       - Detect signing:False → relay targets
       - Detect SMBv1:True → legacy hosts
    2. Null session share listing (no creds)
    3. Authenticated share enumeration (with creds)
       - READ access shares
       - WRITE access shares (critical)
    4. SYSVOL/NETLOGON browsing (with creds)
    5. Spider plus — interesting files discovery (with creds)

Output files:
    smb_unsigned.txt       IPs with SMB signing disabled (relay targets)
    smb_v1.txt             IPs with SMBv1 enabled
    smb_hosts_info.txt     Full host info table
    smb_shares_null.txt    Shares accessible via null session
    smb_shares_read.txt    Shares readable with creds
    smb_shares_write.txt   Shares writable with creds [CRITICAL]
    sysvol_files.txt       Interesting files in SYSVOL/NETLOGON
    smb_spider.txt         Interesting files from spider_plus
    smb_summary.txt        Human-readable findings summary
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


# =============================================================================
# COLOURS
# =============================================================================
class C:
    HEADER = '\033[95m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    WARN   = '\033[93m'
    FAIL   = '\033[91m'
    ENDC   = '\033[0m'
    BOLD   = '\033[1m'


# =============================================================================
# LOGGING
# =============================================================================
def _ts():
    return datetime.now().strftime("%H:%M:%S")

def log_info(msg):  print(f"{C.CYAN}[{_ts()}][*]{C.ENDC} {msg}")
def log_ok(msg):    print(f"{C.GREEN}[{_ts()}][+]{C.ENDC} {msg}")
def log_warn(msg):  print(f"{C.WARN}[{_ts()}][!]{C.ENDC} {msg}")
def log_err(msg):   print(f"{C.FAIL}[{_ts()}][X]{C.ENDC} {msg}")

def log_step(msg):
    print(f"\n{C.HEADER}{C.BOLD}{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}{C.ENDC}")


# =============================================================================
# UTILITIES
# =============================================================================
def run(cmd, timeout=600):
    """Run a shell command. Returns (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1
    except Exception as e:
        return "", str(e), 1


def tool_exists(name):
    _, _, rc = run(f"which {name}")
    return rc == 0


def sort_ips(ips):
    """Sort IPs numerically, discard invalid entries."""
    valid = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip.strip())
            valid.append(ip.strip())
        except ValueError:
            pass
    return sorted(set(valid), key=lambda x: ipaddress.ip_address(x))


def write_file(path, lines, sort=True, label=None):
    """Write deduplicated lines to file. IP-sort when sort=True, else preserve order."""
    cleaned = [l for l in lines if l.strip()]
    if sort:
        cleaned = sort_ips(cleaned)
    else:
        cleaned = list(dict.fromkeys(cleaned))
    Path(path).write_text("\n".join(cleaned) + ("\n" if cleaned else ""))
    if label:
        log_ok(f"{label}: {len(cleaned)} entries → {Path(path).name}")
    return cleaned


def load_hosts(target):
    """Load hosts from a file path, single IP, or CIDR range.

    Returns a list of IP strings (or hostnames from file).
    """
    # Is it a file?
    p = Path(target)
    if p.exists() and p.is_file():
        lines = [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith('#')]
        return lines

    # Is it a CIDR?
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass

    # Single IP / hostname
    return [target]


def hosts_to_tmpfile(hosts):
    """Write a list of hosts to a temporary file and return its path."""
    tf = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    tf.write("\n".join(hosts) + "\n")
    tf.close()
    return tf.name


def build_creds_args(args):
    """Build nxc credential arguments string."""
    parts = []
    if args.username:
        parts += ["-u", args.username]
    if args.hash:
        parts += ["-H", args.hash]
    elif args.password is not None:
        parts += ["-p", f"'{args.password}'"]
    if args.domain:
        parts += ["-d", args.domain]
    return " ".join(parts)


# =============================================================================
# STEP 1 — SMB INFO + SIGNING
# =============================================================================
def step1_smb_info(hosts_file, out_dir):
    """Collect SMB host info, detect signing:False and SMBv1:True."""
    log_step("STEP 1 — SMB Info + Signing Check")

    unsigned_ips = []
    smbv1_ips    = []
    host_rows    = []

    relay_file = out_dir / "smb_unsigned.txt"

    # Single run: --gen-relay-list also prints full host info on stdout
    log_info("Running nxc smb (host details + relay list) ...")
    out, err, rc = run(f"nxc smb '{hosts_file}' --gen-relay-list '{relay_file}'", timeout=300)
    if rc != 0 and "TIMEOUT" not in err:
        log_warn(f"nxc smb returned rc={rc}")

    # SMB  192.168.1.10  445  DC01  [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:CORP) (signing:True) (SMBv1:False)
    pattern = re.compile(
        r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\[\*\]\s+(.*?)"
        r"\(signing:(\w+)\).*?\(SMBv1:(\w+)\)"
    )

    for line in out.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        ip, hostname, os_info, signing, smbv1 = m.groups()
        os_info = os_info.strip()
        host_rows.append(f"{ip:<18} {hostname:<20} {signing:<8} {smbv1:<8} {os_info}")

        if signing.lower() == "false":
            unsigned_ips.append(ip)
        if smbv1.lower() == "true":
            smbv1_ips.append(ip)

    # Merge with nxc-generated relay file in case it differs
    if relay_file.exists():
        existing = [l.strip() for l in relay_file.read_text().splitlines() if l.strip()]
        unsigned_ips = list(set(unsigned_ips + existing))

    write_file(out_dir / "smb_unsigned.txt", unsigned_ips, label="Signing disabled")
    write_file(out_dir / "smb_v1.txt", smbv1_ips, label="SMBv1 enabled")

    # Host info table
    header = f"{'IP':<18} {'Hostname':<20} {'Signing':<8} {'SMBv1':<8} OS\n" + "-"*80
    info_path = out_dir / "smb_hosts_info.txt"
    info_path.write_text(header + "\n" + "\n".join(host_rows) + "\n")
    log_ok(f"Host info: {len(host_rows)} hosts → smb_hosts_info.txt")

    return unsigned_ips, smbv1_ips, host_rows


# =============================================================================
# STEP 2 — NULL SESSION SHARES
# =============================================================================
def step2_null_session(hosts_file, out_dir):
    """Enumerate shares via null session."""
    log_step("STEP 2 — Null Session Share Listing")

    out, err, rc = run(f"nxc smb '{hosts_file}' --shares -u '' -p ''", timeout=300)

    shares = []
    # Parse share lines:
    # SMB  192.168.1.10  445  DC01  [*] Enumerated shares
    # SMB  192.168.1.10  445  DC01  Share           Permissions     Remark
    # SMB  192.168.1.10  445  DC01  -----           -----------     ------
    # SMB  192.168.1.10  445  DC01  ADMIN$                          Remote Admin
    # SMB  192.168.1.10  445  DC01  IPC$            READ            Remote IPC
    share_line = re.compile(
        r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(\S+)\s+(READ|WRITE|READ,WRITE)"
    )
    for line in out.splitlines():
        m = share_line.search(line)
        if m:
            ip, share, perms = m.groups()
            shares.append(f"{ip}  {share}  [{perms}]")

    write_file(out_dir / "smb_shares_null.txt", shares, sort=False, label="Null session shares")
    return shares


# =============================================================================
# STEP 3 — AUTHENTICATED SHARE ENUMERATION
# =============================================================================
def step3_auth_shares(hosts_file, out_dir, creds_args):
    """Enumerate shares with credentials, separate READ vs WRITE."""
    log_step("STEP 3 — Authenticated Share Enumeration")

    out, err, rc = run(f"nxc smb '{hosts_file}' {creds_args} --shares", timeout=300)

    read_shares  = []
    write_shares = []

    share_line = re.compile(
        r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(\S+)\s+(READ(?:,WRITE)?|WRITE)"
    )
    for line in out.splitlines():
        m = share_line.search(line)
        if not m:
            continue
        ip, share, perms = m.groups()
        entry = f"{ip}  {share}  [{perms}]"
        if "WRITE" in perms:
            write_shares.append(entry)
        else:
            read_shares.append(entry)

    write_file(out_dir / "smb_shares_read.txt", read_shares, sort=False, label="Readable shares")
    write_file(out_dir / "smb_shares_write.txt", write_shares, sort=False, label="Writable shares [CRITICAL]")

    if write_shares:
        log_warn(f"[CRITICAL] {len(write_shares)} writable share(s) found!")

    return read_shares, write_shares


# =============================================================================
# STEP 4 — SYSVOL / NETLOGON
# =============================================================================
def step4_sysvol(hosts_file, out_dir, creds_args):
    """Browse SYSVOL and look for interesting scripts."""
    log_step("STEP 4 — SYSVOL/NETLOGON Browsing")

    sysvol_files = []

    # Run spider_plus module on all hosts
    log_info("Running spider_plus module ...")
    out, err, rc = run(
        f"nxc smb '{hosts_file}' {creds_args} -M spider_plus",
        timeout=600
    )

    # Collect lines mentioning SYSVOL or NETLOGON files
    for line in out.splitlines():
        if re.search(r'(SYSVOL|NETLOGON)', line, re.IGNORECASE):
            sysvol_files.append(line.strip())

    # Spider SYSVOL specifically for interesting extensions on all hosts
    log_info("Spidering SYSVOL for scripts/configs ...")
    out2, err2, rc2 = run(
        f"nxc smb '{hosts_file}' {creds_args} --spider SYSVOL "
        f"--pattern '.ps1,.vbs,.bat,.xml,.txt'",
        timeout=600
    )

    interesting_exts = re.compile(r'\.(ps1|vbs|bat|xml|txt)$', re.IGNORECASE)
    for line in out2.splitlines():
        if interesting_exts.search(line):
            sysvol_files.append(line.strip())

    # Dedup
    sysvol_files = list(dict.fromkeys(sysvol_files))
    write_file(out_dir / "sysvol_files.txt", sysvol_files, sort=False, label="SYSVOL files")

    return sysvol_files


# =============================================================================
# STEP 5 — SPIDER PLUS SUMMARY
# =============================================================================
def step5_spider_summary(out_dir):
    """Parse spider_plus JSON output for interesting files."""
    log_step("STEP 5 — Spider Plus Summary")

    interesting = []

    # nxc spider_plus writes JSON to /tmp/nxc_spider_plus or ~/.nxc/logs
    spider_dirs = [
        Path("/tmp/nxc_spider_plus"),
        Path.home() / ".nxc" / "logs",
        Path.home() / ".nxc" / "modules",
    ]

    json_files = []
    for d in spider_dirs:
        if d.exists():
            json_files += list(d.glob("*spider_plus*"))
            json_files += list(d.glob("*SPIDER*"))

    for jf in json_files:
        try:
            data = json.loads(jf.read_text())
            for host, shares in data.items():
                for share, files in shares.items():
                    for fname, meta in (files.items() if isinstance(files, dict) else []):
                        size = meta.get("size", 0) if isinstance(meta, dict) else 0
                        interesting.append(f"{host}  \\\\{share}\\{fname}  ({size} bytes)")
        except Exception:
            continue

    write_file(out_dir / "smb_spider.txt", interesting, sort=False, label="Spider plus files")
    return interesting


# =============================================================================
# SUMMARY
# =============================================================================
def write_summary(out_dir, unsigned, smbv1, null_shares, read_shares, write_shares,
                  sysvol_files, spider_files, has_creds):
    """Write a human-readable summary file and print it."""
    log_step("SUMMARY")

    lines = [
        f"SMB Enumeration Summary — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
        f"[SIGNING]  Hosts with SMB signing DISABLED (relay targets): {len(unsigned)}",
        f"[SMBv1]    Hosts with SMBv1 ENABLED:                         {len(smbv1)}",
        f"[NULL]     Shares accessible via null session:               {len(null_shares)}",
    ]

    if has_creds:
        lines += [
            f"[AUTH]     Readable shares (with creds):                   {len(read_shares)}",
            f"[CRITICAL] Writable shares (with creds):                   {len(write_shares)}",
            f"[SYSVOL]   Interesting SYSVOL/NETLOGON files:              {len(sysvol_files)}",
            f"[SPIDER]   Files found via spider_plus:                    {len(spider_files)}",
        ]

    lines += ["", "Output directory: " + str(out_dir)]

    if unsigned:
        lines += ["", "[!] RELAY TARGETS (signing disabled):"]
        lines += [f"    {ip}" for ip in unsigned[:20]]
        if len(unsigned) > 20:
            lines.append(f"    ... and {len(unsigned) - 20} more (see smb_unsigned.txt)")

    if smbv1:
        lines += ["", "[!] SMBv1 HOSTS (EternalBlue risk):"]
        lines += [f"    {ip}" for ip in smbv1[:20]]

    if write_shares:
        lines += ["", "[CRITICAL] WRITABLE SHARES:"]
        lines += [f"    {s}" for s in write_shares]

    summary_text = "\n".join(lines)
    (out_dir / "smb_summary.txt").write_text(summary_text + "\n")
    print(summary_text)


# =============================================================================
# ARGUMENT PARSING
# =============================================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="check_smb.py — SMB enumeration and vulnerability checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 check_smb.py -t hosts_smb.txt
  python3 check_smb.py -t 192.168.1.0/24 -u admin -p 'P@ss' -d CORP
  python3 check_smb.py -t 192.168.1.10 -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
        """
    )
    p.add_argument("-t", "--target", required=True,
                   help="Hosts file (one IP per line), single IP, or CIDR range")
    p.add_argument("-o", "--output",
                   help="Output directory (default: ./smb_results_<timestamp>)")
    p.add_argument("-u", "--username", help="Username for authenticated checks")
    p.add_argument("-p", "--password", help="Password for authenticated checks")
    p.add_argument("-H", "--hash", help="NTLM hash LM:NT for pass-the-hash")
    p.add_argument("-d", "--domain", default="WORKGROUP",
                   help="Domain (default: WORKGROUP)")
    p.add_argument("--threads", type=int, default=10,
                   help="Number of parallel threads for nxc (default: 10)")
    return p.parse_args()


# =============================================================================
# MAIN
# =============================================================================
def main():
    args = parse_args()

    # --- Output directory ---
    if args.output:
        out_dir = Path(args.output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path(f"smb_results_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Output directory: {out_dir.resolve()}")

    # --- Load hosts ---
    hosts = load_hosts(args.target)
    if not hosts:
        log_warn("No hosts loaded — target file is empty or target is invalid. Exiting.")
        sys.exit(0)
    log_info(f"Loaded {len(hosts)} host(s) from target: {args.target}")

    # Write hosts to temp file for nxc consumption
    hosts_tmp = hosts_to_tmpfile(hosts)

    # --- Check nxc availability ---
    if not tool_exists("nxc"):
        # Try netexec alias
        if tool_exists("netexec"):
            log_warn("'nxc' not found, but 'netexec' found — please create alias: ln -s $(which netexec) /usr/local/bin/nxc")
        log_err("nxc (NetExec) not found. Install: pip install netexec")
        log_warn("Skipping all nxc checks. Install nxc to proceed.")
        # Still create empty output files so callers don't break
        for fname in ["smb_unsigned.txt", "smb_v1.txt", "smb_hosts_info.txt",
                      "smb_shares_null.txt", "smb_shares_read.txt",
                      "smb_shares_write.txt", "sysvol_files.txt",
                      "smb_spider.txt", "smb_summary.txt"]:
            (out_dir / fname).write_text("")
        sys.exit(1)

    has_creds = bool(args.username and (args.password is not None or args.hash))
    creds_args = build_creds_args(args) if has_creds else ""

    unsigned, smbv1, host_rows = step1_smb_info(hosts_tmp, out_dir)
    null_shares = step2_null_session(hosts_tmp, out_dir)

    read_shares  = []
    write_shares = []
    sysvol_files = []
    spider_files = []

    if has_creds:
        read_shares, write_shares = step3_auth_shares(hosts_tmp, out_dir, creds_args)
        sysvol_files = step4_sysvol(hosts_tmp, out_dir, creds_args)
        spider_files = step5_spider_summary(out_dir)
    else:
        log_info("No credentials provided — skipping authenticated checks (steps 3-5)")
        for fname in ["smb_shares_read.txt", "smb_shares_write.txt",
                      "sysvol_files.txt", "smb_spider.txt"]:
            (out_dir / fname).write_text("")

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    write_summary(out_dir, unsigned, smbv1, null_shares, read_shares, write_shares,
                  sysvol_files, spider_files, has_creds)

    # Cleanup temp file
    try:
        os.unlink(hosts_tmp)
    except OSError:
        pass

    log_ok(f"Done. Results in: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
