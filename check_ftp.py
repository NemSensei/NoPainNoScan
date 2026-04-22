#!/usr/bin/env python3
"""check_ftp.py - FTP anonymous access testing and enumeration"""

import argparse, subprocess, os, sys, re, ftplib, socket
from datetime import datetime
from pathlib import Path
import ipaddress

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

def parse_targets(target_arg):
    """Return a list of IP strings from a file path, CIDR, or single IP."""
    targets = []

    # File path?
    p = Path(target_arg)
    if p.exists() and p.is_file():
        lines = p.read_text().splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            targets.extend(_expand_target(line))
        return targets

    return _expand_target(target_arg)


def _expand_target(s):
    """Expand a single IP or CIDR string into a list of IPs."""
    try:
        net = ipaddress.ip_network(s, strict=False)
        # Avoid expanding huge ranges
        if net.num_addresses > 1024:
            log_warn(f"CIDR {s} has {net.num_addresses} hosts — limiting to first 1024")
            return [str(h) for h in list(net.hosts())[:1024]]
        return [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        return [s]


# ---------------------------------------------------------------------------
# STEP 1 — Banner grab
# ---------------------------------------------------------------------------

def grab_banner(ip, timeout=10):
    """Return (banner_str, ftp_obj_connected_not_logged_in) or (None, None)."""
    try:
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(ip, 21, timeout=timeout)
        banner = ftp.getwelcome()
        return banner, ftp
    except Exception as e:
        return None, None


# ---------------------------------------------------------------------------
# STEP 2 — Anonymous / credential login
# ---------------------------------------------------------------------------

ANON_CREDS = [
    ('anonymous', 'anonymous@'),
    ('', ''),
    ('ftp', 'ftp'),
]

def try_login(ftp, user, password):
    """Attempt login on an already-connected FTP object. Returns True on success."""
    try:
        ftp.login(user, password)
        return True
    except ftplib.error_perm:
        return False
    except Exception:
        return False


def test_anonymous_login(ip, timeout=10):
    """Try all anonymous credential variants. Returns (success, cred_tuple, ftp) or (False, None, None)."""
    for user, pwd in ANON_CREDS:
        try:
            ftp = ftplib.FTP(timeout=timeout)
            ftp.connect(ip, 21, timeout=timeout)
            if try_login(ftp, user, pwd):
                return True, (user, pwd), ftp
            ftp.close()
        except Exception:
            pass
    return False, None, None


def test_custom_login(ip, user, password, timeout=10):
    """Try a specific credential pair. Returns (success, ftp) or (False, None)."""
    try:
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(ip, 21, timeout=timeout)
        if try_login(ftp, user, password):
            return True, ftp
        ftp.close()
    except Exception:
        pass
    return False, None


# ---------------------------------------------------------------------------
# STEP 3 — File listing & write-access check
# ---------------------------------------------------------------------------

INTERESTING_EXTENSIONS = {
    '.conf', '.config', '.txt', '.log', '.bak', '.key',
    '.pem', '.db', '.sql', '.xlsx', '.docx', '.pdf',
}

def list_files_recursive(ftp, path='/', depth=0, max_depth=3):
    """Return list of (path, is_dir) tuples up to max_depth."""
    if depth > max_depth:
        return []
    entries = []
    try:
        items = []
        ftp.retrlines(f'LIST {path}', items.append)
        for item in items:
            parts = item.split(None, 8)
            if len(parts) < 9:
                continue
            perms = parts[0]
            name = parts[8].strip()
            if name in ('.', '..'):
                continue
            full_path = f"{path.rstrip('/')}/{name}"
            is_dir = perms.startswith('d')
            entries.append((full_path, is_dir))
            if is_dir and depth < max_depth:
                entries.extend(list_files_recursive(ftp, full_path, depth + 1, max_depth))
    except Exception:
        pass
    return entries


def check_write_access(ftp, path='/'):
    """Try to create a temp directory to detect write access. Returns True if writable."""
    test_dir = f"{path.rstrip('/')}/._nopainnoscan_test"
    try:
        ftp.mkd(test_dir)
        # Clean up
        try:
            ftp.rmd(test_dir)
        except Exception:
            pass
        return True
    except Exception:
        return False


def enumerate_ftp(ip, ftp, output_dir):
    """Enumerate files, detect interesting files, check write access. Returns (file_list, writable_paths)."""
    log_info(f"  Listing files on {ip} (max depth 3)...")
    entries = list_files_recursive(ftp, '/', 0, 3)

    interesting = [e for e in entries if not e[1] and Path(e[0]).suffix.lower() in INTERESTING_EXTENSIONS]
    dirs = [e[0] for e in entries if e[1]]

    # Write file listing
    listing_file = output_dir / f"ftp_files_{ip}.txt"
    with listing_file.open('w') as f:
        f.write(f"# FTP file listing for {ip}\n")
        f.write(f"# Generated: {datetime.now()}\n\n")
        if not entries:
            f.write("(no files found or listing denied)\n")
        for path, is_dir in entries:
            tag = '[DIR]' if is_dir else '[FILE]'
            flag = ' <-- INTERESTING' if (path, is_dir) in [(p, False) for p in [e[0] for e in interesting]] else ''
            f.write(f"{tag} {path}{flag}\n")
        if interesting:
            f.write(f"\n# INTERESTING FILES ({len(interesting)}):\n")
            for path, _ in interesting:
                f.write(f"  {path}\n")

    # Check write access on root and each directory
    writable = []
    paths_to_check = ['/'] + dirs[:10]  # limit to avoid long scans
    for d in paths_to_check:
        if check_write_access(ftp, d):
            writable.append(d)
            log_warn(f"  WRITABLE: {ip}:{d}")

    return entries, interesting, writable


# ---------------------------------------------------------------------------
# STEP 4 — nxc ftp check
# ---------------------------------------------------------------------------

def run_nxc_ftp(hosts_file, user, password, output_dir, label=''):
    """Run nxc ftp against a hosts file and parse successful logins."""
    cmd = f"nxc ftp {hosts_file} -u {user} -p {password}"
    log_info(f"Running: {cmd}")
    out, err, rc = run(cmd, timeout=120)

    results = []
    for line in out.splitlines():
        # nxc marks success with [+] or "FTP" followed by success indicators
        if '[+]' in line or 'Success' in line:
            results.append(line.strip())

    # Save nxc raw output
    nxc_out_file = output_dir / f"nxc_ftp{'_' + label if label else ''}.txt"
    with nxc_out_file.open('w') as f:
        f.write(f"# nxc ftp output — user={user} pass={password}\n")
        f.write(out)
        if err and err != "TIMEOUT":
            f.write(f"\n# STDERR:\n{err}")

    return results


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='check_ftp.py - FTP anonymous access testing and enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 check_ftp.py -t hosts_ftp.txt
  python3 check_ftp.py -t 192.168.1.0/24 -o /tmp/ftp_out
  python3 check_ftp.py -t 10.10.10.5 -u ftpuser -p secret
"""
    )
    parser.add_argument('-t', '--target', required=True,
                        help='Target: file with IPs, single IP, or CIDR')
    parser.add_argument('-o', '--output',
                        help='Output directory (default: ./ftp_results_<timestamp>)')
    parser.add_argument('-u', '--username', default='anonymous',
                        help='Username for credential test (default: anonymous)')
    parser.add_argument('-p', '--password', default='anonymous@',
                        help='Password for credential test (default: anonymous@)')
    args = parser.parse_args()

    # Setup output directory
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path(args.output) if args.output else Path(f'ftp_results_{timestamp}')
    output_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Output directory: {output_dir.resolve()}")

    # Parse targets
    targets = parse_targets(args.target)
    if not targets:
        log_warn("No targets found. Exiting.")
        sys.exit(0)
    log_info(f"Loaded {len(targets)} target(s)")

    use_custom_creds = not (args.username == 'anonymous' and args.password == 'anonymous@')

    # Per-host tracking
    banners = {}          # ip -> banner
    anon_success = []     # list of (ip, user, pwd)
    anon_writable = []    # list of (ip, path)
    custom_success = []   # list of ip

    # -----------------------------------------------------------------------
    log_step("STEP 1 — Banner Grab")
    # -----------------------------------------------------------------------
    for ip in targets:
        log_info(f"Connecting to {ip}:21...")
        banner, ftp = grab_banner(ip)
        if banner:
            banners[ip] = banner
            log_ok(f"  {ip} → {banner[:120]}")
            try:
                ftp.close()
            except Exception:
                pass
        else:
            log_err(f"  {ip} → no response / connection refused")

    with (output_dir / 'ftp_banners.txt').open('w') as f:
        f.write(f"# FTP Banners — {datetime.now()}\n\n")
        for ip, banner in banners.items():
            f.write(f"{ip}\t{banner}\n")
        for ip in targets:
            if ip not in banners:
                f.write(f"{ip}\tNO RESPONSE\n")
    log_ok(f"Banners written to {output_dir / 'ftp_banners.txt'}")

    if not banners:
        log_warn("No FTP servers responded. Nothing more to do.")
        _write_summary(output_dir, targets, banners, anon_success, anon_writable, custom_success)
        sys.exit(0)

    # -----------------------------------------------------------------------
    log_step("STEP 2 — Anonymous Login Test")
    # -----------------------------------------------------------------------
    for ip in banners:
        log_info(f"Testing anonymous login on {ip}...")
        success, cred, ftp = test_anonymous_login(ip)
        if success:
            log_ok(f"  [CRITICAL] {ip} — anonymous login OK (user='{cred[0]}', pass='{cred[1]}')")
            anon_success.append((ip, cred[0], cred[1]))

            # ---------------------------------------------------------------
            # STEP 3 — Enumerate files
            # ---------------------------------------------------------------
            log_step(f"STEP 3 — File Enumeration on {ip}")
            try:
                entries, interesting, writable = enumerate_ftp(ip, ftp, output_dir)
                log_ok(f"  {ip} → {len(entries)} entries, {len(interesting)} interesting files")
                for path in writable:
                    anon_writable.append((ip, path))
                if interesting:
                    log_warn(f"  [!] Interesting files on {ip}:")
                    for epath, _ in interesting[:10]:
                        log_warn(f"      {epath}")
            except Exception as e:
                log_err(f"  Enumeration error on {ip}: {e}")
            finally:
                try:
                    ftp.quit()
                except Exception:
                    try:
                        ftp.close()
                    except Exception:
                        pass
        else:
            log_info(f"  {ip} → anonymous login denied")

    # Write anonymous results
    with (output_dir / 'ftp_anonymous.txt').open('w') as f:
        f.write(f"# FTP Anonymous Access — {datetime.now()}\n")
        f.write(f"# [CRITICAL] if not empty\n\n")
        if anon_success:
            for ip, user, pwd in anon_success:
                f.write(f"{ip}\tuser={user}\tpass={pwd}\n")
        else:
            f.write("# No anonymous access found\n")

    # Write writable results
    with (output_dir / 'ftp_writable.txt').open('w') as f:
        f.write(f"# FTP Writable Directories — {datetime.now()}\n")
        f.write(f"# [CRITICAL] if not empty\n\n")
        if anon_writable:
            for ip, path in anon_writable:
                f.write(f"{ip}\t{path}\n")
        else:
            f.write("# No writable FTP directories found\n")

    if anon_success:
        log_warn(f"[CRITICAL] {len(anon_success)} host(s) allow anonymous FTP access!")
    if anon_writable:
        log_warn(f"[CRITICAL] {len(anon_writable)} writable FTP path(s) found!")

    # -----------------------------------------------------------------------
    # STEP 4 — nxc ftp check
    # -----------------------------------------------------------------------
    log_step("STEP 4 — nxc FTP Check")
    if tool_exists('nxc'):
        # Write hosts file for nxc
        responsive_hosts_file = output_dir / 'responsive_ftp_hosts.txt'
        with responsive_hosts_file.open('w') as f:
            for ip in banners:
                f.write(f"{ip}\n")

        # Anonymous check
        log_info("Running nxc anonymous check...")
        nxc_anon = run_nxc_ftp(str(responsive_hosts_file), 'anonymous', 'anonymous@', output_dir, 'anon')
        if nxc_anon:
            log_ok(f"nxc found {len(nxc_anon)} successful anonymous login(s)")

        # Custom creds check (if not default)
        if use_custom_creds:
            log_info(f"Running nxc with credentials {args.username}:***...")
            nxc_creds = run_nxc_ftp(str(responsive_hosts_file), args.username, args.password, output_dir, 'creds')
            for line in nxc_creds:
                # Extract IP from nxc output
                m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                if m:
                    custom_success.append(m.group(1))

        if custom_success:
            log_ok(f"[+] Custom creds worked on {len(custom_success)} host(s)")
    else:
        log_warn("nxc not found — skipping nxc FTP check")

    # Custom creds test via ftplib (if nxc not available or as complement)
    if use_custom_creds and not tool_exists('nxc'):
        log_info(f"Testing custom credentials {args.username}:*** via ftplib...")
        for ip in banners:
            success, ftp = test_custom_login(ip, args.username, args.password)
            if success:
                log_ok(f"  [+] Custom creds worked on {ip}")
                custom_success.append(ip)
                try:
                    ftp.quit()
                except Exception:
                    pass

    # Write custom login results
    if use_custom_creds:
        with (output_dir / 'ftp_login_success.txt').open('w') as f:
            f.write(f"# FTP Login Success (user={args.username}) — {datetime.now()}\n\n")
            if custom_success:
                for ip in custom_success:
                    f.write(f"{ip}\tuser={args.username}\n")
            else:
                f.write("# No successful logins with provided credentials\n")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    _write_summary(output_dir, targets, banners, anon_success, anon_writable, custom_success)
    log_step("Scan Complete")
    log_ok(f"Results saved to: {output_dir.resolve()}")


def _write_summary(output_dir, targets, banners, anon_success, anon_writable, custom_success):
    summary_path = output_dir / 'ftp_summary.txt'
    with summary_path.open('w') as f:
        f.write("=" * 60 + "\n")
        f.write("  FTP SCAN SUMMARY\n")
        f.write(f"  Generated: {datetime.now()}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Targets scanned:          {len(targets)}\n")
        f.write(f"Hosts with FTP banner:    {len(banners)}\n")
        f.write(f"Anonymous access (CRIT):  {len(anon_success)}\n")
        f.write(f"Writable paths (CRIT):    {len(anon_writable)}\n")
        if custom_success:
            f.write(f"Custom cred success:      {len(custom_success)}\n")

        if anon_success:
            f.write("\n[CRITICAL] ANONYMOUS FTP ACCESS:\n")
            for ip, user, pwd in anon_success:
                f.write(f"  {ip}  (login: {user} / {pwd})\n")

        if anon_writable:
            f.write("\n[CRITICAL] WRITABLE FTP PATHS:\n")
            for ip, path in anon_writable:
                f.write(f"  {ip}:{path}\n")

        if custom_success:
            f.write("\n[+] CUSTOM CREDENTIAL SUCCESS:\n")
            for ip in custom_success:
                f.write(f"  {ip}\n")

        if not anon_success and not anon_writable and not custom_success:
            f.write("\n[OK] No critical FTP findings.\n")

    log_ok(f"Summary: {summary_path}")
    # Print to terminal
    print(f"\n{C.BOLD}{'='*60}")
    print(f"  FTP SCAN SUMMARY")
    print(f"{'='*60}{C.ENDC}")
    print(f"  Targets scanned       : {len(targets)}")
    print(f"  Hosts with FTP banner : {len(banners)}")
    c_anon = C.FAIL if anon_success else C.GREEN
    print(f"  {c_anon}Anonymous access [CRIT]: {len(anon_success)}{C.ENDC}")
    c_wr = C.FAIL if anon_writable else C.GREEN
    print(f"  {c_wr}Writable paths   [CRIT]: {len(anon_writable)}{C.ENDC}")
    if custom_success:
        print(f"  {C.GREEN}Custom cred success   : {len(custom_success)}{C.ENDC}")
    if anon_success:
        print(f"\n  {C.FAIL}[CRITICAL] Anonymous FTP:{C.ENDC}")
        for ip, user, pwd in anon_success:
            print(f"    {ip}  ({user}/{pwd})")
    if anon_writable:
        print(f"\n  {C.FAIL}[CRITICAL] Writable paths:{C.ENDC}")
        for ip, path in anon_writable:
            print(f"    {ip}:{path}")
    print(f"\n  Output: {summary_path.parent}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
