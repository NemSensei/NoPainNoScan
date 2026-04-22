#!/usr/bin/env python3
"""check_winrm.py - WinRM enumeration and authentication testing"""

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Color / logging helpers
# ---------------------------------------------------------------------------

class C:
    HEADER = '\033[95m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    WARN   = '\033[93m'
    FAIL   = '\033[91m'
    ENDC   = '\033[0m'
    BOLD   = '\033[1m'


def log_info(msg):  print(f"{C.CYAN}[*]{C.ENDC} {msg}")
def log_ok(msg):    print(f"{C.GREEN}[+]{C.ENDC} {msg}")
def log_warn(msg):  print(f"{C.WARN}[!]{C.ENDC} {msg}")
def log_err(msg):   print(f"{C.FAIL}[X]{C.ENDC} {msg}")


def log_step(msg):
    print(f"\n{C.HEADER}{C.BOLD}{'='*60}\n  {msg}\n{'='*60}{C.ENDC}")


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def run(cmd, timeout=120):
    """Run a shell command; return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1


def tool_exists(name):
    _, _, rc = run(f"which {name}")
    return rc == 0


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def parse_targets(target_arg):
    """Return a list of IP strings from file path, single IP, or CIDR."""
    p = Path(target_arg)
    if p.is_file():
        ips = [line.strip() for line in p.read_text().splitlines() if line.strip()]
        return ips

    # Try CIDR
    try:
        net = ipaddress.ip_network(target_arg, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError:
        pass

    # Single IP / hostname
    return [target_arg]


def write_hosts_file(ips, path):
    """Write unique, sorted IPs to a temporary file; return path."""
    unique = sorted(set(ips))
    Path(path).write_text("\n".join(unique) + "\n")
    return path


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------

def step1_detect(hosts_file, port, out_dir):
    """WinRM detection + auth method check — no credentials required."""
    log_step("STEP 1 — WinRM Detection & Auth Methods")

    results = []

    # --- nxc winrm sweep ---
    log_info("Running nxc winrm sweep...")
    nxc_out, nxc_err, _ = run(f"nxc winrm {hosts_file}", timeout=300)

    info_path = out_dir / "winrm_hosts_info.txt"
    lines_nxc = [l for l in nxc_out.splitlines() if l.strip()]

    # Extract reachable hosts from nxc output (lines with IP-like entries)
    host_pat = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
    nxc_hosts = []
    for line in lines_nxc:
        m = host_pat.search(line)
        if m and ("WINRM" in line.upper() or "SMB" in line.upper() or m.group(1)):
            nxc_hosts.append(line.strip())

    results.extend(nxc_hosts)

    # --- HTTP header check per host ---
    ips = [l.strip() for l in Path(hosts_file).read_text().splitlines() if l.strip()]
    header_results = []

    for ip in ips:
        for (scheme, p) in [("http", 5985), ("https", 5986)]:
            if port != 5985 and p != port:
                continue
            url = f"{scheme}://{ip}:{p}/wsman"
            log_info(f"Checking headers: {url}")
            curl_cmd = f"curl -sk {url} -D - --max-time 5 2>&1 | head -20"
            hdr_out, _, _ = run(curl_cmd, timeout=15)
            if not hdr_out.strip():
                continue

            auth_line = ""
            for hline in hdr_out.splitlines():
                if "www-authenticate" in hline.lower():
                    auth_line = hline.strip()
                    break

            auth_type = "unknown"
            if "negotiate" in auth_line.lower():
                auth_type = "Negotiate (Kerberos/NTLM)"
            elif "basic" in auth_line.lower():
                auth_type = "Basic"
            elif auth_line:
                auth_type = auth_line

            entry = f"{ip}:{p} [{scheme.upper()}] Auth={auth_type}"
            header_results.append(entry)
            log_ok(entry)

    # Write combined output (deduped, sorted)
    combined = sorted(set(results + header_results))
    with info_path.open("w") as f:
        f.write(f"# WinRM Host Info — {datetime.now()}\n\n")
        f.write("## nxc sweep\n")
        f.write("\n".join(nxc_hosts) + "\n\n")
        f.write("## Header auth method\n")
        f.write("\n".join(sorted(set(header_results))) + "\n")

    log_ok(f"Host info written → {info_path}")
    return combined


def step2_auth(hosts_file, username, password, ntlm_hash, domain, out_dir):
    """Test provided credentials against WinRM."""
    log_step("STEP 2 — Authentication Test")

    cred_part = f"-u '{username}'"
    if ntlm_hash:
        cred_part += f" -H '{ntlm_hash}'"
    elif password:
        cred_part += f" -p '{password}'"
    if domain:
        cred_part += f" -d '{domain}'"

    cmd = f"nxc winrm {hosts_file} {cred_part}"
    log_info(f"Running: {cmd}")
    out, err, _ = run(cmd, timeout=300)

    accessible = []
    for line in out.splitlines():
        if "(Pwn3d!)" in line or "STATUS_SUCCESS" in line.upper() or "[+]" in line:
            accessible.append(line.strip())

    acc_path = out_dir / "winrm_accessible.txt"
    with acc_path.open("w") as f:
        f.write(f"# WinRM Accessible Hosts — {datetime.now()}\n\n")
        f.write("## Full nxc output\n")
        f.write(out + "\n")
        if accessible:
            f.write("\n## [CRITICAL] Successful authentications\n")
            f.write("\n".join(sorted(set(accessible))) + "\n")

    if accessible:
        log_ok(f"[CRITICAL] {len(accessible)} successful auth(s) found → {acc_path}")
    else:
        log_warn(f"No successful authentications. Full output in {acc_path}")

    return accessible


def step3_exec(hosts_file, username, password, ntlm_hash, domain, out_dir):
    """Execute commands on accessible WinRM hosts."""
    log_step("STEP 3 — Command Execution")

    cred_part = f"-u '{username}'"
    if ntlm_hash:
        cred_part += f" -H '{ntlm_hash}'"
    elif password:
        cred_part += f" -p '{password}'"
    if domain:
        cred_part += f" -d '{domain}'"

    commands = [
        ("whoami /all", "whoami"),
        ("hostname",    "hostname"),
        ("ipconfig /all", "ipconfig"),
    ]

    cmd_path = out_dir / "winrm_cmd_results.txt"
    with cmd_path.open("w") as f:
        f.write(f"# WinRM Command Execution Results — {datetime.now()}\n\n")

        for (win_cmd, label) in commands:
            log_info(f"Executing: {win_cmd}")
            nxc_cmd = f"nxc winrm {hosts_file} {cred_part} -x '{win_cmd}'"
            out, err, _ = run(nxc_cmd, timeout=120)
            f.write(f"\n{'='*50}\n## {label}\n{'='*50}\n")
            f.write(out + "\n")
            if out.strip():
                log_ok(f"{label} output captured")
            else:
                log_warn(f"No output for: {win_cmd}")

    log_ok(f"Command results written → {cmd_path}")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_summary(out_dir, targets, has_creds, accessible):
    path = out_dir / "winrm_summary.txt"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with path.open("w") as f:
        f.write(f"WinRM Enumeration Summary\nGenerated: {ts}\n\n")
        f.write(f"Targets scanned : {targets}\n")
        f.write(f"Credentials used: {'Yes' if has_creds else 'No'}\n")
        if has_creds:
            status = f"[CRITICAL] {len(accessible)} host(s) accessible" if accessible else "No successful auth"
            f.write(f"Auth result     : {status}\n")
        f.write("\nOutput files:\n")
        for fname in ["winrm_hosts_info.txt", "winrm_accessible.txt",
                      "winrm_cmd_results.txt", "winrm_summary.txt"]:
            fp = out_dir / fname
            if fp.exists():
                f.write(f"  {fp}\n")
    log_ok(f"Summary written → {path}")
    # Print to terminal
    print(f"\n{C.BOLD}{'='*60}")
    print(f"  WINRM ENUMERATION SUMMARY")
    print(f"{'='*60}{C.ENDC}")
    print(f"  Targets scanned  : {targets}")
    print(f"  Credentials used : {'Yes' if has_creds else 'No (detection only)'}")
    if has_creds:
        c = C.FAIL if accessible else C.GREEN
        label = f"[CRITICAL] {len(accessible)} host(s) accessible" if accessible else "No successful auth"
        print(f"  {c}Auth result      : {label}{C.ENDC}")
        if accessible:
            for line in accessible:
                print(f"    {C.FAIL}{line}{C.ENDC}")
    print(f"\n  Output: {out_dir}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="check_winrm.py — WinRM enumeration and authentication testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target",   required=True,
                   help="File with IPs, single IP, or CIDR range")
    p.add_argument("-o", "--output",   default=None,
                   help="Output directory (default: ./winrm_results_<timestamp>)")
    p.add_argument("-u", "--username", default=None, help="Username")
    p.add_argument("-p", "--password", default=None, help="Password")
    p.add_argument("-H", "--hash",     default=None, help="NTLM hash LM:NT")
    p.add_argument("-d", "--domain",   default=None, help="Domain")
    p.add_argument("--port",           type=int, default=5985, help="WinRM port (default: 5985)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    # --- Dependency check ---
    if not tool_exists("nxc"):
        log_err("nxc (NetExec) not found. Install it: pip install netexec")
        sys.exit(1)

    # --- Output directory ---
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output) if args.output else Path(f"winrm_results_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Output directory: {out_dir.resolve()}")

    # --- Parse targets ---
    ips = parse_targets(args.target)
    if not ips:
        log_err("No valid targets found. Exiting.")
        sys.exit(1)
    log_info(f"Targets loaded: {len(ips)} host(s)")

    # Write temp hosts file used by nxc
    tmp_hosts = str(out_dir / "hosts_winrm_tmp.txt")
    write_hosts_file(ips, tmp_hosts)

    has_creds = bool(args.username and (args.password or args.hash))

    # --- Run steps ---
    step1_detect(tmp_hosts, args.port, out_dir)

    accessible = []
    if has_creds:
        accessible = step2_auth(
            tmp_hosts, args.username, args.password,
            args.hash, args.domain, out_dir
        )
        if accessible:
            step3_exec(
                tmp_hosts, args.username, args.password,
                args.hash, args.domain, out_dir
            )
        else:
            log_warn("Skipping command execution — no successful authentications.")
    else:
        log_warn("No credentials provided — skipping auth test and command execution.")

    write_summary(out_dir, len(ips), has_creds, accessible)
    log_ok("Done.")


if __name__ == "__main__":
    main()
