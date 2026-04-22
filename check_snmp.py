#!/usr/bin/env python3
"""check_snmp.py - SNMP community string brute force and enumeration"""

import argparse, subprocess, os, sys, re
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


DEFAULT_COMMUNITIES = [
    "public", "private", "community", "manager", "admin",
    "secret", "internal", "cisco", "router", "switch", "monitor", "default"
]

SNMP_OIDS = {
    "system":           "system",
    "interfaces":       "interfaces",
    "processes":        "hrSWRunName",
    "software":         "hrSWInstalledName",
    "storage":          "hrStorageTable",
    "win_users":        "1.3.6.1.4.1.77.1.2.25",
    "win_shares":       "1.3.6.1.4.1.77.1.4.2",
}


def parse_targets(target_arg):
    """Return list of IP strings from file, CIDR, or single IP."""
    targets = []

    path = Path(target_arg)
    if path.is_file():
        lines = path.read_text().splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
        return targets

    # CIDR expansion via Python stdlib
    if "/" in target_arg:
        try:
            import ipaddress
            net = ipaddress.ip_network(target_arg, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError as e:
            log_err(f"Invalid CIDR: {e}")
            sys.exit(1)

    # Single IP / hostname
    targets.append(target_arg)
    return targets


def write_communities_file(communities, path="/tmp/snmp_communities.txt"):
    """Write community strings to a temp file for onesixtyone."""
    Path(path).write_text("\n".join(communities) + "\n")
    return path


def brute_onesixtyone(hosts, communities, versions):
    """Use onesixtyone to brute-force all hosts at once.

    Returns dict: {ip: [community, ...]}
    """
    hosts_file = "/tmp/snmp_hosts.txt"
    comm_file  = write_communities_file(communities)
    Path(hosts_file).write_text("\n".join(hosts) + "\n")

    found = {}
    log_info(f"Running onesixtyone against {len(hosts)} host(s) with {len(communities)} community string(s)...")
    out, err, rc = run(f"onesixtyone -c {comm_file} -i {hosts_file}", timeout=120)
    if rc != 0 and not out:
        log_warn(f"onesixtyone returned code {rc}: {err.strip()}")
        return found

    for line in out.splitlines():
        # typical output: 192.168.1.1 [public] Linux ...
        m = re.match(r'^(\S+)\s+\[(\S+)\]', line)
        if m:
            ip, comm = m.group(1), m.group(2)
            found.setdefault(ip, [])
            if comm not in found[ip]:
                found[ip].append(comm)
    return found


def brute_snmpwalk(ip, communities, versions):
    """Fallback: try each community with snmpwalk.

    Returns list of working community strings.
    """
    working = []
    ver_list = [v.strip() for v in versions.split(",")]
    for comm in communities:
        for ver in ver_list:
            out, err, rc = run(
                f"snmpwalk -v{ver} -c {comm} {ip} system 2>/dev/null",
                timeout=10
            )
            if out.strip() and "No Such Object" not in out and "Timeout" not in out:
                if comm not in working:
                    working.append(comm)
                break  # no need to test other versions for this community
    return working


def enumerate_host(ip, community, version, output_dir):
    """Run full SNMP walk for a host and save to file.

    Returns dict with parsed sysDescr and sysName.
    """
    outfile = output_dir / f"snmp_data_{ip}.txt"
    info = {"ip": ip, "community": community, "sysDescr": "", "sysName": "", "interfaces": []}

    ver = version.split(",")[0].strip()   # use first version that worked

    lines_collected = []

    for label, oid in SNMP_OIDS.items():
        if label.startswith("win_"):
            continue
        out, _, _ = run(f"snmpwalk -v{ver} -c {community} {ip} {oid}", timeout=30)
        if out.strip():
            lines_collected.append(f"\n### {label.upper()} ###\n{out}")

    # Parse sysDescr / sysName from system walk
    sys_out, _, _ = run(f"snmpwalk -v{ver} -c {community} {ip} system", timeout=20)
    for line in sys_out.splitlines():
        if "sysDescr" in line:
            info["sysDescr"] = line.split("STRING:", 1)[-1].strip().split("\"")[-2] if "STRING:" in line else line
        if "sysName" in line:
            info["sysName"] = line.split("STRING:", 1)[-1].strip().strip('"')

    outfile.write_text(f"# SNMP enumeration for {ip} (community: {community})\n" + "".join(lines_collected))
    log_ok(f"  Saved SNMP data -> {outfile.name}")
    return info


def enumerate_windows(ip, community, version, output_dir):
    """Enumerate Windows-specific SNMP OIDs."""
    ver = version.split(",")[0].strip()
    results = []

    for label in ("win_users", "win_shares"):
        oid = SNMP_OIDS[label]
        out, _, _ = run(f"snmpwalk -v{ver} -c {community} {ip} {oid}", timeout=20)
        if out.strip() and "No Such Object" not in out:
            results.append(f"### {label.upper()} ###\n{out}")

    if results:
        outfile = output_dir / f"snmp_windows_users_{ip}.txt"
        outfile.write_text(f"# Windows SNMP data for {ip} (community: {community})\n" + "\n".join(results))
        log_ok(f"  Windows SNMP data saved -> {outfile.name}")


def main():
    parser = argparse.ArgumentParser(
        description="check_snmp.py - SNMP community string brute force and enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 check_snmp.py -t hosts_snmp.txt
  python3 check_snmp.py -t 192.168.1.0/24 -c mycompany,snmpread
  python3 check_snmp.py -t 10.10.10.5 --version 1,2c -o ./results
        """
    )
    parser.add_argument("-t", "--target",    required=True,
                        help="File of IPs, single IP, or CIDR range")
    parser.add_argument("-o", "--output",    default=None,
                        help="Output directory (default: ./snmp_results_<timestamp>)")
    parser.add_argument("-c", "--community", default="",
                        help="Additional community strings, comma-separated")
    parser.add_argument("--version",         default="1,2c",
                        help="SNMP version(s) to test, comma-separated (default: 1,2c)")
    args = parser.parse_args()

    # --- Output directory ---
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output) if args.output else Path(f"./snmp_results_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Community strings ---
    communities = list(DEFAULT_COMMUNITIES)
    if args.community:
        for c in args.community.split(","):
            c = c.strip()
            if c and c not in communities:
                communities.append(c)

    # --- Tool availability ---
    has_onesixtyone = tool_exists("onesixtyone")
    has_snmpwalk    = tool_exists("snmpwalk")

    if not has_onesixtyone and not has_snmpwalk:
        log_err("Neither onesixtyone nor snmpwalk found. Install snmp / onesixtyone.")
        sys.exit(1)
    if not has_onesixtyone:
        log_warn("onesixtyone not found — falling back to snmpwalk (slower).")
    if not has_snmpwalk:
        log_warn("snmpwalk not found — enumeration phase will be skipped.")

    if os.geteuid() != 0:
        log_warn("Not running as root. UDP SNMP probes may fail without proper privileges.")

    # --- Parse targets ---
    targets = parse_targets(args.target)
    if not targets:
        log_warn("No targets found. Exiting.")
        sys.exit(0)
    log_info(f"Loaded {len(targets)} target(s)")

    # ================================================================
    log_step("STEP 1 — Community string brute force")
    # ================================================================

    accessible = {}   # {ip: [community, ...]}

    if has_onesixtyone:
        accessible = brute_onesixtyone(targets, communities, args.version)
    else:
        for ip in targets:
            log_info(f"  Trying snmpwalk on {ip}...")
            working = brute_snmpwalk(ip, communities, args.version)
            if working:
                accessible[ip] = working

    if accessible:
        log_ok(f"Found {len(accessible)} accessible host(s).")
    else:
        log_warn("No hosts responded to SNMP community probes.")

    # Write snmp_accessible.txt
    accessible_file = out_dir / "snmp_accessible.txt"
    with accessible_file.open("w") as f:
        f.write("# SNMP Accessible Hosts\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        for ip in sorted(accessible):
            for comm in accessible[ip]:
                f.write(f"{ip}\t{comm}\n")
                log_ok(f"  ACCESSIBLE: {ip}  community={comm}")
    log_info(f"Accessible hosts written to {accessible_file}")

    if not accessible:
        log_info("Nothing to enumerate. Done.")
        sys.exit(0)

    if not has_snmpwalk:
        log_warn("snmpwalk not available — skipping enumeration.")
        sys.exit(0)

    # ================================================================
    log_step("STEP 2 — System enumeration")
    # ================================================================

    summary_entries = []

    for ip in sorted(accessible):
        community = accessible[ip][0]   # use first working community
        log_info(f"Enumerating {ip} (community={community})...")
        info = enumerate_host(ip, community, args.version, out_dir)
        summary_entries.append(info)

    # ================================================================
    log_step("STEP 3 — Windows user/share enumeration")
    # ================================================================

    for ip in sorted(accessible):
        community = accessible[ip][0]
        log_info(f"Checking Windows SNMP OIDs on {ip}...")
        enumerate_windows(ip, community, args.version, out_dir)

    # ================================================================
    # Summary file
    # ================================================================
    summary_file = out_dir / "snmp_summary.txt"
    with summary_file.open("w") as f:
        f.write("# SNMP Scan Summary\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        for entry in summary_entries:
            f.write(f"Host      : {entry['ip']}\n")
            f.write(f"Community : {entry['community']}\n")
            f.write(f"sysName   : {entry['sysName'] or '(unknown)'}\n")
            f.write(f"sysDescr  : {entry['sysDescr'] or '(unknown)'}\n")
            f.write("-" * 50 + "\n")

    log_ok(f"\nSummary written to {summary_file}")
    log_ok(f"All results in: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
