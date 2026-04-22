#!/usr/bin/env python3
"""check_dns.py - DNS zone transfer and reverse lookup enumeration"""

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

def parse_targets(target_arg):
    """Return list of IP strings from file, single IP, or CIDR."""
    targets = []
    p = Path(target_arg)
    if p.is_file():
        lines = p.read_text().splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Support "ip:port" format (from nmap/nxc output)
            ip = line.split(':')[0].split()[0]
            try:
                ipaddress.ip_address(ip)
                targets.append(ip)
            except ValueError:
                log_warn(f"Skipping invalid entry: {line}")
        return targets
    # Try single IP
    try:
        ipaddress.ip_address(target_arg)
        return [target_arg]
    except ValueError:
        pass
    # Try CIDR
    try:
        net = ipaddress.ip_network(target_arg, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError:
        log_err(f"Cannot parse target: {target_arg}")
        sys.exit(1)


def cidr_from_ip(ip):
    """Derive /24 network from a single IP string."""
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


# ---------------------------------------------------------------------------
# STEP 1 — SOA detection
# ---------------------------------------------------------------------------

COMMON_DOMAINS = [
    "corp", "local", "lan", "internal", "intranet", "domain",
    "ad", "home", "office", "net", "org",
]

_SOA_RE = re.compile(r'\bSOA\b', re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r'(?:^|\s)(\w[\w\-]*(?:\.\w[\w\-]*){1,5})\.\s+\d+\s+IN\s+SOA',
    re.IGNORECASE | re.MULTILINE,
)


def detect_domain_from_soa(output):
    """Extract domain name from dig SOA output."""
    m = _DOMAIN_RE.search(output)
    if m:
        return m.group(1).lower()
    # Fallback: look for 'mname' field (first field after SOA keyword)
    for line in output.splitlines():
        if 'SOA' in line.upper() and not line.startswith(';'):
            parts = line.split()
            for i, part in enumerate(parts):
                if part.upper() == 'SOA' and i + 1 < len(parts):
                    ns = parts[i + 1].rstrip('.')
                    # The NS hostname often looks like dc01.corp.local
                    chunks = ns.split('.')
                    if len(chunks) >= 2:
                        return '.'.join(chunks[-2:])
    return None


def step_soa(servers, guessed_domains, outdir):
    """Query SOA records to auto-detect the AD domain."""
    log_step("STEP 1 — SOA / Domain Detection")
    soa_lines = []
    detected = set()

    for ip in servers:
        log_info(f"Querying SOA on {ip}")

        # Try well-known domain guesses first
        for dom in guessed_domains:
            out, _, rc = run(f"dig SOA {dom} @{ip} +time=5 +tries=1", timeout=10)
            if out and _SOA_RE.search(out):
                d = detect_domain_from_soa(out)
                if d:
                    detected.add(d)
                    log_ok(f"  {ip}: SOA → {d}")
                soa_lines.append(f"# {ip} — SOA {dom}\n{out}")

        # Generic root query
        out, _, rc = run(f"dig +short -t SOA . @{ip} +time=5 +tries=1", timeout=10)
        if out.strip():
            soa_lines.append(f"# {ip} — SOA .\n{out}")

        # NS root query
        out, _, _ = run(f"dig @{ip} -t NS . +time=5 +tries=1", timeout=10)
        if out.strip():
            soa_lines.append(f"# {ip} — NS .\n{out}")

        # _msdcs hint
        out, _, _ = run(f"dig @{ip} -t ANY _msdcs +time=5 +tries=1", timeout=10)
        if out.strip() and 'ANSWER' in out:
            soa_lines.append(f"# {ip} — _msdcs\n{out}")
            d = detect_domain_from_soa(out)
            if d:
                detected.add(d)

    soa_path = outdir / "dns_soa.txt"
    soa_path.write_text('\n'.join(soa_lines) if soa_lines else "# No SOA records found\n")
    log_info(f"SOA output → {soa_path}")

    if detected:
        log_ok(f"Detected domains: {', '.join(sorted(detected))}")
    else:
        log_warn("No domain auto-detected from SOA")

    return sorted(detected)


# ---------------------------------------------------------------------------
# STEP 2 — AXFR zone transfer
# ---------------------------------------------------------------------------

def step_axfr(servers, domains, outdir):
    """Attempt DNS zone transfer for each server/domain pair."""
    log_step("STEP 2 — Zone Transfer (AXFR)")
    zones_dir = outdir / "dns_zones"
    zones_dir.mkdir(exist_ok=True)

    success_lines = []

    for ip in servers:
        for domain in domains:
            for dom_variant in [domain, domain + '.']:
                log_info(f"AXFR {dom_variant} @{ip}")
                out, err, rc = run(f"dig axfr {dom_variant} @{ip} +time=10 +tries=1", timeout=30)
                if out and ('Transfer failed' not in out) and ('AXFR' in out or '; <<>> DiG' in out):
                    # Check there are actual records (not just SOA / error)
                    record_lines = [l for l in out.splitlines()
                                    if l.strip() and not l.startswith(';') and '\tIN\t' in l]
                    if len(record_lines) > 1:
                        safe_domain = re.sub(r'[^\w\-]', '_', domain)
                        fname = zones_dir / f"{ip}_{safe_domain}.txt"
                        fname.write_text(out)
                        log_ok(f"  [CRITICAL] AXFR SUCCESS: {ip} → {domain} ({len(record_lines)} records)")
                        success_lines.append(f"[CRITICAL] {ip} — {domain} — {len(record_lines)} records — {fname}")
                        break  # no need to try trailing dot variant
                else:
                    log_warn(f"  AXFR refused/failed for {domain} @{ip}")

    axfr_path = outdir / "dns_axfr_success.txt"
    if success_lines:
        axfr_path.write_text('\n'.join(sorted(set(success_lines))) + '\n')
        log_ok(f"AXFR successes → {axfr_path}")
    else:
        axfr_path.write_text("# No successful zone transfers\n")
        log_info("No zone transfers succeeded.")

    return success_lines


# ---------------------------------------------------------------------------
# STEP 3 — Common subdomain enumeration
# ---------------------------------------------------------------------------

COMMON_NAMES = [
    "dc", "dc01", "dc02", "dc1", "dc2",
    "ad", "ldap", "kerberos", "kdc",
    "mail", "smtp", "mx",
    "vpn", "remote", "gateway",
    "www", "web", "ftp",
    "intranet", "sharepoint", "exchange",
    "fs", "files", "ntp", "syslog",
    "proxy", "wpad",
]


def step_enum_hosts(servers, domains, outdir):
    """Try common AD/Windows hostnames against each DNS server."""
    log_step("STEP 3 — Common Subdomain Enumeration")
    found = {}  # hostname → set of IPs

    for ip in servers:
        for domain in domains:
            for name in COMMON_NAMES:
                fqdn = f"{name}.{domain}"
                out, _, rc = run(f"dig +short {fqdn} @{ip} +time=5 +tries=1", timeout=10)
                result = out.strip()
                if result and not result.startswith(';'):
                    for addr in result.splitlines():
                        addr = addr.strip().rstrip('.')
                        if addr:
                            key = fqdn
                            found.setdefault(key, set()).add(addr)
                            log_ok(f"  {fqdn} → {addr}")

    lines = []
    for fqdn in sorted(found):
        for addr in sorted(found[fqdn]):
            lines.append(f"{fqdn}\t{addr}")

    hosts_path = outdir / "dns_hosts.txt"
    hosts_path.write_text('\n'.join(lines) + '\n' if lines else "# No hostnames discovered\n")
    log_info(f"Discovered hosts → {hosts_path} ({len(lines)} entries)")
    return found


# ---------------------------------------------------------------------------
# STEP 4 — Reverse lookup sweep
# ---------------------------------------------------------------------------

MAX_REVERSE_HOSTS = 256  # hard limit to avoid sweeping /16 etc.


def step_reverse(servers, target_range, outdir):
    """PTR lookup sweep over target_range using first DNS server."""
    log_step("STEP 4 — Reverse Lookup Sweep")

    if not servers:
        log_warn("No DNS servers available for reverse sweep.")
        reverse_path = outdir / "dns_reverse.txt"
        reverse_path.write_text("# No DNS servers available\n")
        return {}

    try:
        net = ipaddress.ip_network(target_range, strict=False)
    except ValueError:
        log_err(f"Invalid range for reverse lookup: {target_range}")
        reverse_path = outdir / "dns_reverse.txt"
        reverse_path.write_text(f"# Invalid range: {target_range}\n")
        return {}

    host_list = list(net.hosts())
    if len(host_list) > MAX_REVERSE_HOSTS:
        log_warn(
            f"Range {target_range} has {len(host_list)} hosts — limiting to first {MAX_REVERSE_HOSTS}. "
            "Use --range with a /24 or smaller."
        )
        host_list = host_list[:MAX_REVERSE_HOSTS]

    dns_server = servers[0]
    log_info(f"Reverse sweep of {len(host_list)} IPs via {dns_server}")

    ptr_map = {}  # ip → hostname
    for host in host_list:
        ip_str = str(host)
        out, _, _ = run(f"dig +short -x {ip_str} @{dns_server} +time=3 +tries=1", timeout=8)
        result = out.strip().rstrip('.')
        if result and not result.startswith(';'):
            ptr_map[ip_str] = result
            log_ok(f"  {ip_str} → {result}")

    lines = [f"{ip}\t{name}" for ip, name in sorted(ptr_map.items())]
    reverse_path = outdir / "dns_reverse.txt"
    reverse_path.write_text('\n'.join(lines) + '\n' if lines else "# No PTR records found\n")
    log_info(f"PTR records → {reverse_path} ({len(ptr_map)} entries)")
    return ptr_map


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_summary(outdir, servers, detected_domains, axfr_successes,
                  enum_hosts, ptr_map, args):
    summary_path = outdir / "dns_summary.txt"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"DNS Enumeration Summary — {ts}",
        "=" * 60,
        f"Target        : {args.target}",
        f"Domain(s)     : {', '.join(detected_domains) if detected_domains else 'N/A'}",
        f"Servers tested: {len(servers)}",
        "",
        f"SOA/Domain detection : {'OK — ' + ', '.join(detected_domains) if detected_domains else 'No domain detected'}",
        f"Zone transfers (AXFR): {len(axfr_successes)} SUCCESS {'[CRITICAL]' if axfr_successes else ''}",
        f"Hostnames via enum   : {len(enum_hosts)} unique FQDNs",
        f"PTR records found    : {len(ptr_map)}",
        "",
    ]

    if axfr_successes:
        lines.append("[CRITICAL] Successful zone transfers:")
        for s in axfr_successes:
            lines.append(f"  {s}")
        lines.append("")

    if enum_hosts:
        lines.append("Discovered hostnames:")
        for fqdn in sorted(enum_hosts):
            for addr in sorted(enum_hosts[fqdn]):
                lines.append(f"  {fqdn} → {addr}")
        lines.append("")

    if ptr_map:
        lines.append("PTR (reverse) records:")
        for ip in sorted(ptr_map, key=lambda x: ipaddress.ip_address(x)):
            lines.append(f"  {ip} → {ptr_map[ip]}")

    summary_path.write_text('\n'.join(lines) + '\n')
    log_ok(f"Summary → {summary_path}")
    # Print to terminal
    print(f"\n{C.BOLD}{'='*60}")
    print(f"  DNS ENUMERATION SUMMARY")
    print(f"{'='*60}{C.ENDC}")
    print(f"  Servers tested        : {len(servers)}")
    print(f"  Domains detected      : {', '.join(detected_domains) if detected_domains else 'none'}")
    print(f"  Hostnames via enum    : {len(enum_hosts)}")
    print(f"  PTR records found     : {len(ptr_map)}")
    c = C.FAIL if axfr_successes else C.GREEN
    print(f"  {c}Zone transfers (AXFR) : {len(axfr_successes)}{' [CRITICAL]' if axfr_successes else ''}{C.ENDC}")
    if axfr_successes:
        for s in axfr_successes:
            print(f"    {C.FAIL}{s}{C.ENDC}")
    print(f"\n  Output: {summary_path.parent}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="check_dns.py — DNS zone transfer and reverse lookup enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t hosts_dns.txt
  %(prog)s -t 192.168.1.10 -d corp.local
  %(prog)s -t 192.168.1.0/24 --range 192.168.1.0/24 -o ./results
        """,
    )
    p.add_argument("-t", "--target", required=True,
                   help="File with IPs, single IP, or CIDR")
    p.add_argument("-o", "--output",
                   help="Output directory (default: ./dns_results_<timestamp>)")
    p.add_argument("-d", "--domain", action="append", dest="domains",
                   metavar="DOMAIN",
                   help="Domain to attempt AXFR on (can be specified multiple times)")
    p.add_argument("--range",
                   help="IP range for reverse lookup (e.g. 192.168.1.0/24)")
    return p.parse_args()


def main():
    args = parse_args()

    # Verify dig is available
    if not tool_exists("dig"):
        log_err("'dig' not found. Install with: sudo apt install dnsutils")
        sys.exit(1)

    # Resolve output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output) if args.output else Path(f"dns_results_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    log_info(f"Output directory: {outdir.resolve()}")

    # Parse targets
    servers = parse_targets(args.target)
    if not servers:
        log_warn("No valid targets found. Exiting.")
        (outdir / "dns_summary.txt").write_text("# No targets provided\n")
        sys.exit(0)

    log_info(f"DNS servers to test: {len(servers)}")

    # Build initial domain guess list
    user_domains = list(args.domains) if args.domains else []
    candidate_domains = list(user_domains) + COMMON_DOMAINS

    # Determine reverse lookup range
    if args.range:
        reverse_range = args.range
    else:
        # Default: /24 derived from first target
        reverse_range = cidr_from_ip(servers[0])

    # Run steps
    detected_domains = step_soa(servers, candidate_domains, outdir)

    # Merge user-supplied + auto-detected; fall back to common guesses if nothing found
    all_domains = list(dict.fromkeys(user_domains + detected_domains))
    if not all_domains:
        log_warn("No domain detected; falling back to common domain guesses for AXFR/enum")
        all_domains = COMMON_DOMAINS[:6]  # keep it short

    axfr_successes = step_axfr(servers, all_domains, outdir)
    enum_hosts = step_enum_hosts(servers, all_domains, outdir)
    ptr_map = step_reverse(servers, reverse_range, outdir)

    write_summary(outdir, servers, detected_domains, axfr_successes, enum_hosts, ptr_map, args)

    log_ok("Done.")


if __name__ == "__main__":
    main()
