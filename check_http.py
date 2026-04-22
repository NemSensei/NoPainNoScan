#!/usr/bin/env python3
"""check_http.py - HTTP/HTTPS service enumeration and ADCS/WebDAV detection"""

import argparse, subprocess, sys, re
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def parse_targets(target_arg):
    """Parse target: file, single IP, or CIDR. Returns list of IPs."""
    hosts = []
    path = Path(target_arg)
    if path.is_file():
        lines = path.read_text().splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Support "ip:port" lines (from hosts_http.txt) — extract just the IP
            ip_part = line.split(':')[0] if ':' in line else line
            if ip_part:
                hosts.append(ip_part)
    else:
        try:
            network = ipaddress.ip_network(target_arg, strict=False)
            hosts = [str(ip) for ip in network.hosts()] if network.num_addresses > 1 else [str(network.network_address)]
        except ValueError:
            hosts = [target_arg]
    return list(dict.fromkeys(hosts))  # deduplicate, preserve order


def curl_fetch(url, timeout):
    """Single curl call: return (status_code, headers_dict, body)."""
    cmd = f"curl -sk -m {timeout} --max-redirs 3 -D - {url}"
    out, _, _ = run(cmd, timeout=timeout + 5)
    status = ""
    headers = {}
    # Headers end at the first blank line; body follows
    header_section, _, body = out.partition("\r\n\r\n")
    if not body:
        header_section, _, body = out.partition("\n\n")
    for line in header_section.splitlines():
        line = line.strip()
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2:
                status = parts[1]
        elif ':' in line:
            key, _, val = line.partition(':')
            headers[key.strip().lower()] = val.strip()
    match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    title = match.group(1).strip()[:120] if match else ""
    return status, headers, title


def check_url_exists(url, timeout):
    """Check if a URL returns 200 or 401."""
    cmd = f"curl -sk -o /dev/null -w '%{{http_code}}' -m {timeout} {url}"
    out, _, _ = run(cmd, timeout=timeout + 5)
    code = out.strip().strip("'")
    return code


def check_webdav(url, timeout):
    """Check if WebDAV is enabled on a URL."""
    cmd = f"curl -sk -X OPTIONS {url} -D - -m {timeout}"
    out, _, _ = run(cmd, timeout=timeout + 5)
    dav_headers = re.search(r'DAV:', out, re.IGNORECASE)
    allow_match = re.search(r'Allow:\s*(.+)', out, re.IGNORECASE)
    allow_val = allow_match.group(1).strip() if allow_match else ""
    webdav_methods = any(m in allow_val.upper() for m in ['PROPFIND', 'COPY', 'MOVE'])
    if dav_headers or webdav_methods:
        return True, allow_val
    return False, ""


# ---------------------------------------------------------------------------
# Per-host checks
# ---------------------------------------------------------------------------

def step1_title(ip, port, timeout):
    """Return list of result dicts for one IP:port (tries http + https)."""
    results = []
    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}:{port}"
        status, hdrs, title = curl_fetch(url, timeout)
        if not status:
            continue
        results.append({
            "ip": ip, "port": port, "scheme": scheme,
            "status": status, "title": title,
            "server": hdrs.get('server', ''),
            "powered_by": hdrs.get('x-powered-by', ''),
            "url": url,
        })
    return results


def step2_adcs(ip, port, scheme, timeout):
    """Check ADCS paths on a given base URL. Returns list of findings."""
    paths = ['/certsrv/', '/certenroll/', '/adcs/', '/CertSrv/Default.asp']
    findings = []
    for path in paths:
        url = f"{scheme}://{ip}:{port}{path}"
        code = check_url_exists(url, timeout)
        if code in ('200', '401', '403'):
            findings.append(f"{url} [{code}]")
    return findings


def step3_webdav(ip, port, scheme, timeout):
    """Check WebDAV on a given URL. Returns finding string or None."""
    url = f"{scheme}://{ip}:{port}/"
    found, allow = check_webdav(url, timeout)
    if found:
        return f"{url} [Allow: {allow}]"
    return None


def step4_services(ip, port, scheme, timeout):
    """Check interesting service paths. Returns dict of service->findings."""
    services = {
        'owa':  ['/owa/', '/exchange/'],
        'rdweb': ['/rdweb/'],
        'adfs':  ['/adfs/ls/'],
        'wsus':  ['/selfupdate/'],
    }
    results = {}
    for svc, paths in services.items():
        for path in paths:
            url = f"{scheme}://{ip}:{port}{path}"
            code = check_url_exists(url, timeout)
            if code in ('200', '301', '302', '401', '403'):
                results.setdefault(svc, []).append(f"{url} [{code}]")
    return results


def step5_whatweb(url):
    """Run whatweb on a URL, return output line."""
    cmd = f"whatweb --no-errors -q {url}"
    out, _, _ = run(cmd, timeout=60)
    return out.strip()


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def process_host_port(args_tuple):
    """Worker function for ThreadPoolExecutor."""
    ip, port, timeout = args_tuple
    result = {
        'ip': ip, 'port': port,
        'titles': [],
        'adcs': [],
        'webdav': [],
        'services': {},
        'whatweb': [],
    }

    titles = step1_title(ip, port, timeout)
    result['titles'] = titles

    for t in titles:
        scheme = t['scheme']
        result['adcs'].extend(step2_adcs(ip, port, scheme, timeout))
        wdav = step3_webdav(ip, port, scheme, timeout)
        if wdav:
            result['webdav'].append(wdav)
        svcs = step4_services(ip, port, scheme, timeout)
        for svc, findings in svcs.items():
            result['services'].setdefault(svc, []).extend(findings)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="check_http.py - HTTP/HTTPS service enumeration and ADCS/WebDAV detection"
    )
    parser.add_argument('-t', '--target', required=True,
                        help='File, single IP, or CIDR range')
    parser.add_argument('-o', '--output', default=None,
                        help='Output directory (default: ./http_results_<timestamp>)')
    parser.add_argument('-u', '--username', default=None, help='Username (optional)')
    parser.add_argument('-p', '--password', default=None, help='Password (optional)')
    parser.add_argument('--ports', default='80,443,8080,8443,8000',
                        help='Comma-separated ports (default: 80,443,8080,8443,8000)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--workers', type=int, default=10,
                        help='Parallel workers (default: 10)')
    args = parser.parse_args()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    outdir = Path(args.output) if args.output else Path(f"./http_results_{timestamp}")
    outdir.mkdir(parents=True, exist_ok=True)

    ports = [p.strip() for p in args.ports.split(',') if p.strip()]

    log_step("HTTP/HTTPS Enumeration — check_http.py")
    log_info(f"Target   : {args.target}")
    log_info(f"Ports    : {', '.join(ports)}")
    log_info(f"Timeout  : {args.timeout}s")
    log_info(f"Output   : {outdir}")

    hosts = parse_targets(args.target)
    if not hosts:
        log_warn("No hosts found in target. Exiting.")
        sys.exit(0)

    log_info(f"Loaded {len(hosts)} host(s)")

    # Build task list: (ip, port, timeout)
    tasks = [(ip, port, args.timeout) for ip in hosts for port in ports]
    log_info(f"Total URL checks: {len(tasks)} host:port combos x2 schemes = {len(tasks)*2} requests")

    # Aggregate results
    all_titles = []
    all_adcs = []
    all_webdav = []
    all_services = {}
    all_whatweb = []

    has_whatweb = tool_exists("whatweb")
    if not has_whatweb:
        log_warn("whatweb not found — skipping tech detection (Step 5)")

    log_step("Step 1-4: Title, ADCS, WebDAV, Service detection")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_host_port, t): t for t in tasks}
        done = 0
        for future in as_completed(futures):
            done += 1
            try:
                res = future.result()
            except Exception as e:
                ip, port, _ = futures[future]
                log_err(f"Error processing {ip}:{port} — {e}")
                continue

            ip, port = res['ip'], res['port']

            for t in res['titles']:
                all_titles.append(t)
                if t['status'] not in ('000', ''):
                    log_ok(f"{t['url']} [{t['status']}] \"{t['title']}\" [Server: {t['server']}]")

            for adcs in res['adcs']:
                all_adcs.append(adcs)
                log_warn(f"[ADCS] {adcs}")

            for wdav in res['webdav']:
                all_webdav.append(wdav)
                log_warn(f"[WebDAV] {wdav}")

            for svc, findings in res['services'].items():
                all_services.setdefault(svc, []).extend(findings)
                for f in findings:
                    log_ok(f"[{svc.upper()}] {f}")

            if done % 20 == 0 or done == len(tasks):
                log_info(f"Progress: {done}/{len(tasks)}")

    # Step 5: whatweb (sequential per live host to avoid hammering)
    if has_whatweb:
        log_step("Step 5: Tech detection (whatweb)")
        seen_urls = set()
        for t in all_titles:
            if t['status'] not in ('000', '') and t['url'] not in seen_urls:
                seen_urls.add(t['url'])
                out = step5_whatweb(t['ip'], t['port'], t['scheme'])
                if out:
                    all_whatweb.append(out)
                    log_info(f"whatweb: {out[:120]}")

    # -----------------------------------------------------------------------
    # Write output files
    # -----------------------------------------------------------------------
    log_step("Writing output files")

    # http_titles.txt
    titles_file = outdir / "http_titles.txt"
    with open(titles_file, 'w') as f:
        f.write("# IP:PORT SCHEME STATUS TITLE SERVER\n")
        for t in all_titles:
            f.write(f"{t['ip']}:{t['port']} {t['scheme'].upper()} {t['status']} \"{t['title']}\" [Server: {t['server']}]\n")
    log_info(f"http_titles.txt    → {len(all_titles)} entries")

    # http_adcs.txt
    adcs_file = outdir / "http_adcs.txt"
    with open(adcs_file, 'w') as f:
        f.write("# ADCS endpoints detected [CRITICAL — ESC8 candidate]\n")
        for line in all_adcs:
            f.write(line + "\n")
    if all_adcs:
        log_warn(f"[CRITICAL] http_adcs.txt → {len(all_adcs)} ADCS endpoint(s) found!")
    else:
        log_info("http_adcs.txt      → no ADCS endpoints found")

    # http_webdav.txt
    webdav_file = outdir / "http_webdav.txt"
    with open(webdav_file, 'w') as f:
        f.write("# WebDAV-enabled hosts [CRITICAL — coercion surface]\n")
        for line in all_webdav:
            f.write(line + "\n")
    if all_webdav:
        log_warn(f"[CRITICAL] http_webdav.txt → {len(all_webdav)} WebDAV host(s) found!")
    else:
        log_info("http_webdav.txt    → no WebDAV found")

    # Per-service files
    svc_files = {
        'owa':   outdir / "http_owa.txt",
        'rdweb': outdir / "http_rdweb.txt",
        'adfs':  outdir / "http_adfs.txt",
        'wsus':  outdir / "http_wsus.txt",
    }
    for svc, svc_file in svc_files.items():
        findings = all_services.get(svc, [])
        with open(svc_file, 'w') as f:
            f.write(f"# {svc.upper()} endpoints\n")
            for line in findings:
                f.write(line + "\n")
        if findings:
            log_ok(f"{svc_file.name:<20} → {len(findings)} finding(s)")
        else:
            log_info(f"{svc_file.name:<20} → none")

    # http_whatweb.txt
    whatweb_file = outdir / "http_whatweb.txt"
    with open(whatweb_file, 'w') as f:
        f.write("# whatweb tech detection output\n")
        for line in all_whatweb:
            f.write(line + "\n")

    # http_summary.txt
    summary_file = outdir / "http_summary.txt"
    with open(summary_file, 'w') as f:
        f.write(f"HTTP Enumeration Summary — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {args.target}\n")
        f.write(f"Hosts scanned: {len(hosts)}\n")
        f.write(f"Ports: {', '.join(ports)}\n\n")
        f.write(f"Web services found  : {len(all_titles)}\n")
        f.write(f"ADCS endpoints      : {len(all_adcs)} {'[CRITICAL]' if all_adcs else ''}\n")
        f.write(f"WebDAV hosts        : {len(all_webdav)} {'[CRITICAL]' if all_webdav else ''}\n")
        f.write(f"OWA/Exchange        : {len(all_services.get('owa', []))}\n")
        f.write(f"RDWeb               : {len(all_services.get('rdweb', []))}\n")
        f.write(f"ADFS                : {len(all_services.get('adfs', []))}\n")
        f.write(f"WSUS                : {len(all_services.get('wsus', []))}\n\n")
        if all_adcs:
            f.write("[CRITICAL] ADCS Endpoints:\n")
            for line in all_adcs:
                f.write(f"  {line}\n")
            f.write("\n")
        if all_webdav:
            f.write("[CRITICAL] WebDAV Hosts:\n")
            for line in all_webdav:
                f.write(f"  {line}\n")
            f.write("\n")
        f.write("Output files:\n")
        for fname in ['http_titles.txt', 'http_adcs.txt', 'http_webdav.txt',
                      'http_owa.txt', 'http_rdweb.txt', 'http_adfs.txt',
                      'http_wsus.txt', 'http_whatweb.txt']:
            f.write(f"  {outdir}/{fname}\n")

    log_step("Summary")
    log_info(f"Web services found  : {len(all_titles)}")
    if all_adcs:
        log_warn(f"[CRITICAL] ADCS     : {len(all_adcs)} endpoint(s)")
    if all_webdav:
        log_warn(f"[CRITICAL] WebDAV   : {len(all_webdav)} host(s)")
    log_ok(f"Results saved to: {outdir}")


if __name__ == "__main__":
    main()
