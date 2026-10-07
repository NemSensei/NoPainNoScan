#!/usr/bin/env python3
"""check_ssh.py - SSH enumeration and cipher audit"""

import argparse, subprocess, os, sys, re, socket, shlex
from datetime import datetime
from pathlib import Path
import ipaddress


from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, confirm_step, set_total_steps, enable_auto_accept,
                         sub_progress)


set_total_steps(4)

def run(cmd, timeout=60):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1


# ─── User confirmation ────────────────────────────────────────────────────────


# ─── Target resolution ────────────────────────────────────────────────────────

def resolve_targets(target_arg):
    """Expand file / single IP / CIDR into a flat list of IP strings."""
    targets = []
    p = Path(target_arg)

    if p.is_file():
        lines = p.read_text().splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.extend(_expand(line))
    else:
        targets.extend(_expand(target_arg))

    return list(dict.fromkeys(targets))

def _expand(entry):
    try:
        net = ipaddress.ip_network(entry, strict=False)
        return [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        return [entry]

# ─── Step 1 – Banner grab ─────────────────────────────────────────────────────

def grab_banner(ip, port, timeout=5):
    """Return the raw SSH banner or None."""
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(256).decode(errors='ignore').strip()
        return banner if banner else None
    except Exception:
        return None

def step_banner(hosts, port, out_dir):
    log_step("STEP 1 — Banner grab and SSH version")
    if not confirm_step("STEP 1 — Banner grab", f"socket connect to {len(hosts)} host(s) on port {port}"):
        (out_dir / "ssh_banners.txt").write_text("")
        return {}
    banners = {}
    _n = len(hosts)
    for _i, ip in enumerate(hosts, 1):
        sub_progress(_i, _n, label="STEP 1 — Banner grab")
        banner = grab_banner(ip, port)
        if banner:
            log_ok(f"{ip}:{port} → {banner}")
            banners[ip] = banner
        else:
            log_warn(f"{ip}:{port} → no response / not SSH")

    banner_file = out_dir / "ssh_banners.txt"
    banner_file.write_text("".join(f"{ip}: {b}\n" for ip, b in sorted(banners.items())))
    log_info(f"Banners written → {banner_file}")
    return banners

# ─── Step 2 – Algorithm audit ─────────────────────────────────────────────────

WEAK_ALGOS = {
    # KEX
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    # Ciphers
    "arcfour", "arcfour128", "arcfour256",
    "des-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    # MACs
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "umac-64@openssh.com",
}

def _parse_ssh_audit(output):
    """Return list of weakness descriptions found in ssh-audit output."""
    issues = []
    for line in output.splitlines():
        lower = line.lower()
        if "(fail)" in lower or "(warn)" in lower:
            issues.append(line.strip())
        elif any(algo in lower for algo in WEAK_ALGOS):
            issues.append(line.strip())
    return list(dict.fromkeys(issues))

def step_audit(hosts, port, out_dir):
    log_step("STEP 2 — Algorithm audit (ssh-audit / nxc fallback)")
    if not confirm_step("STEP 2 — Algorithm audit", f"ssh-audit --no-colors -p {port} <ip>  (or nxc ssh <ip> fallback)"):
        (out_dir / "ssh_weak_algos.txt").write_text("")
        return {}
    has_ssh_audit = tool_exists("ssh-audit")
    has_nxc = tool_exists("nxc")

    if not has_ssh_audit:
        log_warn("ssh-audit not found. Install: apt install ssh-audit  OR  pip install ssh-audit")
        if not has_nxc:
            log_warn("nxc not found either — skipping algorithm audit")
            (out_dir / "ssh_weak_algos.txt").write_text("")
            return {}

    weak_hosts = {}

    for ip in hosts:
        if has_ssh_audit:
            audit_out, audit_err, rc = run(
                f"ssh-audit --no-colors -p {port} {ip}", timeout=30
            )
            full_output = audit_out + audit_err
        else:
            # nxc ssh gives basic info — limited but better than nothing.
            # NB: en nxc `-p` = MOT DE PASSE ; le port se passe avec `--port`.
            audit_out, audit_err, rc = run(f"nxc ssh {shlex.quote(ip)} --port {port}", timeout=30)
            full_output = audit_out + audit_err

        audit_file = out_dir / f"ssh_audit_{ip}.txt"
        audit_file.write_text(full_output)

        issues = _parse_ssh_audit(full_output)
        if issues:
            log_warn(f"{ip} — {len(issues)} weak algorithm(s) detected")
            weak_hosts[ip] = issues
        else:
            log_ok(f"{ip} — no obvious weak algorithms detected")

    weak_file = out_dir / "ssh_weak_algos.txt"
    weak_file.write_text("".join(
        f"\n[{ip}]\n" + "".join(f"  {issue}\n" for issue in weak_hosts[ip])
        for ip in sorted(weak_hosts)
    ))
    log_info(f"Weak-algo report → {weak_file}")
    return weak_hosts

# ─── Step 3 – Auth methods ────────────────────────────────────────────────────

def step_auth_methods(hosts, port, out_dir):
    log_step("STEP 3 — Authentication methods (no credentials)")
    if not confirm_step("STEP 3 — Authentication methods", f"ssh -o PreferredAuthentications=none dummy@<ip> (x{len(hosts)})"):
        (out_dir / "ssh_password_auth.txt").write_text("")
        return []
    password_auth_hosts = []

    _n = len(hosts)
    for _i, ip in enumerate(hosts, 1):
        sub_progress(_i, _n, label="STEP 3 — Authentication methods")
        cmd = (
            f"ssh -o BatchMode=yes -o ConnectTimeout=5 "
            f"-o PreferredAuthentications=none "
            f"-o StrictHostKeyChecking=no "
            f"-p {port} dummy@{ip} 2>&1"
        )
        out, err, _ = run(cmd, timeout=10)
        combined = (out + err).lower()

        # Look for "authentications that can continue: password,..."
        match = re.search(
            r"authentications that can continue[:\s]+([^\r\n]+)", combined
        )
        if match:
            methods = match.group(1).strip()
            log_info(f"{ip} — auth methods: {methods}")
            if "password" in methods:
                log_warn(f"{ip} — PASSWORD authentication ENABLED")
                password_auth_hosts.append(f"{ip}: {methods}")
        else:
            log_info(f"{ip} — could not determine auth methods (host may be unreachable)")

    pw_file = out_dir / "ssh_password_auth.txt"
    pw_file.write_text("".join(f"{entry}\n" for entry in sorted(password_auth_hosts)))
    log_info(f"Password-auth hosts → {pw_file}")
    return password_auth_hosts

# ─── Step 4 – Credential test ────────────────────────────────────────────────

def step_cred_test(hosts, port, username, password, out_dir):
    log_step("STEP 4 — Default credential test")
    if not confirm_step("STEP 4 — Credential test", f"nxc ssh <hosts> --port {port} -u {username} -p ***"):
        (out_dir / "ssh_login_success.txt").write_text("")
        return []
    if not tool_exists("nxc"):
        log_err("nxc not found — cannot run credential test")
        (out_dir / "ssh_login_success.txt").write_text("")
        return []

    # Write a temporary hosts file for nxc
    tmp_hosts = out_dir / "_tmp_hosts.txt"
    tmp_hosts.write_text("\n".join(hosts) + "\n")

    out, err, rc = run(
        f"nxc ssh {tmp_hosts} --port {port} -u {shlex.quote(username)} -p {shlex.quote(password)}",
        timeout=120,
    )
    full_output = out + err

    successes = []
    for line in full_output.splitlines():
        if "[+]" in line or "pwned" in line.lower() or "success" in line.lower():
            successes.append(line.strip())

    success_file = out_dir / "ssh_login_success.txt"
    success_file.write_text("".join(f"{s}\n" for s in successes))

    if successes:
        log_warn(f"{len(successes)} successful login(s) found!")
        for s in successes:
            log_ok(s)
    else:
        log_info("No successful logins with provided credentials")

    tmp_hosts.unlink(missing_ok=True)
    return successes

# ─── Summary ─────────────────────────────────────────────────────────────────

def write_summary(out_dir, hosts, banners, weak_hosts, pw_hosts, successes, has_creds):
    summary = out_dir / "ssh_summary.txt"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        RULE,
        f"SSH Audit Summary — {ts}",
        RULE,
        f"Hosts scanned       : {len(hosts)}",
        f"Banners collected   : {len(banners)}",
        f"Weak-algo hosts     : {len(weak_hosts)}",
        f"Password-auth hosts : {len(pw_hosts)}",
    ]
    if has_creds:
        lines.append(f"Successful logins   : {len(successes)}")
    lines += ["", "── Banners ──"]
    for ip, b in sorted(banners.items()):
        lines.append(f"  {ip}: {b}")
    if weak_hosts:
        lines += ["", "── Weak algorithms ──"]
        for ip in sorted(weak_hosts):
            lines.append(f"  {ip}:")
            for issue in weak_hosts[ip][:5]:
                lines.append(f"    {issue}")
    if pw_hosts:
        lines += ["", "── Password auth enabled ──"]
        for entry in sorted(pw_hosts):
            lines.append(f"  {entry}")
    if successes:
        lines += ["", "── Successful logins ──"]
        for s in successes:
            lines.append(f"  {s}")
    lines.append("")
    summary.write_text("\n".join(lines))
    log_ok(f"Summary → {summary}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="check_ssh.py — SSH enumeration and cipher audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s -t hosts_ssh.txt\n"
            "  %(prog)s -t 192.168.1.0/24 --port 2222\n"
            "  %(prog)s -t 192.168.1.10 -u admin -p admin\n"
        ),
    )
    parser.add_argument("-t", "--target", required=True,
                        help="File of IPs, single IP, or CIDR range")
    parser.add_argument("-o", "--output", default=None,
                        help="Output directory (default: ./ssh_results_<timestamp>)")
    parser.add_argument("-u", "--username", default=None,
                        help="Username for credential test (step 4)")
    parser.add_argument("-p", "--password", default=None,
                        help="Password for credential test (step 4)")
    parser.add_argument("-H", "--hash", default=None,
                        help="Not used for SSH (ignored)")
    parser.add_argument("--port", type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Non-interactive: accept all steps (for automation/UI)")
    args = parser.parse_args()
    if args.yes:
        enable_auto_accept()

    # Banner
    print(f"\n{C.BOLD}SSH — Enumeration & Cipher Audit{C.ENDC}")
    print(f"{C.DIM}{RULE}{C.ENDC}")

    # Output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output) if args.output else Path(f"ssh_results_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Output directory: {out_dir.resolve()}")

    # Resolve targets
    hosts = resolve_targets(args.target)
    if not hosts:
        log_err("No valid targets found. Exiting.")
        sys.exit(1)
    log_info(f"Targets: {len(hosts)} host(s) on port {args.port}")

    if args.hash:
        log_warn("--hash is not applicable to SSH and will be ignored")

    has_creds = bool(args.username and args.password)

    # Run steps
    banners   = step_banner(hosts, args.port, out_dir)
    weak_hosts = step_audit(hosts, args.port, out_dir)
    pw_hosts  = step_auth_methods(hosts, args.port, out_dir)
    successes = []
    if has_creds:
        successes = step_cred_test(hosts, args.port, args.username, args.password, out_dir)
    else:
        log_info("No credentials provided — skipping step 4 (credential test)")
        (out_dir / "ssh_login_success.txt").write_text("")

    write_summary(out_dir, hosts, banners, weak_hosts, pw_hosts, successes, has_creds)

    print(f"\n{C.BOLD}Scan Complete{C.ENDC}")
    print(f"{C.DIM}{RULE}{C.ENDC}")
    log_ok(f"Results in: {out_dir.resolve()}")

if __name__ == "__main__":
    main()
