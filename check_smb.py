#!/usr/bin/env python3
"""check_smb.py - SMB enumeration and vulnerability checks

Usage:
    python3 check_smb.py -t hosts_smb.txt
    python3 check_smb.py -t 192.168.1.0/24 -u admin -p 'P@ssw0rd' -d CORP

Workflow:
    1. Recon (no creds, then creds if given)
       - host info, signing:False → relay targets, SMBv1:True → legacy hosts
       - reachable SMB hosts
       - with creds: hosts where auth succeeds ([+]) / admin (Pwn3d!/admin)
         → this reduced host set feeds the heavy authenticated steps (fast on big scope)
    2. Null session share listing (no creds, on reachable hosts)
    3. Authenticated share enumeration (on auth hosts): READ / WRITE / accessible (non-$)
    4. GPP credentials in SYSVOL (on auth hosts): gpp_password / gpp_autologin

    NB: file spidering (--spider SYSVOL/NETLOGON and -M spider_plus) was removed on
    purpose — too noisy; GPP covers the high-value SYSVOL secrets, the rest is manual.

Output files:
    smb_hosts_info.txt         Full host info table
    smb_unsigned.txt           IPs with SMB signing disabled (relay targets)
    smb_v1.txt                 IPs with SMBv1 enabled
    smb_login_success.txt      Hosts where supplied creds authenticate ([+])
    smb_admin.txt              Hosts where creds are admin (Pwn3d!/admin), if any
    smb_shares_null.txt        Shares accessible via null session
    smb_shares_read.txt        Readable shares with creds (non-$)
    smb_shares_write.txt       Writable shares with creds (non-$) [CRITICAL]
    smb_shares_accessible.txt  Consolidated R/W accessible shares (non-$)
    sysvol_gpp.txt             GPP credentials from SYSVOL [CRITICAL]
    sysvol_gpp_raw.txt         Raw gpp_password/gpp_autologin output
    smb_summary.txt            Human-readable findings summary
"""

import argparse
import ipaddress
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


# =============================================================================
# COLOURS
# =============================================================================
from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, confirm_step, set_total_steps, enable_auto_accept,
                         emit_progress, strip_ansi, nxc_is_admin, nxc_login_ok)


set_total_steps(4)

# Concurrence nxc, fixée depuis --threads dans main(). nxc gère le fan-out par hôte ;
# plus de threads = plus rapide sur gros scope.
_THREADS = 100


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


def run_nxc(cmd, timeout):
    """Run an nxc command, returning (stdout, returncode).

    Pensé pour les gros scopes : la sortie est redirigée vers un fichier temporaire
    (pas de deadlock de pipe), et sur timeout on tue TOUT le groupe de processus
    (le shell ET nxc, via start_new_session + killpg) puis on relit la sortie
    PARTIELLE déjà écrite — au lieu de tout perdre comme le faisait run() qui
    renvoyait "" sur TimeoutExpired (cause du « plus rien ne remonte » sur gros scan).
    rc = -1 si le process a été tué sur timeout.
    """
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".nxcout", delete=False)
    tf.close()
    try:
        with open(tf.name, "w") as fout:
            proc = subprocess.Popen(cmd, shell=True, stdout=fout,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait()
                rc = -1
                log_warn(f"nxc timeout ({timeout}s) — sortie partielle conservée")
        return Path(tf.name).read_text(errors="replace"), rc
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass


def scaled_timeout(n_hosts, base=180, per_host=5, cap=3600):
    """Timeout proportionnel au nombre d'hôtes (évite la troncature sur gros scope)."""
    return min(base + per_host * max(0, n_hosts), cap)


def _nxc(hosts_file, extra, creds=""):
    """Construit une commande `nxc smb` (chemin quoté, --threads injecté)."""
    base = f"nxc smb {shlex.quote(str(hosts_file))}"
    if creds:
        base += f" {creds}"
    return f"{base} --threads {_THREADS} {extra}".strip()


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
        parts += ["-u", shlex.quote(args.username)]
    if args.hash:
        parts += ["-H", shlex.quote(args.hash)]
    elif args.password is not None:
        parts += ["-p", shlex.quote(args.password)]
    if args.domain:
        parts += ["-d", shlex.quote(args.domain)]
    return " ".join(parts)


# =============================================================================
# STEP 1 — RECON : info/signing + hôtes joignables + hôtes où l'auth passe
# =============================================================================
def step1_recon(hosts_file, out_dir, creds_args, n_hosts):
    """Recon SMB en un ou deux balayages nxc.

    1) Sweep SANS creds : infos hôte, signing:False (cibles relais), SMBv1:True, et
       la liste des hôtes SMB JOIGNABLES.
    2) Sweep AVEC creds (si fournis) : hôtes où l'authentification réussit ([+]) et
       ceux en admin (Pwn3d!/admin). Cette liste d'hôtes authentifiés sert de cible
       RÉDUITE aux étapes lourdes (shares, GPP) → beaucoup plus rapide sur gros scope.

    Returns: (unsigned, smbv1, host_rows, reachable, auth_hosts)
    """
    log_step("STEP 1 — SMB Recon (info, signing, reachable, auth)")

    unsigned_ips, smbv1_ips, host_rows = [], [], []
    reachable, auth_hosts, admin_hosts = [], [], []
    relay_file = out_dir / "smb_unsigned.txt"

    detail = "nxc smb <hosts> --gen-relay-list" + (
        "  ; puis  nxc smb <hosts> -u .. -p/-H .. (sweep auth)" if creds_args else "")
    if not confirm_step("STEP 1 — SMB Recon", detail):
        write_file(relay_file, [])
        write_file(out_dir / "smb_v1.txt", [])
        (out_dir / "smb_hosts_info.txt").write_text("# Skipped by user request\n")
        write_file(out_dir / "smb_login_success.txt", [])
        return unsigned_ips, smbv1_ips, host_rows, reachable, auth_hosts

    # --- 1) Sweep sans creds : infos + signing + SMBv1 + joignables ---
    log_info("nxc smb sweep (infos hôte + relay list) ...")
    out, rc = run_nxc(_nxc(hosts_file, f"--gen-relay-list {shlex.quote(str(relay_file))}"),
                      timeout=scaled_timeout(n_hosts))
    out = strip_ansi(out)

    # SMB  10.0.0.1  445  DC01  [*] Windows ... (signing:True) (SMBv1:False)
    info_re = re.compile(
        r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\[\*\]\s+(.*?)"
        r"\(signing:(\w+)\).*?\(SMBv1:(\w+)\)")
    ip_re = re.compile(r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s")
    seen = set()
    for line in out.splitlines():
        mi = ip_re.search(line)
        if mi and mi.group(1) not in seen:
            seen.add(mi.group(1))
            reachable.append(mi.group(1))
        m = info_re.search(line)
        if not m:
            continue
        ip, hostname, os_info, signing, smbv1 = m.groups()
        host_rows.append(f"{ip:<18} {hostname:<20} {signing:<8} {smbv1:<8} {os_info.strip()}")
        if signing.lower() == "false":
            unsigned_ips.append(ip)
        if smbv1.lower() == "true":
            smbv1_ips.append(ip)

    if relay_file.exists():
        existing = [l.strip() for l in relay_file.read_text().splitlines() if l.strip()]
        unsigned_ips = list(set(unsigned_ips + existing))

    write_file(out_dir / "smb_unsigned.txt", unsigned_ips, label="Signing disabled")
    write_file(out_dir / "smb_v1.txt", smbv1_ips, label="SMBv1 enabled")
    header = f"{'IP':<18} {'Hostname':<20} {'Signing':<8} {'SMBv1':<8} OS\n" + "-" * 80
    (out_dir / "smb_hosts_info.txt").write_text(header + "\n" + "\n".join(host_rows) + "\n")
    log_ok(f"Joignables SMB: {len(reachable)} | signing off: {len(unsigned_ips)} | SMBv1: {len(smbv1_ips)}")

    # --- 2) Sweep avec creds : qui s'authentifie ? ---
    if creds_args:
        log_info("nxc smb sweep auth (hôtes acceptant les creds) ...")
        aout, _ = run_nxc(_nxc(hosts_file, "", creds=creds_args), timeout=scaled_timeout(n_hosts))
        aout = strip_ansi(aout)
        a_re = re.compile(r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s")
        seen_a = set()
        for line in aout.splitlines():
            if not nxc_login_ok(line):          # [+] = creds valides
                continue
            ma = a_re.search(line)
            if not ma:
                continue
            ip = ma.group(1)
            if ip not in seen_a:
                seen_a.add(ip)
                auth_hosts.append(ip)
            if nxc_is_admin(line):              # (Pwn3d!)/(admin) = admin local
                admin_hosts.append(ip)
        write_file(out_dir / "smb_login_success.txt", auth_hosts,
                   label="Hosts where creds authenticate")
        if admin_hosts:
            write_file(out_dir / "smb_admin.txt", admin_hosts,
                       label="Hosts with admin (Pwn3d!/admin)")
        if auth_hosts:
            log_ok(f"Creds valides sur {len(set(auth_hosts))} hôte(s)"
                   + (f", admin sur {len(set(admin_hosts))}" if admin_hosts else ""))
        else:
            log_warn("Les creds ne s'authentifient sur aucun hôte.")
    else:
        write_file(out_dir / "smb_login_success.txt", [])

    return unsigned_ips, smbv1_ips, host_rows, sorted(set(reachable)), sorted(set(auth_hosts))


# =============================================================================
# STEP 2 — NULL SESSION SHARES
# =============================================================================
def step2_null_session(hosts_file, out_dir, n_hosts):
    """Enumerate shares via null session (no creds), on reachable hosts."""
    log_step("STEP 2 — Null Session Share Listing")

    if not confirm_step("STEP 2 — Null Session Share Listing", "nxc smb <reachable> --shares -u '' -p ''"):
        write_file(out_dir / "smb_shares_null.txt", [])
        return []

    out, rc = run_nxc(_nxc(hosts_file, "--shares", creds="-u '' -p ''"),
                      timeout=scaled_timeout(n_hosts))
    out = strip_ansi(out)

    shares = []
    # READ,WRITE doit être testé avant READ seul (sinon un READ,WRITE est classé READ).
    share_line = re.compile(
        r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(\S+)\s+(READ(?:,WRITE)?|WRITE)"
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
def step3_auth_shares(hosts_file, out_dir, creds_args, n_hosts):
    """Enumerate accessible shares with credentials (on authenticated hosts only).

    Produit trois vues (les shares administratifs en `$` — ADMIN$, C$, IPC$… — sont
    exclus partout, ce ne sont pas des findings d'accès pertinents) :
      • smb_shares_read.txt        — shares lisibles (sans WRITE)
      • smb_shares_write.txt       — shares inscriptibles [CRITICAL]
      • smb_shares_accessible.txt  — liste consolidée READ|WRITE (ip / share / perms)

    La sortie nxc est nettoyée de ses codes couleur ANSI avant parsing (robustesse).
    """
    log_step("STEP 3 — Authenticated Share Enumeration")

    if not confirm_step("STEP 3 — Authenticated Share Enumeration", "nxc smb <auth-hosts> <creds> --shares"):
        write_file(out_dir / "smb_shares_read.txt", [])
        write_file(out_dir / "smb_shares_write.txt", [])
        write_file(out_dir / "smb_shares_accessible.txt", [])
        return [], [], []

    out, rc = run_nxc(_nxc(hosts_file, "--shares", creds=creds_args),
                      timeout=scaled_timeout(n_hosts))
    out = strip_ansi(out)

    read_shares       = []
    write_shares      = []
    accessible_shares = []

    share_line = re.compile(
        r"SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(\S+)\s+(READ(?:,WRITE)?|WRITE)"
    )
    for line in out.splitlines():
        m = share_line.search(line)
        if not m:
            continue
        ip, share, perms = m.groups()
        if share.endswith("$"):          # exclure les partages administratifs
            continue
        entry = f"{ip}  {share}  [{perms}]"
        accessible_shares.append(entry)
        if "WRITE" in perms:
            write_shares.append(entry)
        else:
            read_shares.append(entry)

    write_file(out_dir / "smb_shares_read.txt", read_shares, sort=False, label="Readable shares")
    write_file(out_dir / "smb_shares_write.txt", write_shares, sort=False, label="Writable shares [CRITICAL]")
    write_file(out_dir / "smb_shares_accessible.txt", accessible_shares, sort=False,
               label="Accessible shares (R/W, non-admin)")

    if write_shares:
        log_warn(f"[CRITICAL] {len(write_shares)} writable share(s) found!")

    return read_shares, write_shares, accessible_shares


# =============================================================================
# STEP 4 — GPP CREDENTIALS (SYSVOL)
# =============================================================================
# NB : le spidering SYSVOL/NETLOGON (--spider) et spider_plus (inventaire de tous les
# shares) ont été RETIRÉS volontairement — trop de bruit. GPP ci-dessous extrait les
# secrets à forte valeur de SYSVOL ; le reste de l'exploration se fait à la main.
# Lignes à retenir dans la sortie des modules GPP : les marqueurs de PAYOFF d'un
# vrai secret — cpassword déchiffré, autologon, "Found credentials in …", et les
# lignes de résultat "Usernames:" / "Passwords:". On cible ces motifs précis (avec
# ':' ou "in ") plutôt que les mots génériques "password/username/credential" seuls :
#   • la version précédente trop large comptait les lignes d'auth nxc
#     (ex. "[+] CORP\svc:xxx STATUS_PASSWORD_MUST_CHANGE") comme un faux GPP ;
#   • la version trop étroite (cpassword|GPP|autologin) jetait au contraire les
#     vraies lignes "Found credentials…/Usernames:/Passwords:" → faux négatif.
# Ce motif précis ne matche jamais un "user:pass" d'auth, et garde tous les payoffs.
_GPP_FINDING_RE = re.compile(
    r"(?i)(cpassword|autologin|credentials?\s+in\b|usernames?\s*:|passwords?\s*:)"
)
# Ceinture-bretelles : on exclut quand même les lignes négatives et de statut nxc.
_GPP_NEGATIVE_RE = re.compile(
    r"(?i)(no (gpp|autologin|credential|password|result|xml|file)"
    r"|not found|nothing found|could ?n'?t|could not|failed to"
    r"|STATUS_[A-Z_]+)"
)


def step_gpp(hosts_file, out_dir, creds_args, n_hosts):
    """Extract GPP credentials from SYSVOL via nxc gpp_password / gpp_autologin.

    gpp_password déchiffre les cpassword des fichiers de préférences GPP
    (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml,
    Printers.xml) ; gpp_autologin extrait les identifiants d'autologon de
    registry.xml. Les deux lisent SYSVOL. Toute trouvaille = creds en clair → 🔴.
    """
    log_step("STEP 4 — GPP credentials (SYSVOL)")

    findings = []
    if not confirm_step("STEP 4 — GPP credentials (SYSVOL)",
                        "nxc smb <auth-hosts> <creds> -M gpp_password  +  -M gpp_autologin"):
        write_file(out_dir / "sysvol_gpp.txt", [])
        return findings

    raw_parts = []
    for module in ("gpp_password", "gpp_autologin"):
        log_info(f"Running {module} on SYSVOL ...")
        out, rc = run_nxc(_nxc(hosts_file, f"-M {module}", creds=creds_args),
                          timeout=scaled_timeout(n_hosts))
        out = strip_ansi(out)
        raw_parts.append(f"# === {module} ===\n{out}")
        for line in out.splitlines():
            if _GPP_FINDING_RE.search(line) and not _GPP_NEGATIVE_RE.search(line):
                findings.append(line.strip())

    (out_dir / "sysvol_gpp_raw.txt").write_text("\n".join(raw_parts) + "\n")
    findings = list(dict.fromkeys(findings))
    write_file(out_dir / "sysvol_gpp.txt", findings, sort=False,
               label="GPP credentials [CRITICAL]")

    if findings:
        log_warn(f"[CRITICAL] {len(findings)} GPP credential finding(s) in SYSVOL!")
    else:
        log_info("No GPP credentials found (see sysvol_gpp_raw.txt for raw module output).")

    return findings


# =============================================================================
# SUMMARY
# =============================================================================
def write_summary(out_dir, unsigned, smbv1, reachable, auth_hosts, null_shares,
                  read_shares, write_shares, accessible_shares, gpp_findings, has_creds):
    """Write a human-readable summary file and print it."""
    log_step("SUMMARY")

    lines = [
        f"SMB Enumeration Summary — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        RULE,
        "",
        f"[RECON]    Reachable SMB hosts:                              {len(reachable)}",
        f"[SIGNING]  Hosts with SMB signing DISABLED (relay targets): {len(unsigned)}",
        f"[SMBv1]    Hosts with SMBv1 ENABLED:                         {len(smbv1)}",
        f"[NULL]     Shares accessible via null session:               {len(null_shares)}",
    ]

    if has_creds:
        lines += [
            f"[AUTH]     Hosts where creds authenticate:                 {len(auth_hosts)}",
            f"[AUTH]     Accessible shares (R/W, non-admin):             {len(accessible_shares)}",
            f"[AUTH]     Readable shares (with creds):                   {len(read_shares)}",
            f"[CRITICAL] Writable shares (with creds):                   {len(write_shares)}",
            f"[CRITICAL] GPP credential findings (SYSVOL):               {len(gpp_findings)}",
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

    if gpp_findings:
        lines += ["", "[CRITICAL] GPP CREDENTIALS (SYSVOL):"]
        lines += [f"    {g}" for g in gpp_findings]

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
    p.add_argument("--threads", type=int, default=100,
                   help="nxc concurrency, passed as --threads (default: 100; raise for big scopes)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Non-interactive: accept all steps (for automation/UI)")
    return p.parse_args()


# =============================================================================
# MAIN
# =============================================================================
def main():
    global _THREADS
    args = parse_args()
    if getattr(args, "yes", False):
        enable_auto_accept()
    _THREADS = max(1, args.threads)

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
                      "smb_login_success.txt", "smb_shares_null.txt",
                      "smb_shares_read.txt", "smb_shares_write.txt",
                      "smb_shares_accessible.txt", "sysvol_gpp.txt", "smb_summary.txt"]:
            (out_dir / fname).write_text("")
        sys.exit(1)

    has_creds = bool(args.username and (args.password is not None or args.hash))
    creds_args = build_creds_args(args) if has_creds else ""
    n_all = len(hosts)

    # --- STEP 1: recon (info/signing + reachable + auth) ---
    unsigned, smbv1, host_rows, reachable, auth_hosts = step1_recon(
        hosts_tmp, out_dir, creds_args, n_all)

    # --- STEP 2: null session (no creds) on reachable hosts only ---
    reachable_tmp = hosts_to_tmpfile(reachable) if reachable else hosts_tmp
    null_shares = step2_null_session(reachable_tmp, out_dir, len(reachable) or n_all)

    read_shares, write_shares, accessible_shares = [], [], []
    gpp_findings = []
    auth_tmp = None

    # --- STEP 3 & 4: authenticated, only against hosts where creds work ---
    if has_creds and auth_hosts:
        auth_tmp = hosts_to_tmpfile(auth_hosts)
        n_auth = len(auth_hosts)
        read_shares, write_shares, accessible_shares = step3_auth_shares(
            auth_tmp, out_dir, creds_args, n_auth)
        gpp_findings = step_gpp(auth_tmp, out_dir, creds_args, n_auth)
    else:
        if has_creds and not auth_hosts:
            log_warn("Creds did not authenticate anywhere — skipping share/GPP steps.")
        else:
            log_info("No credentials provided — skipping authenticated checks (steps 3-4)")
        for fname in ["smb_shares_read.txt", "smb_shares_write.txt",
                      "smb_shares_accessible.txt", "sysvol_gpp.txt"]:
            (out_dir / fname).write_text("")

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    write_summary(out_dir, unsigned, smbv1, reachable, auth_hosts, null_shares,
                  read_shares, write_shares, accessible_shares, gpp_findings, has_creds)

    # Cleanup temp host files
    tmp_files = [hosts_tmp]
    if reachable:
        tmp_files.append(reachable_tmp)
    if auth_tmp:
        tmp_files.append(auth_tmp)
    for tf in set(tmp_files):
        try:
            os.unlink(tf)
        except OSError:
            pass

    log_ok(f"Done. Results in: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
