#!/usr/bin/env python3
"""check_ldap.py — LDAP / Active Directory checks pour pentest interne.

À lancer sur les DC (389/636/3268/3269). Enchaîne les vérifications qu'on fait
systématiquement en interne :

  STEP 1  rootDSE / domaine (sans creds) — identifie les vrais DC.
  STEP 2  LDAP signing + channel binding (lu dans la bannière `nxc ldap`) —
          exposition relais NTLM → LDAP (RBCD, ADCS ESC8). Souvent sans creds.
  STEP 3  Bind anonyme / null bind + dump anonyme (ldapsearch).
  STEP 4  Énumération authentifiée (nxc ldap) : users, groups, password policy,
          MachineAccountQuota, PASSWD_NOTREQD, délégation non contrainte,
          adminCount=1, descriptions (creds en clair), LAPS, gMSA, ADCS,
          AS-REP roasting, Kerberoasting.
  STEP 5  Collecte BloodHound (bloodhound-python -c All).

Conception "gros scope" : la sortie nxc est nettoyée de l'ANSI et PARSÉE en
findings propres (une entité par ligne) — jamais la sortie brute, qui fausse les
compteurs du rapport (lignes bannière [*], auth [+], en-têtes). Sur timeout on
tue tout le groupe de processus et on garde la sortie partielle.
"""

import argparse
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, confirm_step, set_total_steps, enable_auto_accept,
                         emit_progress, strip_ansi)

set_total_steps(5)

# Concurrence nxc (--threads), fixée depuis main(). Peu de DC en général, mais ça
# aide quand le fichier de cibles contient tout le scope.
_THREADS = 50


# ---------------------------------------------------------------------------
# Exécution
# ---------------------------------------------------------------------------

def run(cmd, timeout=60):
    """Commande shell courte (ldapsearch/bloodhound). (stdout, stderr, rc)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1
    except Exception as e:                       # noqa: BLE001
        return "", str(e), 1


def run_nxc(cmd, timeout):
    """Lance nxc en gardant la sortie PARTIELLE sur timeout. (stdout, rc).

    Même logique durcie que check_smb : sortie redirigée vers fichier (pas de
    deadlock de pipe), et sur timeout on tue TOUT le groupe de processus
    (start_new_session + killpg) puis on relit ce qui a été écrit — au lieu de
    tout perdre comme subprocess.run() sur TimeoutExpired. rc = -1 si tué.
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


def scaled_timeout(n_hosts, base=120, per_host=10, cap=900):
    """Timeout proportionnel au nombre de cibles (évite la troncature)."""
    return min(base + per_host * max(0, n_hosts), cap)


def write_file(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def write_lines(path: Path, items, sort=False):
    """Écrit une liste dédupliquée (ordre préservé, ou trié)."""
    cleaned = [i.strip() for i in items if i and i.strip()]
    cleaned = sorted(set(cleaned)) if sort else list(dict.fromkeys(cleaned))
    write_file(path, "\n".join(cleaned) + ("\n" if cleaned else ""))
    return cleaned


def parse_targets(target_arg: str) -> list[str]:
    """Accepte : fichier de hosts, IP seule, ou CIDR (via nmap -sL)."""
    p = Path(target_arg)
    if p.is_file():
        lines = [l.strip() for l in p.read_text().splitlines()
                 if l.strip() and not l.startswith('#')]
        if not lines:
            log_warn(f"Target file '{target_arg}' is empty.")
        return lines

    if '/' in target_arg and tool_exists('nmap'):
        # $NF est entre parenthèses quand nmap résout un hostname : on les retire.
        out, _, _ = run(f"nmap -n -sL {shlex.quote(target_arg)} | awk '/Nmap scan report/{{print $NF}}'")
        ips = [l.strip().strip('()') for l in out.splitlines() if l.strip()]
        return ips if ips else [target_arg]

    return [target_arg]


# ---------------------------------------------------------------------------
# Identifiants nxc (réels + version redacted pour l'affichage/UI)
# ---------------------------------------------------------------------------

def build_creds(user, password, nt_hash, domain):
    """Retourne (real, display) : args nxc réels et version sans secret.

    Le mot de passe / hash n'apparaît jamais dans les logs ni dans l'UI
    (cf. durcissement webui « stop leaking credentials »)."""
    real = [f"-u {shlex.quote(user)}"]
    disp = [f"-u {shlex.quote(user)}"]
    if nt_hash:
        real.append(f"-H {shlex.quote(nt_hash)}")
        disp.append("-H '***'")
    else:
        real.append(f"-p {shlex.quote(password or '')}")
        disp.append("-p '***'")
    if domain:
        real.append(f"-d {shlex.quote(domain)}")
        disp.append(f"-d {shlex.quote(domain)}")
    return " ".join(real), " ".join(disp)


# ---------------------------------------------------------------------------
# Parsing de la sortie nxc ldap
# ---------------------------------------------------------------------------

# Préfixe protocole : "LDAP  10.0.0.1  389  DC01  <message>"
_NXC_PREFIX = re.compile(r'^(?:LDAP|LDAPS|SMB)\s+\S+\s+\d+\s+\S+\s+(.*)$')


def nxc_payloads(out: str):
    """Yield la partie message de chaque ligne nxc (après 'PROTO ip port host')."""
    for line in strip_ansi(out).splitlines():
        m = _NXC_PREFIX.match(line.strip())
        if m:
            yield m.group(1).rstrip()


def nxc_data_lines(out: str) -> list[str]:
    """Lignes de DONNÉES d'un module nxc : on jette bannière/auth/statut/en-têtes.

    Les lignes [*]/[+]/[-]/[!] (bannière, auth, statut) et les en-têtes de
    colonnes '-Username-...' commencent par '[' ou '-' → écartées. Ce qui reste
    est une vraie entité (utilisateur, groupe, valeur de politique, …). C'est ce
    parsing — et pas la sortie brute — qui alimente les compteurs du rapport, et
    qui évite les faux critiques (0 compte réel mais lignes bannière comptées)."""
    items = []
    for payload in nxc_payloads(out):
        if not payload or payload[0] in '[-':
            continue
        items.append(payload)
    return items


def nxc_authenticated(out: str) -> bool:
    """True si au moins une ligne [+] (auth réussie) est présente."""
    return any(p.startswith('[+]') for p in nxc_payloads(out))


_LABEL_RE = re.compile(r'^(?:user|account|samaccountname|username)\s*:\s*', re.I)


def parse_accounts(out: str) -> list[str]:
    """Liste de comptes (1er token, label 'User:'/'Account:' retiré)."""
    res = []
    for line in nxc_data_lines(out):
        line = _LABEL_RE.sub('', line)
        tok = line.split()
        if tok:
            res.append(tok[0])
    return res


def parse_groups(out: str) -> list[str]:
    """Noms de groupes (on retire le suffixe 'membercount: N' ; noms à espaces)."""
    res = []
    for line in nxc_data_lines(out):
        res.append(re.sub(r'\s+membercount:\s*\d+\s*$', '', line, flags=re.I).strip())
    return res


def parse_ldapsearch_attr(out: str, attr: str) -> list[str]:
    """Valeurs d'un attribut dans une sortie ldapsearch (ex. sAMAccountName)."""
    return [m.group(1).strip()
            for m in re.finditer(rf'^{attr}:\s*(.+)$', out, re.M | re.I)]


# ---------------------------------------------------------------------------
# STEP 1 — rootDSE
# ---------------------------------------------------------------------------

def query_rootdse(ip: str) -> str | None:
    cmd = (f"ldapsearch -x -H ldap://{shlex.quote(ip)} -b '' -s base '(objectClass=*)' "
           "defaultNamingContext namingContexts 2>/dev/null")
    out, _, rc = run(cmd, timeout=15)
    if not out:
        return None
    m = re.search(r'defaultNamingContext:\s*(.+)', out)
    if m:
        return m.group(1).strip()
    m = re.search(r'namingContexts:\s*(DC=\S+)', out, re.IGNORECASE)
    return m.group(1).strip() if m else None


def step_rootdse(hosts: list[str], outdir: Path) -> dict[str, str]:
    """rootDSE pour chaque hôte → {ip: base_dn} (DC joignables uniquement)."""
    log_step("STEP 1 — rootDSE query (no credentials)")
    host_map: dict[str, str] = {}
    lines: list[str] = []

    if not confirm_step("STEP 1 — rootDSE query",
                        f"ldapsearch -x -H ldap://<ip> -b '' -s base  (x{len(hosts)} host(s))"):
        write_file(outdir / "ldap_domain_info.txt", "# Skipped by user request\n")
        return host_map

    for ip in hosts:
        log_info(f"ldapsearch -x -H ldap://{ip} -b '' -s base  (rootDSE)")
        base_dn = query_rootdse(ip)
        if base_dn:
            log_ok(f"{ip} → {base_dn}")
            host_map[ip] = base_dn
            lines.append(f"{ip}\t{base_dn}")
        else:
            log_warn(f"{ip} → rootDSE échoué / pas de naming context (hôte non-LDAP ?)")
            lines.append(f"{ip}\tUNREACHABLE")

    write_file(outdir / "ldap_domain_info.txt", "\n".join(lines) + "\n")
    log_ok(f"Domain info → {outdir / 'ldap_domain_info.txt'}")
    return host_map


# ---------------------------------------------------------------------------
# STEP 2 — LDAP signing & channel binding (relais NTLM / ESC8)
# ---------------------------------------------------------------------------

# NetExec n'a plus le module `ldap-checker` : le statut signing / channel binding
# est désormais imprimé DIRECTEMENT dans la bannière de connexion `[*]` à chaque
# `nxc ldap`, p.ex. :
#   LDAP  10.0.0.1  389  DC01  [*] Windows ... (signing:None) (channel binding:Never)
# On parse donc la bannière au lieu d'appeler un module.
_BANNER_RE  = re.compile(r'(?:LDAP|LDAPS)\s+(\S+)\s+\d+\s+\S+\s+\[\*\](.*)')
_SIGNING_TOK = re.compile(r'\(\s*(?:ldap[\s_]*)?signing\s*:\s*([^)]+)\)', re.I)
_CB_TOK      = re.compile(r'\(\s*channel[\s_]*binding\s*:\s*([^)]+)\)', re.I)


def _signing_bad(val: str) -> bool:
    """signing non imposé (relayable vers LDAP 389)."""
    v = val.strip().lower()
    return v in ("none", "off", "false", "no", "0", "disabled") or "not" in v


def _cb_bad(val: str) -> bool:
    """channel binding non imposé (relayable vers LDAPS 636).

    Conservateur : seul « Never » est un vrai signal de vuln. « No TLS cert »
    signifie qu'il n'y a pas de LDAPS à tester, pas une faiblesse en soi."""
    return "never" in val.strip().lower()


def step_ldap_signing(dc_targets: list[str], creds_real, creds_disp, outdir: Path):
    """Signing / channel binding non imposés → relais NTLM possible.

    Lu dans la bannière `[*]` d'un simple `nxc ldap` (marche même sans creds : la
    bannière est imprimée à la connexion, avant l'auth). Finding 🔴 : un DC qui
    n'impose pas le signing est relayable vers LDAP (ajout d'ordinateur + RBCD) ;
    channel binding « Never » l'est vers LDAPS (enrôlement de certificat ESC8)."""
    log_step("STEP 2 — LDAP signing & channel binding (NTLM relay / ESC8)")
    findings_file = outdir / "ldap_signing.txt"

    if not tool_exists("nxc"):
        log_warn("nxc introuvable — étape ignorée.")
        write_file(findings_file, "")
        return []
    if not confirm_step("STEP 2 — LDAP signing & channel binding",
                        "nxc ldap <dc>  (bannière : signing / channel binding)"):
        write_file(findings_file, "")
        return []

    targets = " ".join(shlex.quote(h) for h in dc_targets)
    # Creds si dispo (plus fiable), sinon bind anonyme : la bannière sort quand même.
    creds = creds_real if creds_real else "-u '' -p ''"
    disp  = creds_disp if creds_disp else "-u '' -p ''"
    log_info(f"nxc ldap {targets} {disp}")
    out, _ = run_nxc(f"nxc ldap {targets} {creds}", timeout=scaled_timeout(len(dc_targets)))
    write_file(outdir / "ldap_signing_raw.txt", strip_ansi(out))

    findings, seen = [], set()
    for line in strip_ansi(out).splitlines():
        m = _BANNER_RE.search(line.strip())
        if not m:
            continue
        ip, msg = m.group(1), m.group(2)
        ms, mc = _SIGNING_TOK.search(msg), _CB_TOK.search(msg)
        if not (ms or mc) or ip in seen:
            continue
        seen.add(ip)
        sv = ms.group(1).strip() if ms else "?"
        cv = mc.group(1).strip() if mc else "?"
        if (ms and _signing_bad(sv)) or (mc and _cb_bad(cv)):
            findings.append(f"{ip}  signing:{sv}  channel binding:{cv}")

    findings = write_lines(findings_file, findings, sort=True)
    if findings:
        log_warn(f"[CRITICAL] signing/channel binding non imposé sur {len(findings)} DC "
                 f"→ {findings_file}")
    else:
        log_ok("Signing/channel binding imposés (ou bannière non parsée — voir ldap_signing_raw.txt).")
    return findings


# ---------------------------------------------------------------------------
# STEP 3 — Null bind + dump anonyme
# ---------------------------------------------------------------------------

def test_nullbind(ip: str, base_dn: str) -> bool:
    cmd = (f"ldapsearch -x -H ldap://{shlex.quote(ip)} -D '' -w '' -b '{base_dn}' "
           "'(objectClass=person)' sAMAccountName cn 2>/dev/null | head -50")
    out, _, _ = run(cmd, timeout=20)
    return bool(re.search(r'^dn:', out, re.MULTILINE))


def ldap_dump(ip: str, base_dn: str, obj_class: str, attrs: str) -> str:
    cmd = (f"ldapsearch -x -H ldap://{shlex.quote(ip)} -b '{base_dn}' "
           f"'(objectClass={obj_class})' {attrs} 2>/dev/null")
    out, _, _ = run(cmd, timeout=60)
    return out


def step_nullbind(host_map: dict[str, str], outdir: Path) -> list[str]:
    log_step("STEP 3 — Null bind (anonymous LDAP) + dump")
    vulnerable: list[str] = []

    if not confirm_step("STEP 3 — Null bind test",
                        f"ldapsearch -x -D '' -w '' -b <base_dn>  (x{len(host_map)} DC)"):
        write_file(outdir / "ldap_nullbind.txt", "")
        return vulnerable

    for ip, base_dn in host_map.items():
        log_info(f"ldapsearch -x -H ldap://{ip} -D '' -w '' -b '{base_dn}'  (null bind)")
        if test_nullbind(ip, base_dn):
            log_warn(f"{ip} — NULL BIND AUTORISÉ [CRITICAL]")
            vulnerable.append(ip)
        else:
            log_ok(f"{ip} — null bind refusé (bon)")

    write_lines(outdir / "ldap_nullbind.txt", vulnerable, sort=True)
    if vulnerable:
        log_warn(f"{len(vulnerable)} DC autorisent le null bind → dump anonyme")
    else:
        log_ok("Aucun null bind autorisé.")

    # Dump anonyme sur les seuls DC vulnérables — seule source de données sans
    # creds (BloodHound/nxc authentifiés couvrent le reste quand on a des creds,
    # d'où pas de dump redondant ici).
    for ip in vulnerable:
        base_dn = host_map[ip]
        users = ldap_dump(ip, base_dn, "user", "sAMAccountName")
        write_file(outdir / f"ldap_anon_users_{ip}_raw.txt", users)
        write_lines(outdir / f"ldap_users_{ip}.txt",
                    parse_ldapsearch_attr(users, "sAMAccountName"), sort=True)

        groups = ldap_dump(ip, base_dn, "group", "cn")
        write_file(outdir / f"ldap_anon_groups_{ip}_raw.txt", groups)
        write_lines(outdir / f"ldap_groups_{ip}.txt",
                    parse_ldapsearch_attr(groups, "cn"), sort=True)

        comps = ldap_dump(ip, base_dn, "computer", "dNSHostName")
        write_file(outdir / f"ldap_anon_computers_{ip}_raw.txt", comps)
        write_lines(outdir / f"ldap_computers_{ip}.txt",
                    parse_ldapsearch_attr(comps, "dNSHostName"), sort=True)
        log_ok(f"{ip} — dump anonyme users/groups/computers écrit.")

    return vulnerable


# ---------------------------------------------------------------------------
# STEP 4 — Énumération authentifiée (nxc ldap)
# ---------------------------------------------------------------------------

def step_auth_enum(dc_targets: list[str], creds_real, creds_disp, outdir: Path) -> dict:
    """Toutes les vérifs LDAP authentifiées, en une étape (sorties PARSÉES)."""
    log_step("STEP 4 — Authenticated enumeration (nxc ldap)")
    results: dict = {}

    if not confirm_step("STEP 4 — Authenticated enumeration",
                        "nxc ldap <dc> <creds> --users/--groups/--pass-pol/-M maq/"
                        "--password-not-required/--trusted-for-delegation/--admin-count/"
                        "-M get-desc-users/--laps/--gmsa/-M adcs/--asreproast/--kerberoasting"):
        return results

    targets = " ".join(shlex.quote(h) for h in dc_targets)
    tmo = scaled_timeout(len(dc_targets))

    def nxc(extra):
        log_info(f"nxc ldap {targets} {creds_disp} {extra}")
        out, _ = run_nxc(f"nxc ldap {targets} {creds_real} {extra}", timeout=tmo)
        return out

    # Témoin d'auth : si le premier module n'auth jamais, les creds sont mauvais.
    first = nxc("--users")
    if not nxc_authenticated(first):
        log_err("Les identifiants ne s'authentifient sur aucun DC (pas de [+]) — "
                "étapes authentifiées abandonnées.")
        write_file(outdir / "ldap_auth_error.txt",
                   "nxc ldap n'a renvoyé aucun [+] — creds invalides ou DC injoignable.\n")
        return results

    # (label, flag, parser, outfile, [raw aussi])
    users  = write_lines(outdir / "ldap_users.txt",  parse_accounts(first), sort=True)
    # Brut nommé en ".raw.txt" (sans underscore) pour NE PAS matcher le glob
    # `ldap_users_*.txt` du rapport, qui regonflerait sinon le compteur users.
    write_file(outdir / "ldap_users.raw.txt", strip_ansi(first))
    log_ok(f"Users: {len(users)} → ldap_users.txt")
    results["users"] = users

    checks = [
        ("Groups",                   "--groups",                 parse_groups,   "ldap_groups.txt"),
        ("PASSWD_NOTREQD",           "--password-not-required",  parse_accounts, "ldap_no_preauth.txt"),
        ("Unconstrained delegation", "--trusted-for-delegation", parse_accounts, "ldap_delegation.txt"),
        ("adminCount=1",             "--admin-count",            parse_accounts, "ldap_admin_count.txt"),
        ("Password policy",          "--pass-pol",               nxc_data_lines, "ldap_pass_policy.txt"),
        ("MachineAccountQuota",      "-M maq",                   nxc_data_lines, "ldap_maq.txt"),
        ("User descriptions",        "-M get-desc-users",        nxc_data_lines, "ldap_descriptions.txt"),
        ("LAPS (readable)",          "--laps",                   nxc_data_lines, "ldap_laps.txt"),
        ("gMSA (readable)",          "--gmsa",                   nxc_data_lines, "ldap_gmsa.txt"),
        ("ADCS (CA/templates)",      "-M adcs",                  nxc_data_lines, "ldap_adcs.txt"),
    ]
    for label, flag, parser, fname in checks:
        out = nxc(flag)
        items = write_lines(outdir / fname, parser(out),
                            sort=fname in ("ldap_groups.txt", "ldap_no_preauth.txt",
                                           "ldap_delegation.txt", "ldap_admin_count.txt"))
        write_file(outdir / fname.replace(".txt", ".raw.txt"), strip_ansi(out))
        results[fname] = items
        (log_warn if items and fname in (
            "ldap_delegation.txt", "ldap_laps.txt", "ldap_gmsa.txt") else log_ok)(
            f"{label}: {len(items)} → {fname}")

    # AS-REP roasting / Kerberoasting : nxc écrit directement les hashes dans le
    # fichier donné. (Overlap assumé avec check_kerberos — demandé explicitement.)
    for label, flag, fname, mode in [
        ("AS-REP roast",   "--asreproast",   "ldap_asrep_hashes.txt",      "18200"),
        ("Kerberoast",     "--kerberoasting", "ldap_kerberoast_hashes.txt", "13100"),
    ]:
        hash_path = outdir / fname
        log_info(f"nxc ldap {targets} {creds_disp} {flag} {hash_path.name}")
        _, _ = run_nxc(f"nxc ldap {targets} {creds_real} {flag} {shlex.quote(str(hash_path))}",
                       timeout=tmo)
        if hash_path.exists() and hash_path.stat().st_size > 0:
            n = len([l for l in hash_path.read_text().splitlines() if l.strip()])
            results[fname] = n
            log_warn(f"[CRITICAL] {label}: {n} hash(es) → {fname}  [hashcat -m {mode}]")
        else:
            write_file(hash_path, "")
            results[fname] = 0
            log_ok(f"{label}: aucun compte concerné.")

    return results


# ---------------------------------------------------------------------------
# STEP 5 — BloodHound
# ---------------------------------------------------------------------------

def step_bloodhound(user, password, nt_hash, domain, outdir: Path, dc_ip: str):
    log_step("STEP 5 — BloodHound collection (1 DC)")
    log_info(f"Collecte via un seul DC : {dc_ip} (couvre tout le domaine {domain})")
    if not confirm_step("STEP 5 — BloodHound collection",
                        f"bloodhound-python -u {user} -d {domain} -ns {dc_ip} -c All --zip"):
        return
    bh_dir = outdir / "bloodhound"
    bh_dir.mkdir(parents=True, exist_ok=True)
    cred = f"--hashes {shlex.quote(nt_hash)}" if nt_hash else f"-p {shlex.quote(password or '')}"
    cred_disp = "--hashes '***'" if nt_hash else "-p '***'"

    cmd = (f"cd {shlex.quote(str(bh_dir))} && bloodhound-python "
           f"-u {shlex.quote(user)} {cred} -d {shlex.quote(domain)} "
           f"-ns {shlex.quote(dc_ip)} -c All --zip")
    log_info(f"bloodhound-python -u {user} {cred_disp} -d {domain} -ns {dc_ip} -c All --zip")
    out, err, rc = run(cmd, timeout=600)
    if rc == 0:
        log_ok(f"BloodHound collecté → {bh_dir}/")
    else:
        log_warn(f"bloodhound-python rc={rc}: {(err or out).strip()[:300]}")
    if out.strip():
        write_file(bh_dir / "bloodhound_run.log", out)


# ---------------------------------------------------------------------------
# Résumé
# ---------------------------------------------------------------------------

def write_summary(outdir: Path, hosts, dc_targets, vulnerable_nb, signing,
                  auth: dict, has_creds: bool):
    def n(key):
        v = auth.get(key, [])
        return v if isinstance(v, int) else len(v)

    lines = [
        RULE,
        "LDAP / AD Enumeration Summary",
        f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        RULE,
        f"Targets scanned           : {len(hosts)}",
        f"DC répondant au rootDSE    : {len(dc_targets)}",
        f"[CRITICAL] Null bind       : {len(vulnerable_nb)}",
        f"[CRITICAL] Signing/CB faible: {len(signing)}",
    ]
    if vulnerable_nb:
        lines.append("  Null-bind hosts:")
        lines += [f"    [CRITICAL] {ip}" for ip in sorted(vulnerable_nb)]

    lines += ["", f"Authenticated checks run : {'YES' if has_creds else 'NO'}"]
    if has_creds:
        lines += [
            f"  Users                    : {n('users')}",
            f"  Groups                   : {n('ldap_groups.txt')}",
            f"  PASSWD_NOTREQD           : {n('ldap_no_preauth.txt')}",
            f"  [CRITICAL] Unconstr. deleg: {n('ldap_delegation.txt')}",
            f"  adminCount=1             : {n('ldap_admin_count.txt')}",
            f"  User descriptions        : {n('ldap_descriptions.txt')}",
            f"  [CRITICAL] LAPS readable : {n('ldap_laps.txt')}",
            f"  [CRITICAL] gMSA readable : {n('ldap_gmsa.txt')}",
            f"  ADCS entries             : {n('ldap_adcs.txt')}",
            f"  [CRITICAL] AS-REP hashes : {n('ldap_asrep_hashes.txt')}",
            f"  [CRITICAL] Kerb. hashes  : {n('ldap_kerberoast_hashes.txt')}",
        ]
    lines.append(RULE)

    summary = "\n".join(lines) + "\n"
    write_file(outdir / "ldap_summary.txt", summary)
    print("\n" + summary)


# ---------------------------------------------------------------------------
# Args & main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="check_ldap.py — LDAP / Active Directory checks (pentest interne)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s -t hosts_ldap.txt
  %(prog)s -t 192.168.1.10 -u admin -p 'Password1' -d corp.local
  %(prog)s -t 10.0.0.0/24 -u svc -H aad3b435b51404eeaad3b435b51404ee:abc123 -d lab.local
  %(prog)s -t hosts_ldap.txt -u svc -p 'Pass' -d corp.local --bloodhound
""")
    p.add_argument("-t", "--target", required=True,
                   help="Cible : fichier de hosts, IP, ou CIDR")
    p.add_argument("-o", "--output", default=None,
                   help="Répertoire de sortie (défaut: ldap_results_<timestamp>)")
    p.add_argument("-u", "--username", default=None, help="Utilisateur")
    p.add_argument("-p", "--password", default=None, help="Mot de passe")
    p.add_argument("-H", "--hash", default=None, help="Hash NTLM LM:NT")
    p.add_argument("-d", "--domain", default=None, help="Domaine FQDN")
    p.add_argument("--threads", type=int, default=50,
                   help="Concurrence nxc (--threads, défaut 50)")
    p.add_argument("--bloodhound", action="store_true",
                   help="Lance la collecte BloodHound (bloodhound-python -c All) "
                        "sur UN seul DC. Désactivé par défaut.")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Non-interactif : accepte toutes les étapes (automatisation/UI)")
    return p.parse_args()


def main():
    global _THREADS
    args = parse_args()
    if getattr(args, "yes", False):
        enable_auto_accept()
    _THREADS = max(1, args.threads)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output) if args.output else Path(f"ldap_results_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    log_ok(f"Output directory: {outdir.resolve()}")

    hosts = parse_targets(args.target)
    if not hosts:
        log_warn("No targets to process. Exiting.")
        sys.exit(0)
    log_info(f"Loaded {len(hosts)} target(s)")

    if not tool_exists("ldapsearch"):
        log_err("ldapsearch introuvable. Installe ldap-utils (apt install ldap-utils).")
        sys.exit(1)

    # '' est un mot de passe valide en AD (comptes PASSWD_NOTREQD) : tester
    # `is not None` et pas la vérité pour ne pas sauter les étapes 4-5 sur -p ''.
    has_creds = bool(args.username and (args.password is not None or args.hash))

    # ---- STEP 1 : rootDSE ----
    host_map = step_rootdse(hosts, outdir)

    # DC réels = ceux qui répondent au rootDSE ; sinon repli sur toutes les cibles
    # (rootDSE anonyme peut être coupé alors que le bind authentifié marche).
    dc_targets = list(host_map) or hosts

    # Domaine auto-détecté depuis le rootDSE si absent.
    domain = args.domain
    if not domain and host_map:
        for base_dn in host_map.values():
            parts = re.findall(r'DC=([^,]+)', base_dn, re.IGNORECASE)
            if parts:
                domain = ".".join(parts)
                log_info(f"Domaine auto-détecté : {domain}")
                break

    creds_real, creds_disp = ("", "")
    if has_creds:
        creds_real, creds_disp = build_creds(args.username, args.password, args.hash, domain)

    # ---- STEP 2 : LDAP signing & channel binding ----
    signing = step_ldap_signing(dc_targets, creds_real, creds_disp, outdir)

    # ---- STEP 3 : Null bind + dump anonyme ----
    vulnerable_nb = step_nullbind(host_map, outdir)

    # ---- STEP 4 : énumération authentifiée ----
    auth: dict = {}
    if has_creds:
        if not tool_exists("nxc"):
            log_warn("nxc introuvable — énumération authentifiée ignorée.")
        elif not domain:
            log_warn("Domaine inconnu (ni -d ni rootDSE) — énumération authentifiée ignorée.")
        else:
            auth = step_auth_enum(dc_targets, creds_real, creds_disp, outdir)
    else:
        log_info("Pas de creds — étapes authentifiées (4-5) ignorées.")

    # ---- STEP 5 : BloodHound (opt-in via --bloodhound, sur UN seul DC) ----
    if args.bloodhound:
        if not has_creds:
            log_warn("--bloodhound demandé mais aucun identifiant fourni — ignoré.")
        elif not domain:
            log_warn("--bloodhound demandé mais domaine inconnu (ni -d ni rootDSE) — ignoré.")
        elif not tool_exists("bloodhound-python"):
            log_warn("--bloodhound demandé mais bloodhound-python non installé — ignoré.")
        else:
            # bloodhound-python collecte TOUT le domaine via un seul DC (-ns) :
            # inutile (et absurde) de le relancer par hôte. On prend le 1er DC.
            step_bloodhound(args.username, args.password, args.hash, domain,
                            outdir, dc_targets[0])
    elif has_creds and domain and tool_exists("bloodhound-python"):
        log_info("BloodHound non lancé (ajoute --bloodhound pour la collecte).")

    write_summary(outdir, hosts, dc_targets, vulnerable_nb, signing, auth, has_creds)


if __name__ == "__main__":
    main()
