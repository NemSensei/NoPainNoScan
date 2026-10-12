#!/usr/bin/env python3
"""check_dc.py — Checks spécifiques Domain Controller (SYSVOL / NETLOGON).

À lancer sur les DC avec des identifiants de domaine (SYSVOL/NETLOGON exigent
une lecture authentifiée — n'importe quel compte du domaine suffit).

  STEP 1  GPP credentials (SYSVOL) — nxc -M gpp_password / gpp_autologin.
          cpassword GPP (MS14-025) déchiffrés + autologon (Registry.xml).  [creds]
  STEP 2  Contenu SYSVOL/NETLOGON — télécharge les deux partages (smbclient -Tc)
          et analyse localement, critères adPEAS/Snaffler : extensions ciblées +
          motifs Tier 1 (secret 🔴) / Tier 2 (indice ⚠️) + exclusions ; détecte
          aussi les fichiers sensibles (clés, KeePass, unattend/sysprep, .rdp) et
          l'accès WRITE à SYSVOL/NETLOGON (GPO abuse, via nxc --shares).   [creds]
  STEP 3  Vulnérabilités DC (nxc) — zerologon, noPac, SMBGhost, PrintNightmare,
          Spooler, coercion (PetitPotam/…). Mode CHECK only.    [marche sans creds]
  STEP 4  ADCS (optionnel --adcs) — certipy find -vulnerable (ESC1-16).     [creds]

Pensé « gros scope » : GPP/vulns via nxc (sweep multi-hôtes) ; le téléchargement
SYSVOL/NETLOGON ne se fait que sur UN DC (partages répliqués, identiques sur tous
les DC) — inutile de tout re-télécharger par hôte.
"""

import argparse
import ipaddress
import os
import re
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, confirm_step, set_total_steps, enable_auto_accept,
                         emit_progress, strip_ansi)

set_total_steps(4)

_THREADS = 50


# ---------------------------------------------------------------------------
# Exécution
# ---------------------------------------------------------------------------

def run(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1
    except Exception as e:                       # noqa: BLE001
        return "", str(e), 1


def run_nxc(cmd, timeout):
    """nxc en gardant la sortie partielle sur timeout (killpg). (stdout, rc)."""
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


def scaled_timeout(n_hosts, base=120, per_host=5, cap=1800):
    return min(base + per_host * max(0, n_hosts), cap)


def write_lines(path: Path, items, sort=False):
    cleaned = [i.strip() for i in items if i and i.strip()]
    cleaned = sorted(set(cleaned)) if sort else list(dict.fromkeys(cleaned))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(cleaned) + ("\n" if cleaned else ""))
    return cleaned


def load_hosts(target):
    p = Path(target)
    if p.exists() and p.is_file():
        return [l.strip() for l in p.read_text().splitlines()
                if l.strip() and not l.startswith('#')]
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [target]


def hosts_to_tmpfile(hosts):
    tf = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    tf.write("\n".join(hosts) + "\n")
    tf.close()
    return tf.name


# ---------------------------------------------------------------------------
# Identifiants (nxc + smbclient), avec version redacted
# ---------------------------------------------------------------------------

def nxc_creds(user, password, nt_hash, domain):
    parts, disp = [], []
    parts.append(f"-u {shlex.quote(user)}"); disp.append(f"-u {shlex.quote(user)}")
    if nt_hash:
        parts.append(f"-H {shlex.quote(nt_hash)}"); disp.append("-H '***'")
    else:
        parts.append(f"-p {shlex.quote(password or '')}"); disp.append("-p '***'")
    if domain:
        parts.append(f"-d {shlex.quote(domain)}"); disp.append(f"-d {shlex.quote(domain)}")
    return " ".join(parts), " ".join(disp)


def smbclient_auth(user, password, nt_hash, domain):
    """(userarg_quoté, extra_flags, display). Supporte le pass-the-hash.

    smbclient attend `DOMAIN\\user%secret` ; en PtH le secret = partie NT du hash
    LM:NT avec --pw-nt-hash."""
    prefix = f"{domain}\\" if domain else ""
    if nt_hash:
        secret = nt_hash.split(':')[-1]          # partie NT
        extra = "--pw-nt-hash"
        disp_secret = "<NT-hash>"
    else:
        secret = password or ""
        extra = ""
        disp_secret = "***"
    userarg = shlex.quote(f"{prefix}{user}%{secret}")
    display = f"{prefix}{user}%{disp_secret}"
    return userarg, extra, display


# ===========================================================================
# STEP 1 — GPP credentials (SYSVOL)   [migré depuis check_smb]
# ===========================================================================
# Lignes à retenir dans la sortie des modules GPP : les marqueurs de PAYOFF d'un
# vrai secret — cpassword déchiffré, autologon, "Found credentials in …", et les
# lignes de résultat "Usernames:" / "Passwords:". Motifs précis (avec ':' ou
# "in ") plutôt que les mots génériques seuls, pour ne pas ramasser la ligne
# d'auth nxc ("[+] CORP\\svc:xxx STATUS_…") ni jeter les vrais payoffs.
_GPP_FINDING_RE = re.compile(
    r"(?i)(cpassword|autologin|credentials?\s+in\b|usernames?\s*:|passwords?\s*:)"
)
_GPP_NEGATIVE_RE = re.compile(
    r"(?i)(no (gpp|autologin|credential|password|result|xml|file)"
    r"|not found|nothing found|could ?n'?t|could not|failed to"
    r"|STATUS_[A-Z_]+)"
)


def step_gpp(hosts_file, out_dir, creds_real, creds_disp, n_hosts):
    log_step("STEP 1 — GPP credentials (SYSVOL)")
    findings = []
    if not tool_exists("nxc"):
        log_warn("nxc introuvable — GPP ignoré.")
        write_lines(out_dir / "dc_gpp.txt", [])
        return findings
    if not confirm_step("STEP 1 — GPP credentials (SYSVOL)",
                        "nxc smb <dc> <creds> -M gpp_password  +  -M gpp_autologin"):
        write_lines(out_dir / "dc_gpp.txt", [])
        return findings

    raw_parts = []
    for module in ("gpp_password", "gpp_autologin"):
        log_info(f"nxc smb <dc> {creds_disp} -M {module}")
        out, _ = run_nxc(f"nxc smb {shlex.quote(str(hosts_file))} {creds_real} "
                         f"--threads {_THREADS} -M {module}",
                         timeout=scaled_timeout(n_hosts))
        out = strip_ansi(out)
        raw_parts.append(f"# === {module} ===\n{out}")
        for line in out.splitlines():
            if _GPP_FINDING_RE.search(line) and not _GPP_NEGATIVE_RE.search(line):
                findings.append(line.strip())

    (out_dir / "dc_gpp_raw.txt").write_text("\n".join(raw_parts) + "\n")
    findings = write_lines(out_dir / "dc_gpp.txt", findings)
    if findings:
        log_warn(f"[CRITICAL] {len(findings)} secret(s) GPP dans SYSVOL !")
    else:
        log_info("Aucun secret GPP (voir dc_gpp_raw.txt pour la sortie brute).")
    return findings


# ===========================================================================
# STEP 2 — Fichiers intéressants SYSVOL / NETLOGON
# ===========================================================================
# Critères inspirés d'adPEAS / Snaffler. On ne regarde que des extensions de
# scripts/config (les .xml GPP sont couverts par STEP 1). Deux niveaux :
#   Tier 1 (🔴) : motif à forte confiance avec valeur exploitable.
#   Tier 2 (⚠️) : mention plus faible → revue manuelle.
# Les exclusions écartent la doc de politique de mot de passe, les commentaires,
# les prompts, les valeurs masquées — source classique de faux positifs.
SCRIPT_EXTS = {'.txt', '.bat', '.ini', '.conf', '.cnf', '.cmd',
               '.vbs', '.kix', '.ps1', '.psm1'}

# Fichiers SENSIBLES détectés par nom/extension : leur simple présence dans
# SYSVOL/NETLOGON est un finding (à récupérer et inspecter à la main — binaires
# ou formats structurés qu'on ne scanne pas ligne à ligne).
SENSITIVE_EXTS = {'.pfx', '.p12', '.pem', '.cer', '.kdbx', '.ppk', '.rdp'}
SENSITIVE_NAMES = {'id_rsa', 'id_dsa', 'id_ecdsa',
                   'unattend.xml', 'autounattend.xml', 'sysprep.inf', 'sysprep.xml'}

_NET_USE = (r"net use (?:\w|\*|LPT\d):? \\\\?\S+"
            r"(?:.*?(?:/user:\S+|\s(?!/)\S+|/savecred))+")

TIER1 = [(re.compile(p, re.I), d) for p, d in [
    (r'passw(or)?d\s*[=:]\s*["\'][^"\']{3,}["\']', "Password assignment (quoted)"),
    (r'passw(or)?d\s*[=:]\s*(?!["\'])\S{3,}',      "Password assignment (unquoted)"),
    (r'[-/]passw(or)?d\s+\S{3,}',                  "Password parameter"),
    (r'psexec.{0,100}\s-p\s+\S+',                  "PSExec with password"),
    (r'schtasks.{0,300}/rp\s+\S+',                 "Schtasks with password"),
    (r'net\s+user\s+\S+\s+\S+\s+/add',             "Net user creation"),
    (r'cmdkey\s+/add:\S+.*?/pass:\S+',             "Cmdkey with password"),
    (r'connectionstring.{1,200}passw',             "DB connection string"),
    (r'ConvertTo-SecureString\s+["\'][^"\']+["\']', "SecureString conversion"),
    (r'api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']', "API key assignment"),
    (r'\$cred(ential)?\s*=.*password',             "Credential variable"),
    (_NET_USE,                                     "net use with password"),
]]
TIER2 = [(re.compile(p, re.I), d) for p, d in [
    (r"<passw[^>]*>[^<]+</passw",       "XML password element"),
    (r"passwd",                         "Passwd mention"),
    (r"passw(or)?d",                    "Password mention"),
    (r"credential",                     "Credential mention"),
    (r"(secret|token)\s*[=:]\s*\S{5,}", "Secret/token assignment"),
]]
EXCLUSIONS = [re.compile(p, re.I) for p in [
    r'passw(or)?d\s*(policy|policies|requirement|guideline)',
    r'passw(or)?d\s+(must|should|cannot|shall)\s+(be|contain|have|include)',
    r'passw(or)?d\s+(length|complexity|history|age|expir)',
    r'passw(or)?d\s+(reset|change|recover|forgot)',
    r'(minimum|maximum)\s+passw(or)?d',
    r'(set|change|update|reset)\s+(your|the|a)\s+passw(or)?d',
    r'^\s*(REM|::|\'|#)\s+.*passw',
    r'echo\s+.*passw(or)?d.*help',
    r'usage:.*passw(or)?d',
    r'passw(or)?d\s*:\s*\*+',
    r'passw(or)?d\s*:\s*<[^>]+>',
    r'Enter\s+(your\s+)?passw(or)?d',
    r'passw(or)?d\s+prompt',
]]


def scan_text(text, label, findings, hints, max_per_file=10):
    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(x.search(line) for x in EXCLUSIONS):
            continue
        snip = (line[:140] + '…') if len(line) > 140 else line
        hit = next((d for pat, d in TIER1 if pat.search(line)), None)
        if hit:
            findings.append(f"[{label}] ({hit}) {snip}")
            count += 1
        else:
            hit = next((d for pat, d in TIER2 if pat.search(line)), None)
            if hit:
                hints.append(f"[{label}] ({hit}) {snip}")
                count += 1
        if count >= max_per_file:
            break


def download_share_tar(host, share, userarg, extra, tmpdir):
    """Télécharge un partage entier en tar via smbclient. Retourne le chemin ou None.

    Forme canonique `-Tc <tar>` (flag ligne de commande) : `tar` récurse de
    lui-même, pas besoin de `tarmode/recurse/prompt` (dont la syntaxe varie selon
    la version de Samba et pourrait casser la chaîne `-c`)."""
    tarpath = Path(tmpdir) / f"{share}.tar"
    cmd = (f"smbclient //{shlex.quote(host)}/{share} -U {userarg} {extra} "
           f"-Tc {shlex.quote(str(tarpath))}")
    out, err, rc = run(cmd, timeout=600)
    if tarpath.exists() and tarpath.stat().st_size > 0:
        return tarpath
    log_warn(f"{host}/{share} — téléchargement échoué: {(err or out).strip()[:200]}")
    return None


def analyze_tar(tarpath, share, findings, hints, inventory, sensitive):
    """Parcourt le tar EN MÉMOIRE (pas d'extraction disque — archive non fiable).

    - extensions scripts/config → scan de contenu (Tier1/Tier2) ;
    - fichiers sensibles (clés, KeePass, unattend/sysprep, .rdp) → finding de
      présence (pas de scan ligne à ligne, souvent binaire)."""
    try:
        tf = tarfile.open(tarpath)
    except (tarfile.TarError, OSError) as e:
        log_warn(f"tar illisible ({share}): {e}")
        return
    with tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            name = m.name.replace('\\', '/').lstrip('./')
            base = name.rsplit('/', 1)[-1].lower()
            ext = os.path.splitext(name)[1].lower()

            if ext in SENSITIVE_EXTS or base in SENSITIVE_NAMES:
                kind = base if base in SENSITIVE_NAMES else ext
                sensitive.append(f"[{share}] {name} ({kind})")
                continue
            if ext not in SCRIPT_EXTS:
                continue
            inventory.append(f"[{share}] {name}")
            try:
                fh = tf.extractfile(m)
                data = fh.read() if fh else b""
            except (tarfile.TarError, OSError):
                continue
            scan_text(data.decode('utf-8', 'replace'), f"{share}/{name}",
                      findings, hints)


# SYSVOL/NETLOGON inscriptibles (écriture = GPO abuse → RCE). On lit la permission
# au niveau partage via `nxc --shares` (NON intrusif : aucune écriture tentée). Les
# ACL d'un GPO précis se vérifient à la main / via BloodHound.
def check_writable_sysvol(hosts_file, creds_real, n_hosts):
    """Retourne les lignes SYSVOL/NETLOGON montrant un accès WRITE (via nxc --shares)."""
    if not tool_exists("nxc"):
        return []
    out, _ = run_nxc(f"nxc smb {shlex.quote(str(hosts_file))} {creds_real} "
                     f"--threads {_THREADS} --shares", timeout=scaled_timeout(n_hosts))
    writable = []
    for line in strip_ansi(out).splitlines():
        # garde uniquement SYSVOL/NETLOGON avec WRITE (le regex share générique ailleurs)
        if re.search(r"\b(SYSVOL|NETLOGON)\b", line, re.I) and re.search(r"\bWRITE\b", line):
            writable.append(line.strip())
    return writable


def step_interesting_files(hosts, hosts_file, out_dir, user, password, nt_hash,
                           domain, creds_real):
    log_step("STEP 2 — SYSVOL / NETLOGON content (files, sensitive, writable)")
    findings, hints, inventory, sensitive, writable = [], [], [], [], []
    outs = ("dc_sysvol_creds.txt", "dc_sysvol_hints.txt", "dc_sysvol_files.txt",
            "dc_sysvol_sensitive.txt", "dc_sysvol_writable.txt")

    if not tool_exists("smbclient"):
        log_warn("smbclient introuvable (apt install smbclient) — étape ignorée.")
        for f in outs:
            write_lines(out_dir / f, [])
        return findings, hints, inventory, sensitive, writable

    userarg, extra, disp = smbclient_auth(user, password, nt_hash, domain)
    if not confirm_step("STEP 2 — SYSVOL/NETLOGON content",
                        f"smbclient //<dc>/SYSVOL -U {disp} -Tc <tar>  (+ NETLOGON, 1 DC) ; "
                        "nxc --shares (write?)"):
        for f in outs:
            write_lines(out_dir / f, [])
        return findings, hints, inventory, sensitive, writable

    # Permission d'écriture SYSVOL/NETLOGON (non intrusif, sur toutes les cibles).
    log_info("nxc smb <dc> --shares  (recherche WRITE sur SYSVOL/NETLOGON)")
    writable = check_writable_sysvol(hosts_file, creds_real, len(hosts))

    # Les partages sont répliqués → on prend le 1er DC qui répond, pas tous.
    with tempfile.TemporaryDirectory() as tmp:
        done_host = None
        for host in hosts:
            got_any = False
            for share in ("SYSVOL", "NETLOGON"):
                log_info(f"smbclient //{host}/{share} -U {disp} -Tc <tar>")
                tarpath = download_share_tar(host, share, userarg, extra, tmp)
                if tarpath:
                    got_any = True
                    analyze_tar(tarpath, share, findings, hints, inventory, sensitive)
            if got_any:
                done_host = host
                break
        if not done_host:
            log_warn("Aucun DC n'a renvoyé SYSVOL/NETLOGON (creds ? accès ?).")

    findings   = write_lines(out_dir / "dc_sysvol_creds.txt", findings)
    hints      = write_lines(out_dir / "dc_sysvol_hints.txt", hints)
    inventory  = write_lines(out_dir / "dc_sysvol_files.txt", inventory, sort=True)
    sensitive  = write_lines(out_dir / "dc_sysvol_sensitive.txt", sensitive, sort=True)
    writable   = write_lines(out_dir / "dc_sysvol_writable.txt", writable)
    log_ok(f"Fichiers: {len(inventory)} | Tier1: {len(findings)} | Tier2: {len(hints)} | "
           f"sensibles: {len(sensitive)} | SYSVOL/NETLOGON WRITE: {len(writable)}")
    if findings:
        log_warn(f"[CRITICAL] {len(findings)} secret(s) probable(s) dans les scripts !")
    if writable:
        log_warn(f"[CRITICAL] SYSVOL/NETLOGON inscriptible ({len(writable)}) → GPO abuse !")
    return findings, hints, inventory, sensitive, writable


# ===========================================================================
# STEP 3 — Vulnérabilités DC (nxc modules) — Lot A
# ===========================================================================
# Modules nxc lancés sur les DC. zerologon/smbghost/spooler marchent sans creds ;
# nopac/coerce_plus en profitent si on en a. NB : les NOMS de modules bougent
# selon le build NetExec (coerce_plus récent regroupe PetitPotam/DFSCoerce/
# ShadowCoerce/PrinterBug) — la sortie brute est conservée pour ajuster au besoin.
# On reste en mode CHECK : jamais d'exploitation qui casserait le compte machine.
#   severity "crit" → dc_vulns.txt (🔴) ; "warn" → dc_coercion.txt (⚠️, vecteurs).
DC_VULN_MODULES = [
    ("zerologon",      "Zerologon (CVE-2020-1472)",            "crit"),
    ("nopac",          "noPac (CVE-2021-42278/42287)",         "crit"),
    ("smbghost",       "SMBGhost (CVE-2020-0796)",             "crit"),
    ("printnightmare", "PrintNightmare (CVE-2021-34527)",      "warn"),
    ("spooler",        "Spooler service enabled (coercion)",   "warn"),
    ("coerce_plus",    "Coercion (PetitPotam/DFSCoerce/…)",    "warn"),
]
_VULN_POS = re.compile(r"(VULNERABLE|is enabled|enabled\b|likely vulnerable|"
                       r"path:|coerc|found)", re.I)
_VULN_NEG = re.compile(r"(not vulnerable|non vulnerable|not enabled|disabled|"
                       r"error|traceback)", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def step_dc_vulns(hosts_file, out_dir, creds_real, creds_disp, n_hosts):
    log_step("STEP 3 — DC vulnerabilities (nxc modules)")
    crit, coercion, raw = [], [], []
    if not tool_exists("nxc"):
        log_warn("nxc introuvable — vulns DC ignorées.")
        write_lines(out_dir / "dc_vulns.txt", [])
        write_lines(out_dir / "dc_coercion.txt", [])
        return crit, coercion
    if not confirm_step("STEP 3 — DC vulnerabilities",
                        "nxc smb <dc> -M " + "/".join(m for m, _, _ in DC_VULN_MODULES)):
        write_lines(out_dir / "dc_vulns.txt", [])
        write_lines(out_dir / "dc_coercion.txt", [])
        return crit, coercion

    creds = creds_real or "-u '' -p ''"
    disp  = creds_disp or "-u '' -p ''"
    for module, label, sev in DC_VULN_MODULES:
        log_info(f"nxc smb <dc> {disp} -M {module}")
        out, _ = run_nxc(f"nxc smb {shlex.quote(str(hosts_file))} {creds} "
                         f"--threads {_THREADS} -M {module}",
                         timeout=scaled_timeout(n_hosts))
        out = strip_ansi(out)
        raw.append(f"# === {module} ===\n{out}")
        hits = []
        for line in out.splitlines():
            if _VULN_POS.search(line) and not _VULN_NEG.search(line):
                ip = _IP_RE.search(line)
                hits.append(f"{ip.group(1) if ip else '?'}  [{label}]  {line.strip()[-160:]}")
        hits = list(dict.fromkeys(hits))
        if hits:
            (crit if sev == "crit" else coercion).extend(hits)
            (log_warn if sev == "crit" else log_info)(
                f"  {label}: {len(hits)} hôte(s) concerné(s)"
                + (" [CRITICAL]" if sev == "crit" else ""))
        else:
            log_ok(f"  {label}: non vulnérable / non détecté")

    (out_dir / "dc_vulns_raw.txt").write_text("\n".join(raw) + "\n")
    crit     = write_lines(out_dir / "dc_vulns.txt", crit)
    coercion = write_lines(out_dir / "dc_coercion.txt", coercion)
    return crit, coercion


# ===========================================================================
# STEP 4 — ADCS (optionnel, --adcs) : certipy find -vulnerable
# ===========================================================================

def step_adcs(hosts, out_dir, user, password, nt_hash, domain):
    log_step("STEP 4 — ADCS vulnerable templates (certipy)")
    findings = []
    if not tool_exists("certipy") and not tool_exists("certipy-ad"):
        log_warn("certipy introuvable (pip install certipy-ad) — --adcs ignoré.")
        write_lines(out_dir / "dc_adcs_vulnerable.txt", [])
        return findings
    if not domain:
        log_warn("--adcs nécessite un domaine (-d) — ignoré.")
        write_lines(out_dir / "dc_adcs_vulnerable.txt", [])
        return findings

    cbin = "certipy" if tool_exists("certipy") else "certipy-ad"
    dc = hosts[0]
    if nt_hash:
        auth = f"-hashes {shlex.quote(nt_hash)}"
        disp = "-hashes '***'"
    else:
        auth = f"-p {shlex.quote(password or '')}"
        disp = "-p '***'"
    upn = f"{user}@{domain}"
    if not confirm_step("STEP 4 — ADCS (certipy find -vulnerable)",
                        f"certipy find -u {upn} {disp} -dc-ip {dc} -vulnerable -stdout"):
        write_lines(out_dir / "dc_adcs_vulnerable.txt", [])
        return findings

    log_info(f"{cbin} find -u {upn} {disp} -dc-ip {dc} -vulnerable -stdout")
    out, err, _ = run(f"{cbin} find -u {shlex.quote(upn)} {auth} "
                      f"-dc-ip {shlex.quote(dc)} -vulnerable -stdout 2>&1", timeout=300)
    (out_dir / "dc_adcs_raw.txt").write_text(out or err)
    for line in strip_ansi(out).splitlines():
        if re.search(r"\bESC\d+\b", line) or re.search(r"(?i)vulnerab", line):
            findings.append(line.strip())
    findings = write_lines(out_dir / "dc_adcs_vulnerable.txt", findings)
    if findings:
        log_warn(f"[CRITICAL] ADCS: {len(findings)} ligne(s) de vulnérabilité (ESCx) "
                 f"→ dc_adcs_vulnerable.txt")
    else:
        log_ok("ADCS: aucune template vulnérable détectée (voir dc_adcs_raw.txt).")
    return findings


# ---------------------------------------------------------------------------
# Résumé
# ---------------------------------------------------------------------------

def write_summary(out_dir, hosts, gpp, creds, hints, inventory, sensitive,
                  writable, vulns, coercion, adcs):
    lines = [
        RULE,
        "Domain Controller Summary",
        f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        RULE,
        f"Targets                          : {len(hosts)}",
        f"[CRITICAL] DC vulns (zerologon…)  : {len(vulns)}",
        f"[CRITICAL] GPP secrets (SYSVOL)   : {len(gpp)}",
        f"[CRITICAL] Script creds (Tier1)   : {len(creds)}",
        f"[CRITICAL] SYSVOL/NETLOGON WRITE  : {len(writable)}",
        f"[CRITICAL] ADCS vulnerable lines  : {len(adcs)}",
        f"[WARN]     Coercion vectors       : {len(coercion)}",
        f"[WARN]     Sensitive files        : {len(sensitive)}",
        f"[WARN]     Hints (Tier2)          : {len(hints)}",
        f"Files reviewed                   : {len(inventory)}",
    ]
    for title, items in [("DC VULNS", vulns), ("GPP", gpp),
                         ("SYSVOL/NETLOGON script credentials", creds),
                         ("SYSVOL/NETLOGON WRITABLE", writable),
                         ("ADCS", adcs)]:
        if items:
            lines += ["", f"[CRITICAL] {title}:"] + [f"    {i}" for i in items[:20]]
    lines.append(RULE)
    summary = "\n".join(lines) + "\n"
    (out_dir / "dc_summary.txt").write_text(summary)
    print("\n" + summary)


# ---------------------------------------------------------------------------
# Args & main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="check_dc.py — Domain Controller checks (GPP + SYSVOL/NETLOGON files)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s -t dc01.corp.local -u jdoe -p 'P@ss' -d corp.local
  %(prog)s -t hosts_dc.txt   -u svc  -H aad3b435b51404eeaad3b435b51404ee:abc -d corp.local
  %(prog)s -t 10.0.0.10 -u svc -p 'P@ss' -d corp.local --adcs
  %(prog)s -t 10.0.0.10            # sans creds : seules les vulns DC (zerologon…) tournent
""")
    p.add_argument("-t", "--target", required=True,
                   help="Cible : fichier de hosts (DC), IP, ou CIDR")
    p.add_argument("-o", "--output", default=None,
                   help="Répertoire de sortie (défaut: dc_results_<timestamp>)")
    p.add_argument("-u", "--username", default=None, help="Utilisateur")
    p.add_argument("-p", "--password", default=None, help="Mot de passe")
    p.add_argument("-H", "--hash", default=None, help="Hash NTLM LM:NT (pass-the-hash)")
    p.add_argument("-d", "--domain", default=None, help="Domaine FQDN")
    p.add_argument("--adcs", action="store_true",
                   help="Énumère les templates ADCS vulnérables (certipy find -vulnerable). "
                        "Désactivé par défaut.")
    p.add_argument("--threads", type=int, default=50,
                   help="Concurrence nxc (--threads, défaut 50)")
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
    out_dir = Path(args.output) if args.output else Path(f"dc_results_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Output directory: {out_dir.resolve()}")

    hosts = load_hosts(args.target)
    if not hosts:
        log_warn("No hosts loaded — exiting.")
        sys.exit(0)
    log_info(f"Loaded {len(hosts)} target(s)")

    # Les étapes SYSVOL/GPP/ADCS exigent des creds (lecture authentifiée) ; les
    # vulns DC (STEP 3 : zerologon/smbghost/spooler…) tournent même sans creds.
    has_creds = bool(args.username and (args.password is not None or args.hash))
    creds_real, creds_disp = ("", "")
    if has_creds:
        creds_real, creds_disp = nxc_creds(args.username, args.password, args.hash, args.domain)
    else:
        log_warn("Aucun identifiant (-u + -p/-H) : SYSVOL/GPP/ADCS sautés ; "
                 "seules les vulns DC (STEP 3) tournent.")

    hosts_tmp = hosts_to_tmpfile(hosts)
    gpp, creds, hints, inventory, sensitive, writable, adcs = [], [], [], [], [], [], []

    # ---- STEP 1 : GPP ----
    if has_creds:
        gpp = step_gpp(hosts_tmp, out_dir, creds_real, creds_disp, len(hosts))
    else:
        write_lines(out_dir / "dc_gpp.txt", [])

    # ---- STEP 2 : SYSVOL/NETLOGON content ----
    if has_creds:
        creds, hints, inventory, sensitive, writable = step_interesting_files(
            hosts, hosts_tmp, out_dir, args.username, args.password, args.hash,
            args.domain, creds_real)
    else:
        for f in ("dc_sysvol_creds.txt", "dc_sysvol_hints.txt", "dc_sysvol_files.txt",
                  "dc_sysvol_sensitive.txt", "dc_sysvol_writable.txt"):
            write_lines(out_dir / f, [])

    # ---- STEP 3 : vulns DC (avec ou sans creds) ----
    vulns, coercion = step_dc_vulns(hosts_tmp, out_dir, creds_real, creds_disp, len(hosts))

    # ---- STEP 4 : ADCS (opt-in --adcs) ----
    if args.adcs:
        if not has_creds:
            log_warn("--adcs nécessite des creds — ignoré.")
            write_lines(out_dir / "dc_adcs_vulnerable.txt", [])
        else:
            adcs = step_adcs(hosts, out_dir, args.username, args.password,
                             args.hash, args.domain)

    try:
        os.unlink(hosts_tmp)
    except OSError:
        pass

    write_summary(out_dir, hosts, gpp, creds, hints, inventory, sensitive,
                  writable, vulns, coercion, adcs)
    log_ok(f"Done. Results in: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
