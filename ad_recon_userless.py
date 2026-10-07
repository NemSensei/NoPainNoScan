#!/usr/bin/env python3
"""
AD Recon Userless — Phase 1: Host Discovery + Port Scan
Usage: sudo python3 ad_recon_userless.py -t 192.168.1.0/24
       sudo python3 ad_recon_userless.py -t targets.txt

Workflow:
    1. fping      — ICMP sweep (hosts alive)
    2. nmap       — TCP SYN ping sur ports AD/internes courants (hosts bloquant ICMP)
    3. masscan    — port scan rapide (ports AD + services communs + UDP SNMP/IPMI)

Input:
    -t peut être :
      • un CIDR     : 192.168.1.0/24
      • une IP      : 10.0.0.5
      • un fichier  : targets.txt  (un CIDR/IP/plage par ligne, # pour commentaires)
    Les lignes invalides du fichier sont ignorées avec un avertissement.

Reprise / incrémental (façon feroxbuster):
    L'outil est relançable sur le même dossier de sortie. Il ACCUMULE les
    résultats : l'état est persisté dans state.json, et à chaque relance il ne
    (re)découvre que les NOUVEAUX subnets et ne port-scanne que les hôtes jamais
    scannés ; hosts_alive / ports sont fusionnés avec l'existant. Une exécution
    interrompue (Ctrl-C) ou un masscan tronqué reprend proprement au run suivant.
    --fresh efface l'état précédent et rescanne tout.
    Le dossier de sortie est stable par source (nom du fichier de cibles, ou CIDR).

Output files:
    targets.txt           cibles scannées (copie, si multi-cibles)
    hosts_alive.txt       tous les hosts répondants (ICMP/TCP)
    hosts_dc.txt          DCs potentiels (Kerberos 88/464 + LDAP 389/3268)
    hosts_smb.txt         SMB (445/139)
    hosts_ldap.txt        LDAP/LDAPS (389,636,3268,3269)
    hosts_rdp.txt         RDP (3389)
    hosts_winrm.txt       WinRM (5985,5986)
    hosts_ssh.txt         SSH (22)
    hosts_http.txt        Web (80,443,8080,8443,8000)
    hosts_mssql.txt       MSSQL (1433)
    hosts_dns.txt         DNS (53)
    hosts_kerberos.txt    Kerberos (88,464)
    hosts_ftp.txt         FTP (21)
    hosts_snmp.txt        SNMP UDP (161)
    hosts_ipmi.txt        IPMI UDP (623)
    masscan_raw.json      résultats bruts masscan
    port_<PORT>.txt       IPs ayant ce port ouvert
    hosts_detail/<IP>.txt ports ouverts par host
    ports_summary.json    {IP: [ports]} toutes IPs (accumulé entre runs)
    summary.txt           synthèse lisible
    state.json            état de reprise (subnets/hôtes déjà traités)
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                         tool_exists, emit_progress)


# =============================================================================
# UTILITAIRES
# =============================================================================
def run(cmd, timeout=600):
    """Exécute une commande shell, retourne (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1


def check_root():
    if os.geteuid() != 0:
        log_warn("Non root — masscan et nmap SYN ping nécessitent les privilèges root")
        log_warn("Relancer avec sudo pour des résultats complets")


_RANGE_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}(\.\d{1,3}){0,3}$')


def is_valid_target(token):
    """True si token est une IP, un CIDR, ou une plage nmap/masscan (a.b.c.d-e[.f.g.h])."""
    try:
        ipaddress.ip_network(token, strict=False)  # couvre IP seule et CIDR
        return True
    except ValueError:
        pass
    return bool(_RANGE_RE.match(token))


def parse_targets(target_arg):
    """
    Retourne la liste des cibles (dédupliquées, ordre préservé) depuis un CIDR/IP
    ou un fichier. Le fichier accepte : CIDRs, IPs, plages (10.0.0.1-50), commentaires #.
    Les lignes invalides sont ignorées avec un avertissement.
    """
    p = Path(target_arg)
    if p.is_file():
        targets, invalid, seen = [], [], set()
        for line in p.read_text().splitlines():
            tok = line.split("#")[0].strip()
            if not tok:
                continue
            if not is_valid_target(tok):
                invalid.append(tok)
                continue
            if tok not in seen:
                seen.add(tok)
                targets.append(tok)
        for tok in invalid:
            log_warn(f"Ligne invalide ignorée dans {target_arg}: {tok!r}")
        if not targets:
            log_err(f"Fichier {target_arg} : aucune cible valide")
            sys.exit(1)
        log_ok(f"{len(targets)} cible(s) valide(s) depuis {target_arg}"
               + (f" ({len(invalid)} ignorée(s))" if invalid else ""))
        return targets
    # Argument direct (IP / CIDR / plage)
    if not is_valid_target(target_arg):
        log_err(f"Cible invalide: {target_arg!r} (attendu IP, CIDR ou plage a.b.c.d-e)")
        sys.exit(1)
    return [target_arg]


def setup_output_multi(base_dir, target_arg, targets):
    """Répertoire de sortie STABLE par source d'entrée (indispensable pour la
    reprise/incrémental) : nom du fichier de cibles si c'en est un, sinon le CIDR/IP.
    Ne dépend PAS du nombre de cibles (sinon ajouter un subnet changerait de dossier)."""
    if Path(target_arg).is_file():
        safe = Path(target_arg).stem.replace(" ", "_") or "targets"
    else:
        safe = target_arg.replace("/", "_")
    path = Path(base_dir) / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def sort_ips(ips):
    """Trie une liste d'IPs numériquement, écarte les entrées invalides."""
    valid = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            pass
    return sorted(valid, key=lambda ip: ipaddress.ip_address(ip))


def write_list(path, items):
    """Écrit une liste d'IPs triées dans un fichier."""
    sorted_items = sort_ips(list(set(items)))
    with open(path, "w") as f:
        f.write("\n".join(sorted_items) + ("\n" if sorted_items else ""))


def atomic_write_text(path, text):
    """Écrit `text` dans `path` de façon atomique (tmp + os.replace).

    state.json et ports_summary.json sont la source de vérité de la reprise
    incrémentale : une coupure pendant un write_text() direct (kill -9, OOM,
    coupure secteur pendant un long masscan) laisse un JSON tronqué, et le
    run suivant repart alors d'un état/ports vides — réécrivant tous les
    fichiers agrégés avec les seuls résultats du run courant.
    """
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def read_list(path):
    """Lit une liste d'IPs depuis un fichier. Retourne [] si absent."""
    p = Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text().splitlines() if line.strip()]


# =============================================================================
# ETAT / REPRISE — merge incrémental + resume (façon feroxbuster)
# =============================================================================
STATE_FILE = "state.json"


def _default_state():
    return {
        "version": 1, "created": None, "updated": None, "rate": None,
        "targets_scanned": [],         # subnets/cibles déjà découverts
        "hosts_scanned": [],           # hôtes déjà port-scannés (AD, masscan terminé)
        "hosts_exotic_scanned": [],    # hôtes déjà scannés sur les ports exotiques
        "last_phase": None,
    }


def load_state(base_path):
    p = Path(base_path) / STATE_FILE
    if not p.exists():
        return _default_state()
    try:
        st = _default_state()
        st.update(json.loads(p.read_text()))
        return st
    except (json.JSONDecodeError, OSError):
        log_warn(f"{STATE_FILE} illisible — repart d'un état vierge")
        return _default_state()


def save_state(base_path, state):
    state["updated"] = datetime.now().isoformat(timespec="seconds")
    if not state.get("created"):
        state["created"] = state["updated"]
    atomic_write_text(
        Path(base_path) / STATE_FILE,
        json.dumps(state, indent=2, sort_keys=True)
    )


def load_prior_ports(base_path):
    """Charge ports_summary.json accumulé → {ip: set(int)} ({} si absent/illisible)."""
    p = Path(base_path) / "ports_summary.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
        return {ip: set(int(x) for x in ports) for ip, ports in data.items()}
    except (json.JSONDecodeError, OSError, ValueError):
        log_warn("ports_summary.json illisible — ports précédents ignorés")
        return {}


def merge_ports(a, b):
    """Union des ports par IP de deux dicts {ip: set(int)}."""
    out = {ip: set(ports) for ip, ports in a.items()}
    for ip, ports in b.items():
        out.setdefault(ip, set()).update(ports)
    return out


def clean_output(base_path):
    """--fresh : supprime les artefacts d'un run précédent pour repartir à zéro."""
    bp = Path(base_path)
    for pat in ("hosts_*.txt", "port_*.txt", "masscan_raw.json", "masscan_exotic.json",
                "nmap_verify.xml", "ports_summary.json", "exotic_services.txt",
                STATE_FILE, "paused.conf", "_scan_list.txt", "_verify_list.txt"):
        for f in bp.glob(pat):
            try:
                f.unlink()
            except OSError:
                pass
    detail = bp / "hosts_detail"
    if detail.is_dir():
        shutil.rmtree(detail, ignore_errors=True)


# =============================================================================
# PORTS CIBLES
# =============================================================================
PORT_CATEGORIES = {
    "ftp":      [21],
    "ssh":      [22],
    "dns":      [53],
    "http":     [80, 8000, 8080],
    "kerberos": [88, 464],
    "rpc":      [135, 593],
    "smb":      [139, 445],
    "ldap":     [389, 3268],
    "https":    [443, 8443],
    "ldaps":    [636, 3269],
    "mssql":    [1433],
    "rdp":      [3389],
    "winrm":    [5985, 5986],
}

# UDP ports scanned separately via masscan -pU:
UDP_PORTS = {
    "snmp": 161,
    "ipmi": 623,
}

ALL_TCP_PORTS = sorted({p for ps in PORT_CATEGORIES.values() for p in ps})

PORT_TO_CAT = {}
for _cat, _ports in PORT_CATEGORIES.items():
    for _p in _ports:
        PORT_TO_CAT[_p] = _cat


# Ports utilisés pour la découverte TCP (SYN ping nmap) — ports AD/internes courants
DISCOVERY_TCP_PORTS = "22,80,88,135,139,389,443,445,3389,5985,5986"


# =============================================================================
# PORTS EXOTIQUES (--exotic) — services internes à forte valeur, hors périmètre AD
# Scannés en enrichissement sur les hôtes déjà découverts (hosts_alive).
# =============================================================================
EXOTIC_TCP_PORTS = {
    # Bases de données
    1521: "Oracle", 3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 5984: "CouchDB", 11211: "Memcached",
    8086: "InfluxDB", 1099: "Java RMI",
    # Web / applicatif sur ports non standard
    3000: "Grafana/Node", 5000: "Flask/UPnP", 5601: "Kibana", 8081: "HTTP-alt",
    8088: "HTTP-alt", 8888: "HTTP-alt", 9000: "SonarQube/PHP-FPM", 9090: "Prometheus/HTTP",
    9443: "HTTPS-alt", 10000: "Webmin", 15672: "RabbitMQ-mgmt",
    # Conteneurs / orchestration
    2375: "Docker", 2376: "Docker-TLS", 2379: "etcd", 6443: "Kubernetes-API",
    10250: "Kubelet",
    # Remote / fichiers / legacy
    23: "Telnet", 111: "rpcbind", 512: "rexec", 513: "rlogin", 514: "rsh",
    873: "rsync", 2049: "NFS", 5900: "VNC", 5901: "VNC", 548: "AFP",
    # Mail
    25: "SMTP", 110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S",
    # Impression
    515: "LPD", 631: "IPP", 9100: "JetDirect",
    # OT / ICS (forte valeur, réseaux industriels)
    102: "Siemens-S7", 502: "Modbus", 44818: "EtherNet/IP", 47808: "BACnet",
    # Divers
    1883: "MQTT", 4786: "Cisco-SmartInstall",
}

EXOTIC_UDP_PORTS = {
    137: "NetBIOS", 69: "TFTP", 500: "IKE/VPN", 1900: "SSDP", 5353: "mDNS",
}

# Libellés lisibles pour la synthèse / exotic_services.txt (exotiques uniquement).
PORT_LABELS = dict(EXOTIC_TCP_PORTS)
PORT_LABELS.update({p: f"{n} (UDP)" for p, n in EXOTIC_UDP_PORTS.items()})


# =============================================================================
# ETAPE 1 — DECOUVERTE DES HOSTS
# =============================================================================
# Découverte parallélisée par chunks de cibles (exhaustif mais rapide sur gros
# scope). Chaque chunk produit 2 tâches indépendantes (fping ICMP + nmap TCP-SYN)
# soumises à un pool unique : peu de cibles -> 1 chunk -> fping ‖ nmap ; beaucoup
# de cibles -> tout se parallélise jusqu'à DISCOVERY_MAX_WORKERS.
DISCOVERY_MAX_WORKERS = 8
DISCOVERY_CHUNK_SIZE = 8


def _chunks(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def _fping_sweep(token):
    """ICMP sweep fping sur UNE cible. `-g` est requis pour expandre un CIDR
    (sans lui, fping prend l'argument pour un nom d'hôte). Un IP seule passe sans -g.
    Retourne les IP vivantes."""
    cmd = (f"fping -a -g -q {token} 2>/dev/null" if "/" in token
           else f"fping -a -q {token} 2>/dev/null")
    out, _, _ = run(cmd, timeout=600)
    return {line.strip() for line in out.splitlines() if line.strip()}


def _nmap_sweep(tokens):
    """TCP SYN ping nmap sur un chunk de cibles. Retourne les IP répondantes."""
    if not tokens:
        return set()
    out, _, _ = run(
        f"nmap -sn -PS{DISCOVERY_TCP_PORTS} -n --max-retries 3 --min-rate 500 "
        f"{' '.join(tokens)} -oG - 2>/dev/null",
        timeout=1200,
    )
    hosts = set()
    for line in out.splitlines():
        if "Status: Up" in line:
            m = re.match(r'^Host:\s+(\S+)', line)
            if m:
                hosts.add(m.group(1))
    return hosts


def discover_hosts(targets):
    """
    Découverte via ICMP (fping) + TCP SYN ping (nmap) sur `targets`, parallélisée
    par chunks de cibles. Fonction pure : n'écrit aucun fichier (main() gère le
    merge/écriture de hosts_alive.txt pour l'accumulation incrémentale).

    fping ne comprend pas les plages a.b.c.d-e : seuls les tokens IP/CIDR lui sont
    passés ; nmap reçoit toutes les cibles (il gère les plages).

    Returns:
        set[str]: IPs vivantes trouvées sur ce run
    """
    log_step("ETAPE 1 — Découverte des hôtes")
    if not targets:
        log_info("Aucun nouveau subnet à découvrir — étape sautée")
        return set()

    have_fping = tool_exists("fping")
    have_nmap = tool_exists("nmap")
    if not have_fping:
        log_warn("fping non installé — skipping ICMP (apt install fping)")
    if not have_nmap:
        log_warn("nmap non installé — TCP port ping désactivé (apt install nmap)")
    if not (have_fping or have_nmap):
        return set()

    fping_tokens = [t for t in targets if not _RANGE_RE.match(t)]  # fping: pas de plages
    nmap_tokens = list(targets)

    # fping : une tâche par cible (le -g ne prend qu'un CIDR à la fois).
    # nmap  : une tâche par chunk (il gère plusieurs cibles d'un coup).
    tasks = []  # (méthode, callable, arg, label)
    if have_fping:
        tasks += [("fping", _fping_sweep, t, t) for t in fping_tokens]
    if have_nmap:
        tasks += [("nmap", _nmap_sweep, ch, f"{len(ch)} cible(s)")
                  for ch in _chunks(nmap_tokens, DISCOVERY_CHUNK_SIZE)]

    total = len(tasks)
    log_info(f"Découverte parallèle : {len(targets)} cible(s), {total} tâche(s), "
             f"{DISCOVERY_MAX_WORKERS} workers max...")

    icmp_hosts, tcp_hosts = set(), set()
    done = 0
    with ThreadPoolExecutor(max_workers=DISCOVERY_MAX_WORKERS) as ex:
        futs = {ex.submit(fn, arg): (method, label) for method, fn, arg, label in tasks}
        for fut in as_completed(futs):
            method, label = futs[fut]
            done += 1
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001
                log_warn(f"  [{done}/{total}] {method} {label}: échec ({e})")
                continue
            if method == "fping":
                icmp_hosts |= res
            else:
                tcp_hosts |= res
            log_info(f"  [{done}/{total}] {method:<5} {label} → {len(res)} hôte(s)")

    hosts = icmp_hosts | tcp_hosts
    if have_fping:
        log_ok(f"fping (ICMP)   : {len(icmp_hosts)} hôte(s)")
    if have_nmap:
        log_ok(f"nmap (TCP-SYN) : {len(tcp_hosts)} hôte(s) (+{len(tcp_hosts - icmp_hosts)} hors ICMP)")
    if not hosts:
        log_warn("Aucun host découvert sur les cibles de ce run")
    else:
        log_ok(f"{len(hosts)} hôte(s) vivant(s) découvert(s) sur ce run")
    return hosts


# =============================================================================
# ETAPE 2 — PORT SCAN (MASSCAN)
# =============================================================================
def parse_masscan_json(filepath):
    """
    Parse le JSON masscan en gérant les formats invalides (trailing commas, etc.).
    Consolide les entrées par IP (masscan crée 1 entrée par port ouvert).

    Returns:
        dict[str, set[int]]: {ip: {port1, port2, ...}}
    """
    content = Path(filepath).read_text().strip()
    if not content or content == '[]':
        return {}

    cleaned = re.sub(r',\s*\]', ']', content)
    cleaned = re.sub(r',\s*$', '', cleaned)

    try:
        entries = json.loads(cleaned)
    except json.JSONDecodeError:
        # JSON tronqué (timeout/interruption) : on récupère ligne par ligne.
        # masscan -oJ écrit un objet par ligne ; une dernière ligne coupée est
        # simplement ignorée au lieu de perdre tout le reste.
        entries = []
        for line in content.splitlines():
            line = line.strip().rstrip(',')
            if not (line.startswith('{') and line.endswith('}')):
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if entries:
            log_warn(f"JSON masscan tronqué — {len(entries)} enregistrement(s) récupéré(s)")

    host_ports = {}
    for entry in entries:
        ip = entry.get("ip", "")
        if not ip:
            continue
        if ip not in host_ports:
            host_ports[ip] = set()
        for port_entry in entry.get("ports", []):
            port = port_entry.get("port")
            if port is not None:
                host_ports[ip].add(int(port))

    return host_ports


def _rewrite_output_files(base_path, host_ports):
    """
    Écrit/réécrit tous les fichiers de sortie catégorisés depuis un dict {ip: set(ports)}.
    Appelé par masscan_scan et après nmap_verify pour rester cohérent.
    """
    categories = {cat: set() for cat in list(PORT_CATEGORIES.keys()) + ["dc"]}
    udp_cat    = {cat: set() for cat in UDP_PORTS}

    for ip, open_ports in host_ports.items():
        for port in open_ports:
            cat = PORT_TO_CAT.get(port)
            if cat:
                categories[cat].add(ip)
        has_kerberos = bool(open_ports & {88, 464})
        has_ldap     = bool(open_ports & {389, 3268})
        if has_kerberos and has_ldap:
            categories["dc"].add(ip)
        for svc, port in UDP_PORTS.items():
            if port in open_ports:
                udp_cat[svc].add(ip)

    categories["http"] = categories["http"] | categories.get("https", set())
    categories["ldap"] = categories["ldap"] | categories.get("ldaps", set())

    output_map = {
        "dc":       "hosts_dc.txt",
        "smb":      "hosts_smb.txt",
        "ldap":     "hosts_ldap.txt",
        "rdp":      "hosts_rdp.txt",
        "winrm":    "hosts_winrm.txt",
        "ssh":      "hosts_ssh.txt",
        "http":     "hosts_http.txt",
        "mssql":    "hosts_mssql.txt",
        "dns":      "hosts_dns.txt",
        "kerberos": "hosts_kerberos.txt",
        "ftp":      "hosts_ftp.txt",
    }
    for cat, filename in output_map.items():
        write_list(base_path / filename, list(categories.get(cat, set())))

    write_list(base_path / "hosts_snmp.txt", list(udp_cat["snmp"]))
    write_list(base_path / "hosts_ipmi.txt", list(udp_cat["ipmi"]))

    port_to_ips: dict[int, list[str]] = {}
    for ip, open_ports in host_ports.items():
        for port in open_ports:
            port_to_ips.setdefault(port, []).append(ip)
    for port, ips in port_to_ips.items():
        write_list(base_path / f"port_{port}.txt", ips)

    detail_dir = base_path / "hosts_detail"
    detail_dir.mkdir(exist_ok=True)
    for ip, open_ports in host_ports.items():
        (detail_dir / f"host_{ip}.txt").write_text(
            "\n".join(str(p) for p in sorted(open_ports)) + "\n"
        )

    ports_summary = {ip: sorted(ports) for ip, ports in host_ports.items()}
    atomic_write_text(
        base_path / "ports_summary.json",
        json.dumps(ports_summary, indent=2, sort_keys=True)
    )

    # Services exotiques (--exotic) : liste dédiée + labels lisibles.
    exotic_ports = set(EXOTIC_TCP_PORTS) | set(EXOTIC_UDP_PORTS)
    exotic_hosts, exotic_lines = set(), []
    for ip, open_ports in host_ports.items():
        for port in sorted(open_ports & exotic_ports):
            exotic_hosts.add(ip)
            exotic_lines.append(f"{ip}\t{port}\t{PORT_LABELS.get(port, '?')}")
    if exotic_lines:
        write_list(base_path / "hosts_exotic.txt", list(exotic_hosts))
        (base_path / "exotic_services.txt").write_text("\n".join(sorted(exotic_lines)) + "\n")

    log_ok(f"Hosts avec ports ouverts : {len(host_ports)}")
    log_ok(f"DC potentiels   : {len(categories['dc'])}")
    log_ok(f"SMB             : {len(categories['smb'])}")
    log_ok(f"LDAP            : {len(categories['ldap'])}")
    log_ok(f"RDP             : {len(categories['rdp'])}")
    log_ok(f"WinRM           : {len(categories['winrm'])}")
    log_ok(f"SSH             : {len(categories['ssh'])}")
    log_ok(f"HTTP/S          : {len(categories['http'])}")
    log_ok(f"MSSQL           : {len(categories['mssql'])}")
    log_ok(f"FTP             : {len(categories['ftp'])}")
    log_ok(f"SNMP (UDP 161)  : {len(udp_cat['snmp'])}")
    log_ok(f"IPMI (UDP 623)  : {len(udp_cat['ipmi'])}")
    if exotic_lines:
        log_ok(f"Exotiques       : {len(exotic_hosts)} hosts, {len(exotic_lines)} service(s) → exotic_services.txt")
    log_ok(f"Ports distincts : {len(port_to_ips)}")


def masscan_scan(base_path, hosts_to_scan, tcp_ports, udp_ports, rate=5000,
                 raw_name="masscan_raw.json", label="AD/services"):
    """
    Scan masscan d'un jeu de ports donné sur les hôtes fournis.
    N'écrit PAS les fichiers catégorisés (c'est main() qui merge puis appelle
    _rewrite_output_files sur l'ensemble accumulé).

    Args:
        tcp_ports: iterable[int] — ports TCP à scanner
        udp_ports: iterable[int] — ports UDP à scanner
        raw_name:  nom du fichier -oJ (distinct par passe pour ne pas s'écraser)
    Returns:
        (dict[str, set[int]], bool): ({ip: {ports}}, scan_terminé_proprement)
        completed=False si masscan absent, aucun hôte, échec ou timeout
        (les hôtes ne sont alors PAS marqués scannés → re-scan au prochain run).
    """
    if not tool_exists("masscan"):
        log_warn("masscan non installé — skipping (apt install masscan)")
        return {}, False

    if not hosts_to_scan:
        log_info(f"Aucun hôte à scanner (masscan {label})")
        return {}, False

    tcp_ports = sorted(set(tcp_ports))
    udp_ports = sorted(set(udp_ports))
    if not tcp_ports and not udp_ports:
        return {}, False

    scan_list   = base_path / "_scan_list.txt"
    write_list(scan_list, list(hosts_to_scan))
    output_file = base_path / raw_name

    parts = []
    if tcp_ports:
        parts.append(",".join(str(p) for p in tcp_ports))
    if udp_ports:
        parts.append(",".join(f"U:{p}" for p in udp_ports))
    ports_arg = ",".join(parts)

    log_info(f"masscan {label}: {len(hosts_to_scan)} hosts × {len(tcp_ports)} TCP + "
             f"{len(udp_ports)} UDP @ {rate} pps (retries=2) — progression masscan ci-dessous :")
    cmd = (f"masscan -iL {scan_list} -p{ports_arg} --rate={rate} "
           f"--retries=2 --wait=3 -oJ {output_file}")
    # On NE capture PAS la sortie : la barre de progression native de masscan
    # (rate / % done, sur stderr) s'affiche en direct. Les résultats vont dans -oJ.
    try:
        code = subprocess.run(cmd, shell=True, timeout=900).returncode
    except subprocess.TimeoutExpired:
        code = -1

    # Récupère tout résultat disponible (même partiel en cas de timeout).
    host_ports = {}
    if output_file.exists() and output_file.stat().st_size > 0:
        host_ports = parse_masscan_json(output_file)

    completed = (code == 0)
    if not completed:
        log_warn(f"masscan interrompu/timeout (code={code}) — hôtes conservés pour re-scan")
    if not host_ports:
        log_warn(f"masscan {label}: aucun port ouvert trouvé")

    return host_ports, completed


# =============================================================================
# ETAPE 3 — VERIFICATION NMAP (optionnel)
# =============================================================================
def nmap_verify(base_path, hosts_to_verify, host_ports_in):
    """
    Second pass nmap SYN sur les hôtes fournis pour compléter masscan.
    Merge les résultats dans host_ports_in et retourne le dict fusionné.

    Typiquement 30-120s sur un /24 avec 50 hosts (ports limités, pas de service detection).
    Returns:
        dict[str, set[int]]: host_ports fusionné masscan + nmap
    """
    log_step("ETAPE 3 — Vérification nmap (double-check)")

    if not tool_exists("nmap"):
        log_warn("nmap non installé — skipping verify (apt install nmap)")
        return host_ports_in

    if not hosts_to_verify:
        log_warn("Aucun host pour nmap verify")
        return host_ports_in

    verify_list = base_path / "_verify_list.txt"
    write_list(verify_list, list(hosts_to_verify))
    nmap_output = base_path / "nmap_verify.xml"
    tcp_ports_str = ",".join(str(p) for p in ALL_TCP_PORTS)

    log_info(f"nmap SYN scan sur {len(hosts_to_verify)} hosts, ports TCP {tcp_ports_str}")
    log_info("Paramètres: -sS --open --max-retries 2 --min-rate 500 (fiable, pas agressif)")

    _, err, code = run(
        f"nmap -sS --open -p {tcp_ports_str} --max-retries 2 --min-rate 500 "
        f"-iL {verify_list} -oX {nmap_output} -n 2>/dev/null",
        timeout=600
    )

    if not nmap_output.exists() or nmap_output.stat().st_size == 0:
        log_warn(f"nmap n'a pas produit de résultats (code={code})")
        return host_ports_in

    # ── Parse XML nmap ────────────────────────────────────────────────────────
    nmap_ports: dict[str, set[int]] = {}
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(nmap_output)
        for host_el in tree.findall(".//host"):
            status_el = host_el.find("status")
            if status_el is None or status_el.get("state") != "up":
                continue
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr")
            ports_found = set()
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    ports_found.add(int(port_el.get("portid")))
            if ports_found:
                nmap_ports[ip] = ports_found
    except ET.ParseError as e:
        log_warn(f"Erreur parsing XML nmap: {e}")
        return host_ports_in

    # ── Stats diff ────────────────────────────────────────────────────────────
    new_ports_total = 0
    new_hosts_total = 0
    merged = {ip: set(ports) for ip, ports in host_ports_in.items()}

    for ip, ports in nmap_ports.items():
        if ip not in merged:
            merged[ip] = set()
            new_hosts_total += 1
            log_ok(f"nmap nouveau host: {ip} ({len(ports)} ports)")
        new_here = ports - merged[ip]
        if new_here:
            new_ports_total += len(new_here)
            log_ok(f"nmap ports supplémentaires sur {ip}: {sorted(new_here)}")
        merged[ip].update(ports)

    log_ok(f"nmap verify: {new_hosts_total} hosts supplémentaires, {new_ports_total} ports supplémentaires")
    log_info(f"Résultats nmap bruts → {nmap_output}")
    return merged


# =============================================================================
# SYNTHESE
# =============================================================================
def write_summary(base_path, target, hosts_list, host_ports, rate):
    """Génère summary.txt avec un récap lisible."""
    log_step("Synthèse")

    # Charge les catégories depuis hosts_*.txt
    categories = {}
    for f in sorted(base_path.glob("hosts_*.txt")):
        cat = f.stem.replace("hosts_", "")
        ips = read_list(f)
        if ips:
            categories[cat] = ips

    port_counts = Counter(p for ports in (host_ports or {}).values() for p in ports)
    top_ports = port_counts.most_common(15)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    targets_file = base_path / "targets.txt"
    all_targets  = targets_file.read_text().splitlines() if targets_file.exists() else [target]

    lines = [
        "NoPainNoScan Discovery Summary",
        "===============================",
    ]
    if len(all_targets) == 1:
        lines.append(f"Target     : {all_targets[0]}")
    else:
        lines.append(f"Targets    : {len(all_targets)} réseaux")
        for t in all_targets:
            lines.append(f"             {t}")
    lines += [
        f"Date       : {now}",
        f"Rate       : {rate} pps",
        "",
        "HOSTS",
        f"  Alive    : {len(hosts_list)}",
    ]
    cat_order = ["dc", "smb", "ldap", "rdp", "winrm", "ssh", "http",
                 "mssql", "dns", "kerberos", "ftp", "snmp", "ipmi"]
    shown = set()
    for cat in cat_order:
        if cat in categories:
            lines.append(f"  {cat.upper():<9}: {len(categories[cat])}")
            shown.add(cat)
    for cat, ips in sorted(categories.items()):
        if cat not in shown and cat != "alive":
            lines.append(f"  {cat.upper():<9}: {len(ips)}")

    if top_ports:
        lines += ["", "TOP OPEN PORTS"]
        for port, count in top_ports:
            lines.append(f"  {port:<6} : {count} hosts")

    summary_txt = "\n".join(lines) + "\n"
    summary_file = base_path / "summary.txt"
    summary_file.write_text(summary_txt)
    log_ok(f"summary.txt écrit → {summary_file}")

    print(f"\n{C.BOLD}Synthèse — {target}{C.ENDC}")
    print(f"{C.DIM}{RULE}{C.ENDC}")
    print(summary_txt)
    print(f"{C.BOLD}  Output : {base_path}/{C.ENDC}\n")


# =============================================================================
# MAIN
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="AD Recon Userless — Phase 1: Host Discovery + Port Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  sudo python3 ad_recon_userless.py -t 192.168.1.0/24
  sudo python3 ad_recon_userless.py -t 10.10.10.0/24 -o /tmp/pentest -r 2000
  sudo python3 ad_recon_userless.py -t targets.txt -o /tmp/pentest --verify
  sudo python3 ad_recon_userless.py -t targets.txt -o /tmp/pentest --exotic   # enrichit après un 1er run

Fichier de cibles (targets.txt):
  10.0.0.0/24
  172.16.5.0/24
  192.168.1.50    # serveur isolé
        """
    )
    parser.add_argument("-t", "--target", required=True,
                        help="CIDR/IP cible ou fichier de cibles (un CIDR/IP par ligne)")
    parser.add_argument("-o", "--output", default=".",
                        help="Répertoire de sortie (défaut: .)")
    parser.add_argument("-r", "--rate",   default=5000, type=int,
                        help="Taux masscan en pps (défaut: 5000)")
    parser.add_argument("--verify", action="store_true",
                        help="Double-check nmap SYN après masscan (plus lent mais zéro faux négatif)")
    parser.add_argument("--fresh", action="store_true",
                        help="Ignore l'état précédent et rescanne tout (par défaut : reprise/incrémental)")
    parser.add_argument("--exotic", action="store_true",
                        help="Passe d'enrichissement : scanne des ports à forte valeur hors AD "
                             "(bases de données, web exotique, VNC, conteneurs, NetBIOS...) sur les hôtes vivants")
    args = parser.parse_args()

    targets = parse_targets(args.target)

    print(f"\n{C.BOLD}AD Recon Userless — Phase 1: Discovery + Port Scan{C.ENDC}")
    print(f"{C.DIM}{RULE}{C.ENDC}")
    if len(targets) == 1:
        print(f"  Cible   : {targets[0]}")
    else:
        print(f"  Cibles  : {len(targets)} réseaux (depuis {args.target})")
        for t in targets:
            print(f"            {t}")
    print(f"  Output  : {args.output}")
    print(f"  Rate    : {args.rate} pps")
    print(f"{C.DIM}{RULE}{C.ENDC}\n")

    check_root()

    base_path = setup_output_multi(args.output, args.target, targets)

    if args.fresh:
        clean_output(base_path)
        log_info("--fresh : état précédent effacé, scan complet")

    # ── Charge l'état accumulé (merge incrémental + reprise) ──────────────────
    state         = load_state(base_path)
    prior_targets = set(state.get("targets_scanned", []))
    prior_scanned = set(state.get("hosts_scanned", []))
    prior_alive   = set(read_list(base_path / "hosts_alive.txt"))
    prior_ports   = load_prior_ports(base_path)
    prior_exotic  = set(state.get("hosts_exotic_scanned", []))

    # targets.txt = union de toutes les cibles connues (historique cumulé)
    all_known = sorted(prior_targets | set(targets))
    (base_path / "targets.txt").write_text("\n".join(all_known) + "\n")

    # Incrémental : on ne (re)découvre que les subnets pas encore traités.
    new_targets = [t for t in targets if t not in prior_targets]
    if prior_targets:
        if new_targets:
            log_info(f"Reprise : {len(new_targets)} nouveau(x) subnet(s) à découvrir")
        else:
            log_info("Reprise : aucun nouveau subnet depuis le dernier run")

    total_steps = 3 if args.verify else 2

    try:
        # ── ETAPE 1 — découverte (nouveaux subnets) + merge ──────────────────
        emit_progress(1, total_steps, label="ÉTAPE 1 — Découverte des hôtes")
        discovered   = discover_hosts(new_targets)
        merged_alive = prior_alive | discovered
        write_list(base_path / "hosts_alive.txt", list(merged_alive))
        if discovered:
            log_ok(f"{len(merged_alive)} hôtes vivants cumulés "
                   f"(+{len(discovered - prior_alive)} nouveaux)")
        if not merged_alive:
            log_err("Aucun host vivant (ni nouveau ni accumulé) — rien à scanner")
            sys.exit(1)

        # Incrémental : on ne masscanne que les hôtes jamais scannés.
        hosts_to_scan = sorted(merged_alive - prior_scanned)
        if not hosts_to_scan:
            log_info("Tous les hôtes vivants ont déjà été port-scannés")

        # ── ETAPE 2 — masscan AD/services (nouveaux hôtes) + merge ───────────
        emit_progress(2, total_steps, label="ÉTAPE 2 — Port scan (masscan)")
        log_step("ETAPE 2 — Port scan rapide (masscan)")
        new_ports, scan_ok = masscan_scan(
            base_path, hosts_to_scan, ALL_TCP_PORTS, UDP_PORTS.values(),
            rate=args.rate, raw_name="masscan_raw.json", label="AD/services")
        merged_ports = merge_ports(prior_ports, new_ports)
        # On ne marque "scannés" que si masscan a terminé proprement.
        scanned_now = prior_scanned | (set(hosts_to_scan) if scan_ok else set())

        # ── ETAPE 2bis — passe exotique (--exotic) sur les hôtes vivants ──────
        exotic_now = set(prior_exotic)
        if args.exotic:
            exotic_targets = sorted(merged_alive - prior_exotic)
            log_step("ETAPE 2bis — Ports exotiques (--exotic)")
            ex_ports, ex_ok = masscan_scan(
                base_path, exotic_targets, EXOTIC_TCP_PORTS.keys(), EXOTIC_UDP_PORTS.keys(),
                rate=args.rate, raw_name="masscan_exotic.json", label="exotiques")
            merged_ports = merge_ports(merged_ports, ex_ports)
            if ex_ok:
                exotic_now |= set(exotic_targets)

        # ── ETAPE 3 — vérification nmap (optionnel) ──────────────────────────
        if args.verify:
            emit_progress(3, total_steps, label="ÉTAPE 3 — Vérification nmap")
            verify_hosts = hosts_to_scan or sorted(merged_alive)
            merged_ports = nmap_verify(base_path, verify_hosts, merged_ports)

        # ── Écriture des fichiers catégorisés depuis l'ensemble accumulé ─────
        _rewrite_output_files(base_path, merged_ports)

        # ── Persistance de l'état ────────────────────────────────────────────
        state["rate"]                 = args.rate
        state["targets_scanned"]      = sorted(prior_targets | set(new_targets))
        state["hosts_scanned"]        = sorted(scanned_now)
        state["hosts_exotic_scanned"] = sorted(exotic_now)
        state["last_phase"]           = "done"
        save_state(base_path, state)

        write_summary(base_path, args.target, sorted(merged_alive), merged_ports, args.rate)

    except KeyboardInterrupt:
        log_warn("Interruption (Ctrl-C) — sauvegarde de l'état pour reprise")
        # On ne valide ni les nouveaux subnets ni les hôtes du run en cours,
        # pour qu'ils soient repris au prochain lancement.
        state["rate"]       = args.rate
        state["last_phase"] = "interrupted"
        save_state(base_path, state)
        log_info(f"Relancez la même commande pour reprendre (état : {base_path}/{STATE_FILE})")
        sys.exit(130)


if __name__ == "__main__":
    main()
