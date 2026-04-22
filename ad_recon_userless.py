#!/usr/bin/env python3
"""
AD Recon Userless — Phase 1: Host Discovery + Port Scan
Usage: sudo python3 ad_recon_userless.py -t 192.168.1.0/24

Workflow:
    1. fping      — ICMP sweep (hosts alive)
    2. arp-scan   — ARP sweep (hosts silencieux ICMP, réseau local)
    3. masscan    — port scan rapide (ports AD + services communs + UDP SNMP/IPMI)

Output files:
    hosts_alive.txt       tous les hosts répondants (ICMP/ARP)
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
    ports_summary.json    {IP: [ports]} toutes IPs
    summary.txt           synthèse lisible
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
from datetime import datetime
from pathlib import Path


# =============================================================================
# COULEURS
# =============================================================================
class C:
    HEADER = '\033[95m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    WARN   = '\033[93m'
    FAIL   = '\033[91m'
    ENDC   = '\033[0m'
    BOLD   = '\033[1m'


# =============================================================================
# LOGGING
# =============================================================================
def log_info(msg): print(f"{C.CYAN}[*]{C.ENDC} {msg}")
def log_ok(msg):   print(f"{C.GREEN}[+]{C.ENDC} {msg}")
def log_warn(msg): print(f"{C.WARN}[!]{C.ENDC} {msg}")
def log_err(msg):  print(f"{C.FAIL}[X]{C.ENDC} {msg}")

def log_step(msg):
    print(f"\n{C.HEADER}{C.BOLD}{'='*60}\n  {msg}\n{'='*60}{C.ENDC}")


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


def tool_exists(name):
    return shutil.which(name) is not None


def check_root():
    if os.geteuid() != 0:
        log_warn("Non root — masscan nécessite les privilèges root")
        log_warn("Relancer avec sudo pour des résultats complets")


def setup_output(base_dir, target):
    safe = target.replace("/", "_")
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


def read_list(path):
    """Lit une liste d'IPs depuis un fichier. Retourne [] si absent."""
    p = Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text().splitlines() if line.strip()]


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


# =============================================================================
# ETAPE 1 — DECOUVERTE DES HOSTS
# =============================================================================
def discover_hosts(base_path, target):
    """
    Découverte via ICMP (fping) + ARP (arp-scan).
    Les deux sources sont fusionnées et dédupliquées.

    Returns:
        list[str]: IPs découvertes, triées
    """
    log_step("ETAPE 1 — Découverte des hôtes")
    hosts = set()

    # --- fping: ICMP echo ---
    if tool_exists("fping"):
        log_info("fping ICMP sweep...")
        out, _, _ = run(f"fping -a -g -q {target} 2>/dev/null", timeout=120)
        icmp_hosts = {line.strip() for line in out.splitlines() if line.strip()}
        if icmp_hosts:
            log_ok(f"fping: {len(icmp_hosts)} hosts ICMP alive")
            hosts.update(icmp_hosts)
        else:
            log_warn("fping: 0 host ICMP (ICMP filtré ou réseau vide)")
    else:
        log_warn("fping non installé — skipping ICMP (apt install fping)")

    # --- arp-scan: ARP (réseau local, détecte les hosts qui bloquent ICMP) ---
    if tool_exists("arp-scan"):
        log_info("arp-scan ARP sweep...")
        out, _, _ = run("arp-scan --localnet --quiet 2>/dev/null", timeout=60)
        arp_hosts = set()
        for line in out.splitlines():
            match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s', line)
            if match:
                arp_hosts.add(match.group(1))
        if arp_hosts:
            log_ok(f"arp-scan: {len(arp_hosts)} hosts ARP")
            hosts.update(arp_hosts)
    else:
        log_warn("arp-scan non installé — hosts silencieux ICMP non détectés (apt install arp-scan)")

    if not hosts:
        log_err("Aucun host découvert — vérifier le réseau ou les permissions (root requis pour ARP)")
        return []

    hosts_list = sort_ips(list(hosts))
    write_list(base_path / "hosts_alive.txt", hosts_list)
    log_ok(f"{len(hosts_list)} hosts uniques → hosts_alive.txt")
    return hosts_list


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
    content = re.sub(r',\s*\]', ']', content)
    content = re.sub(r',\s*$', '', content)

    if not content or content in ('[]', ''):
        return {}

    try:
        entries = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON masscan invalide après nettoyage: {e}")

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
    (base_path / "ports_summary.json").write_text(
        json.dumps(ports_summary, indent=2, sort_keys=True)
    )

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
    log_ok(f"Ports distincts : {len(port_to_ips)}")


def masscan_scan(base_path, hosts_list, rate=5000):
    """
    Scan rapide des ports AD/services + UDP SNMP/IPMI.
    Génère les fichiers hosts_*.txt, port_*.txt, hosts_detail/, ports_summary.json.

    Returns:
        dict[str, set[int]]: {ip: {open ports}}
    """
    log_step("ETAPE 2 — Port scan rapide (masscan)")

    if not tool_exists("masscan"):
        log_warn("masscan non installé — skipping (apt install masscan)")
        return {}

    if not hosts_list:
        log_warn("Aucun host à scanner")
        return {}

    hosts_file  = base_path / "hosts_alive.txt"
    output_file = base_path / "masscan_raw.json"

    tcp_ports_str = ",".join(str(p) for p in ALL_TCP_PORTS)
    udp_ports_str = ",".join(f"U:{p}" for p in UDP_PORTS.values())
    ports_arg     = f"{tcp_ports_str},{udp_ports_str}"

    log_info(f"Scanning {len(hosts_list)} hosts × TCP {len(ALL_TCP_PORTS)} ports + UDP 161,623 @ {rate} pps (retries=2)...")
    _, err, code = run(
        f"masscan -iL {hosts_file} -p{ports_arg} --rate={rate} --retries=2 -oJ {output_file}",
        timeout=900
    )

    if not output_file.exists() or output_file.stat().st_size == 0:
        log_err(f"masscan a échoué ou 0 résultat. Code={code}")
        if err.strip():
            log_err(f"stderr: {err.strip()[:300]}")
        return {}

    try:
        host_ports = parse_masscan_json(output_file)
    except ValueError as e:
        log_err(str(e))
        return {}

    if not host_ports:
        log_warn("masscan: aucun port ouvert trouvé")
        return {}

    _rewrite_output_files(base_path, host_ports)
    return host_ports


# =============================================================================
# ETAPE 3 — VERIFICATION NMAP (optionnel)
# =============================================================================
def nmap_verify(base_path, hosts_list, host_ports_masscan):
    """
    Second pass nmap SYN sur les hosts découverts pour compléter masscan.
    - Lance nmap sur les mêmes ports TCP que masscan (--retries déjà dans masscan pour UDP)
    - Merge les résultats avec ceux de masscan
    - Met à jour tous les fichiers hosts_*.txt / port_*.txt

    Typiquement 30-120s sur un /24 avec 50 hosts (ports limités, pas de service detection).
    Returns:
        dict[str, set[int]]: host_ports fusionné masscan + nmap
    """
    log_step("ETAPE 3 — Vérification nmap (double-check)")

    if not tool_exists("nmap"):
        log_warn("nmap non installé — skipping verify (apt install nmap)")
        return host_ports_masscan

    if not hosts_list:
        log_warn("Aucun host pour nmap verify")
        return host_ports_masscan

    hosts_file  = base_path / "hosts_alive.txt"
    nmap_output = base_path / "nmap_verify.xml"
    tcp_ports_str = ",".join(str(p) for p in ALL_TCP_PORTS)

    log_info(f"nmap SYN scan sur {len(hosts_list)} hosts, ports TCP {tcp_ports_str}")
    log_info("Paramètres: -sS --open --max-retries 2 --min-rate 500 (fiable, pas agressif)")

    _, err, code = run(
        f"nmap -sS --open -p {tcp_ports_str} --max-retries 2 --min-rate 500 "
        f"-iL {hosts_file} -oX {nmap_output} -n 2>/dev/null",
        timeout=600
    )

    if not nmap_output.exists() or nmap_output.stat().st_size == 0:
        log_warn(f"nmap n'a pas produit de résultats (code={code})")
        return host_ports_masscan

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
        return host_ports_masscan

    # ── Stats diff ────────────────────────────────────────────────────────────
    new_ports_total = 0
    new_hosts_total = 0
    merged = {ip: set(ports) for ip, ports in host_ports_masscan.items()}

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

    lines = [
        "NoPainNoScan Discovery Summary",
        "===============================",
        f"Target     : {target}",
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

    print(f"\n{C.BOLD}{'='*60}")
    print(f"  SYNTHESE — {target}")
    print(f"{'='*60}{C.ENDC}")
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
        """
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Réseau cible CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("-o", "--output", default=".",
                        help="Répertoire de sortie (défaut: .)")
    parser.add_argument("-r", "--rate",   default=5000, type=int,
                        help="Taux masscan en pps (défaut: 5000)")
    parser.add_argument("--verify", action="store_true",
                        help="Double-check nmap SYN après masscan (plus lent mais zéro faux négatif)")
    args = parser.parse_args()

    print(f"\n{C.BOLD}{'='*60}")
    print(f"    AD RECON USERLESS — PHASE 1: DISCOVERY + PORT SCAN")
    print(f"{'='*60}{C.ENDC}")
    print(f"  Cible   : {args.target}")
    print(f"  Output  : {args.output}")
    print(f"  Rate    : {args.rate} pps")
    print(f"{'='*60}\n")

    check_root()

    base_path  = setup_output(args.output, args.target)
    hosts_list = discover_hosts(base_path, args.target)

    if not hosts_list:
        sys.exit(1)

    host_ports = masscan_scan(base_path, hosts_list, rate=args.rate)

    if args.verify and host_ports is not None:
        host_ports = nmap_verify(base_path, hosts_list, host_ports)
        # Réécrire les fichiers hosts_*.txt / port_*.txt avec les résultats mergés
        _rewrite_output_files(base_path, host_ports)

    write_summary(base_path, args.target, hosts_list, host_ports, args.rate)


if __name__ == "__main__":
    main()
