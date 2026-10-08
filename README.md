# NoPainNoScan

Toolkit Python d'automatisation pour les **pentests internes Active Directory**. Chaque script est autonome, lit les fichiers de hosts produits par la découverte (ou accepte un IP/CIDR/fichier), et génère des sorties structurées agrégées en un rapport HTML. Une interface web optionnelle permet de tout piloter depuis le navigateur.

> ⚠️ **Usage autorisé uniquement** — audits et tests d'intrusion mandatés, labs, recherche. Vous êtes responsable de l'usage que vous en faites.

---

## Caractéristiques

- **Scripts standalone** — un script par service, utilisables indépendamment ou en chaîne.
- **Découverte relançable** — `ad_recon_userless.py` accumule les résultats, reprend après interruption et ne rescanne que le nouveau (idéal quand les subnets arrivent au fil de l'eau via LDAP) ; passe `--exotic` pour enrichir avec les services hors AD.
- **Sorties structurées** — fichiers `hosts_<service>.txt`, `ports_summary.json`, etc., consommés par le rapport et l'UI.
- **Rapport HTML** self-contained (un seul fichier, zéro dépendance).
- **Interface web** optionnelle (FastAPI) : lancement, suivi live, dashboard, export.
- **Mode non-interactif** (`--yes`) et **affichage couleur** auto-désactivé hors terminal.

---

## Installation

```bash
git clone <repo> && cd NoPainNoScan
# Outils système (selon les checks utilisés)
sudo apt install masscan fping nmap ldap-utils dnsutils ipmitool onesixtyone snmp whatweb curl
pip install netexec impacket bloodhound ssh-audit
# kerbrute : https://github.com/ropnop/kerbrute/releases
```

Chaque script vérifie ses outils au démarrage et signale les manquants sans planter.

| Outil | Utilisé par |
|---|---|
| `masscan`, `fping`, `nmap` | discovery (`ad_recon_userless`) |
| `nxc` / `netexec` | smb, ldap, rdp, mssql, ssh, ftp, winrm, kerberos |
| `ldapsearch`, `bloodhound-python` | ldap |
| `dig` | dns |
| `ssh-audit` | ssh |
| `kerbrute`, `impacket` | kerberos |
| `ipmitool`, `ipmipwner` (opt.) | ipmi |
| `onesixtyone`, `snmpwalk` | snmp |
| `whatweb`, `curl` | http, winrm |

---

## Démarrage rapide

```bash
# 1. Découverte hosts + services (root requis)
sudo python3 ad_recon_userless.py -t targets.txt -o /tmp/pentest

# 2. Checks par service, sur les fichiers de hosts générés
python3 check_smb.py  -t /tmp/pentest/targets/hosts_smb.txt  -o /tmp/pentest/smb
python3 check_ldap.py -t /tmp/pentest/targets/hosts_ldap.txt -o /tmp/pentest/ldap
# ... puis, une fois des creds obtenus :
python3 check_smb.py  -t /tmp/pentest/targets/hosts_smb.txt -u jdoe -p 'P@ss' -d corp.local -o /tmp/pentest/smb_auth

# 3. Rapport HTML agrégé
python3 generate_report.py -d /tmp/pentest -n "Client" -o /tmp/pentest/report.html
```

---

## Les scripts

| Script | Port(s) | Vérifie |
|---|---|---|
| `ad_recon_userless.py` | — | Découverte réseau (fping + nmap), port scan masscan, tri par service |
| `check_smb.py` | 139/445 | Signing, SMBv1, null session, partages (R/W), SYSVOL/NETLOGON |
| `check_ldap.py` | 389/636/3268 | Null bind + dump anonyme, LDAP signing/channel binding (relais NTLM), pass-pol, MachineAccountQuota, délégation, adminCount, LAPS/gMSA lisibles, ADCS, descriptions, AS-REP/Kerberoast, BloodHound (`--bloodhound`, 1 DC) |
| `check_rdp.py` | 3389 | NLA, OS, test de login, screenshot |
| `check_ssh.py` | 22 | Bannière, algos faibles, méthodes d'auth, test creds |
| `check_http.py` | 80/443/8080/8443/8000 | ADCS, WebDAV, OWA/RDWeb/ADFS/WSUS, whatweb |
| `check_mssql.py` | 1433 | Creds SA par défaut, xp_cmdshell (RCE), linked servers |
| `check_dns.py` | 53 | Transfert de zone (AXFR), énum, reverse PTR |
| `check_ftp.py` | 21 | Accès anonyme, chemins inscriptibles, test creds |
| `check_snmp.py` | 161/UDP | Community strings, snmpwalk |
| `check_ipmi.py` | 623/UDP | Cipher-zero, RAKP, creds par défaut |
| `check_winrm.py` | 5985/5986 | Méthodes d'auth, test creds, exécution |
| `check_kerberos.py` | 88/464 | Énum users, AS-REP roasting, Kerberoasting |
| `generate_report.py` | — | Rapport HTML agrégeant toutes les sorties |

### Arguments communs

| Arg | Description |
|---|---|
| `-t` | Fichier de hosts, IP, ou CIDR |
| `-o` | Répertoire de sortie (créé automatiquement) |
| `-u` / `-p` | Identifiants (optionnels) → active les checks authentifiés |
| `-H` | Hash NTLM `LM:NT` (pass-the-hash) |
| `-d` | Domaine AD (FQDN) |
| `--yes` | Non-interactif : accepte toutes les étapes (automatisation / UI) |

Détails et options spécifiques (`--threads`, `--port`, …) : `python3 <script>.py --help`.

---

## Phase 0 — Découverte (`ad_recon_userless.py`)

**Prérequis : root** (masscan et nmap SYN ping utilisent des sockets raw).

```bash
sudo python3 ad_recon_userless.py -t 10.10.0.0/24 -o /tmp/pentest [--verify]
sudo python3 ad_recon_userless.py -t targets.txt  -o /tmp/pentest [--fresh]
```

Étapes : **fping** (ICMP) ‖ **nmap** (TCP SYN ping, détecte les hosts filtrant l'ICMP) — lancés **en parallèle par chunks de cibles** pour tenir un gros scope — → **masscan** (ports AD/services + UDP SNMP/IPMI, `--wait` court) → **nmap `--verify`** (optionnel, double-check TCP). Produit `hosts_alive.txt`, un `hosts_<service>.txt` par service, `port_<n>.txt`, `ports_summary.json`, `summary.txt`.

**Relançable / incrémental** (pensé pour des subnets découverts progressivement) :

- Relancer sur le même `-o` **accumule** les résultats au lieu de les écraser.
- Seuls les **nouveaux subnets** sont redécouverts et seuls les **hôtes jamais scannés** sont port-scannés.
- L'état est persisté dans `state.json` ; une interruption (Ctrl-C) ou un masscan tronqué **reprend proprement** au run suivant.
- `--fresh` ignore l'état et rescanne tout.
- `--exotic` ajoute une passe d'enrichissement sur les hôtes vivants : services à forte valeur hors AD (bases de données, web sur ports exotiques, VNC, NFS, conteneurs/k8s, mail, imprimantes, NetBIOS/mDNS UDP, quelques ports OT/ICS) → `hosts_exotic.txt` + `exotic_services.txt` (IP, port, service).
- Le `targets.txt` accepte IP / CIDR / plage `a.b.c.d-e` ; les lignes invalides sont ignorées avec un avertissement.

| Flag | Rôle |
|---|---|
| `-r` | Taux masscan en pps (défaut 5000) |
| `--verify` | Second passage nmap SYN après masscan |
| `--exotic` | Passe d'enrichissement : ports à forte valeur hors AD |
| `--fresh` | Repart de zéro (ignore `state.json`) |

---

## Rapport HTML

```bash
python3 generate_report.py -d /tmp/pentest -n "Client" -o report.html
```

Scanne récursivement le répertoire, détecte automatiquement tous les fichiers de sortie connus, et génère un rapport HTML autonome : sidebar par service (code couleur de criticité), bandeaux des findings critiques/warnings, stats, et une carte par service. Criticité : 🔴 critique · ⚠️ important.

---

## Interface web (optionnelle)

Interface FastAPI locale (`127.0.0.1`, mono-utilisateur) pour lancer les scans, suivre leur progression en temps réel, explorer les findings dans un dashboard et générer les rapports — en réutilisant les scripts existants.

```bash
cd webui
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-web.txt
python -m app.main        # http://127.0.0.1:8000
```

Détails : [`webui/README.md`](webui/README.md).

---

## Arborescence

```
NoPainNoScan/
├── ad_recon_userless.py   # Phase 0 — découverte + port scan
├── check_*.py             # 12 checks par service
├── generate_report.py     # Rapport HTML
├── npns_common.py         # Plomberie partagée (couleurs, logs, étapes)
├── _npns_progress.py      # Émission de progression (barre UI web)
└── webui/                 # Interface web (FastAPI, optionnelle)
```
