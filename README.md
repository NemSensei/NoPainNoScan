# NoPainNoScan

Toolkit Python d'automatisation pour les pentests internes Active Directory. Chaque script est standalone, lit les fichiers de hosts générés par la discovery ou accepte directement un IP/CIDR, et produit des fichiers de résultats structurés.

---

## Architecture

```
NoPainNoScan/
├── ad_recon_userless.py   # Phase 0 — Discovery réseau (black box, sans compte)
├── check_smb.py           # SMB : signing, SMBv1, shares, SYSVOL
├── check_ldap.py          # LDAP : null bind, dump AD, enum authentifiée
├── check_rdp.py           # RDP : NLA, OS, screenshot
├── check_ssh.py           # SSH : banner, ciphers faibles, auth methods
├── check_http.py          # HTTP/S : ADCS, WebDAV, OWA, ADFS, WSUS
├── check_mssql.py         # MSSQL : creds par défaut SA, xp_cmdshell
├── check_dns.py           # DNS : AXFR, subdomain enum, reverse PTR
├── check_ftp.py           # FTP : accès anonyme, listing fichiers
├── check_snmp.py          # SNMP : community strings, snmpwalk
├── check_ipmi.py          # IPMI : cipher-zero, RAKP, creds par défaut
├── check_winrm.py         # WinRM : auth methods, test creds, exec
└── check_kerberos.py      # Kerberos : user enum, AS-REP, Kerberoast
```

---

## Dépendances

| Outil | Script(s) concerné(s) | Installation |
|---|---|---|
| `masscan` | ad_recon_userless | `apt install masscan` |
| `fping` | ad_recon_userless | `apt install fping` |
| `arp-scan` | ad_recon_userless | `apt install arp-scan` |
| `nxc` / `netexec` | smb, ldap, rdp, mssql, ssh, ftp, winrm, kerberos | `pip install netexec` |
| `ldapsearch` | ldap | `apt install ldap-utils` |
| `dig` | dns | `apt install dnsutils` |
| `ssh-audit` | ssh | `pip install ssh-audit` ou `apt install ssh-audit` |
| `ipmitool` | ipmi | `apt install ipmitool` |
| `onesixtyone` | snmp | `apt install onesixtyone` |
| `snmpwalk` | snmp | `apt install snmp` |
| `kerbrute` | kerberos | [github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute/releases) |
| `impacket` | kerberos | `pip install impacket` |
| `bloodhound-python` | ldap | `pip install bloodhound` |
| `whatweb` | http | `apt install whatweb` |
| `curl` | http, winrm | `apt install curl` |
| `ipmipwner` | ipmi | optionnel, améliore RAKP |

Chaque script vérifie les outils requis au démarrage et signale les manquants sans crasher.

---

## Workflow typique

```
┌─────────────────────────────────────────────────────────────────┐
│  ad_recon_userless.py -t 10.10.0.0/24                           │
│                                                                  │
│  → hosts_alive.txt, hosts_smb.txt, hosts_ldap.txt, ...          │
│  → port_445.txt, port_22.txt, ...                               │
│  → hosts_detail/<IP>.txt, ports_summary.json, summary.txt       │
└────────────────────────────────────┬────────────────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          ▼                          ▼                          ▼
    check_smb.py             check_ldap.py           check_kerberos.py
    check_rdp.py             check_dns.py             check_http.py
    check_ssh.py             check_mssql.py           check_ipmi.py
    check_ftp.py             check_snmp.py            check_winrm.py
          │
          └────────── avec -u/-p/-H : checks authentifiés supplémentaires
```

---

## Phase 0 — Discovery réseau

### `ad_recon_userless.py`

**Prérequis :** root (arp-scan et masscan nécessitent des sockets raw)

```bash
sudo python3 ad_recon_userless.py -t 192.168.1.0/24
sudo python3 ad_recon_userless.py -t 10.10.10.0/24 -o /tmp/pentest -r 2000
```

| Argument | Défaut | Description |
|---|---|---|
| `-t` | — | Réseau cible CIDR |
| `-o` | `.` | Répertoire de sortie |
| `-r` | `5000` | Taux masscan en paquets/seconde |

#### Ce que fait le script

**ETAPE 1 — Découverte des hôtes**

- `fping -a -g -q <CIDR>` — ICMP sweep, liste les hosts qui répondent
- `arp-scan --localnet` — ARP sweep, détecte les hosts qui bloquent ICMP (silencieux)
- Fusionne et déduplique les deux sources → **`hosts_alive.txt`**

**ETAPE 2 — Port scan (masscan)**

Scan TCP sur tous les ports AD/services communs + UDP 161 et 623 :
```
TCP : 21, 22, 53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636,
      1433, 3268, 3269, 3389, 5985, 5986, 8000, 8080, 8443
UDP : 161 (SNMP), 623 (IPMI)
```

Parse le JSON masscan (gère les trailing commas malformées), catégorise les hosts et génère :

| Fichier | Contenu |
|---|---|
| `hosts_alive.txt` | Tous les hôtes vivants (ICMP + ARP) |
| `hosts_dc.txt` | DC potentiels : ports Kerberos (88 ou 464) **ET** LDAP (389 ou 3268) |
| `hosts_smb.txt` | Hôtes avec SMB (139 ou 445) |
| `hosts_ldap.txt` | Hôtes avec LDAP/LDAPS (389, 636, 3268, 3269) |
| `hosts_rdp.txt` | Hôtes avec RDP (3389) |
| `hosts_ssh.txt` | Hôtes avec SSH (22) |
| `hosts_http.txt` | Hôtes avec HTTP/S (80, 443, 8000, 8080, 8443) |
| `hosts_mssql.txt` | Hôtes avec MSSQL (1433) |
| `hosts_dns.txt` | Hôtes avec DNS (53) |
| `hosts_kerberos.txt` | Hôtes avec Kerberos (88, 464) |
| `hosts_ftp.txt` | Hôtes avec FTP (21) |
| `hosts_winrm.txt` | Hôtes avec WinRM (5985, 5986) |
| `hosts_snmp.txt` | Hôtes avec SNMP UDP (161) |
| `hosts_ipmi.txt` | Hôtes avec IPMI UDP (623) |
| `port_<PORT>.txt` | Un fichier par port ouvert : IPs ayant ce port |
| `hosts_detail/host_<IP>.txt` | Un fichier par IP : liste des ports ouverts |
| `ports_summary.json` | `{"IP": [port1, port2, ...], ...}` — mapping complet |
| `masscan_raw.json` | Output brut masscan |
| `summary.txt` | Résumé lisible : comptes par catégorie + top 15 ports |

---

## Scripts par service

**Arguments communs à tous les scripts :**

| Argument | Description |
|---|---|
| `-t` | Fichier de hosts, IP unique, ou CIDR |
| `-o` | Répertoire de sortie (créé automatiquement) |
| `-u` | Nom d'utilisateur (optionnel) |
| `-p` | Mot de passe (optionnel) |
| `-H` | Hash NTLM `LM:NT` — pass-the-hash (optionnel) |
| `-d` | Domaine AD FQDN (optionnel) |

---

### `check_smb.py` — SMB (139/445)

```bash
python3 check_smb.py -t output/hosts_smb.txt
python3 check_smb.py -t 192.168.1.0/24 -u jdoe -p 'P@ss' -d corp.local
python3 check_smb.py -t 192.168.1.10  -u admin -H aad3b435:31d6cfe0 -d corp.local
```

Argument supplémentaire : `--threads` (défaut : 10)

#### Ce que fait le script

**STEP 1 — SMB info + signing (sans creds)**

Lance `nxc smb <hosts> --gen-relay-list` qui produit à la fois le tableau d'infos et le fichier de relay.
Parse chaque ligne de sortie nxc avec regex pour extraire :
- IP, hostname, OS, statut signing, version SMBv1

```
SMB 192.168.1.10 445 DC01 [*] Windows Server 2019 ... (signing:False) (SMBv1:False)
```

**STEP 2 — Null session (sans creds)**

`nxc smb <hosts> --shares -u '' -p ''`
Parse les lignes contenant `READ` ou `WRITE` pour extraire les partages accessibles en session nulle.

**STEP 3 — Shares authentifiées (avec creds)**

`nxc smb <hosts> -u <user> -p <pass> -d <domain> --shares`
Sépare les partages `READ` des `READ,WRITE`. Les partages en écriture sont flaggés CRITICAL.

**STEP 4 — SYSVOL/NETLOGON (avec creds)**

- `nxc smb <hosts> -M spider_plus` — spider tous les partages, collecte les lignes mentionnant SYSVOL/NETLOGON
- `nxc smb <hosts> --spider SYSVOL --pattern '.ps1,.vbs,.bat,.xml,.txt'` — cherche spécifiquement les scripts/configs GPP

**STEP 5 — Spider plus summary (avec creds)**

Parse les JSON générés par spider_plus dans `~/.nxc/logs/` pour lister les fichiers intéressants avec leur taille.

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `smb_unsigned.txt` | IPs avec SMB signing désactivé (cibles de relay NTLM) | ⚠️ |
| `smb_v1.txt` | IPs avec SMBv1 activé (EternalBlue risk) | ⚠️ |
| `smb_hosts_info.txt` | Tableau : IP, hostname, signing, SMBv1, OS | — |
| `smb_shares_null.txt` | Partages accessibles en null session (format `IP  SHARE  [READ]`) | ⚠️ |
| `smb_shares_read.txt` | Partages lisibles avec creds | — |
| `smb_shares_write.txt` | Partages accessibles en écriture avec creds | 🔴 |
| `sysvol_files.txt` | Scripts/configs trouvés dans SYSVOL/NETLOGON | 🔴 |
| `smb_spider.txt` | Fichiers intéressants découverts via spider_plus | ⚠️ |
| `smb_summary.txt` | Résumé : comptes, liste des relay targets, writable shares | — |

---

### `check_ldap.py` — LDAP (389/3268)

```bash
python3 check_ldap.py -t output/hosts_ldap.txt
python3 check_ldap.py -t 192.168.1.10 -u jdoe -p 'P@ss' -d corp.local
python3 check_ldap.py -t 10.0.0.0/24  -u svc  -H aad3b435:abc123 -d lab.local
```

#### Ce que fait le script

**STEP 1 — rootDSE (sans creds)**

Pour chaque IP : `ldapsearch -x -H ldap://<ip> -b '' -s base '(objectClass=*)' defaultNamingContext`
Extrait le `defaultNamingContext` (ex: `DC=corp,DC=local`).
Si le domaine n'est pas fourni via `-d`, il est auto-détecté à partir du base DN (ex: `corp.local`).

**STEP 2 — Test null bind (sans creds)**

`ldapsearch -x -H ldap://<ip> -D '' -w '' -b '<base_dn>' '(objectClass=person)' sAMAccountName cn`
Si des entrées `dn:` apparaissent dans la réponse → null bind autorisé (CRITICAL).

**STEP 3 — Dump via null bind (si null bind OK)**

Trois requêtes ldapsearch sans credentials :
- `(objectClass=user)` → sAMAccountName, cn, userPrincipalName
- `(objectClass=group)` → cn, member
- `(objectClass=computer)` → name, dNSHostName

**STEP 4 — Enumération authentifiée (avec creds)**

Cinq appels nxc ldap successifs :
```bash
nxc ldap <hosts> -u <user> -p <pass> -d <domain> --users
nxc ldap <hosts> -u <user> -p <pass> -d <domain> --groups
nxc ldap <hosts> -u <user> -p <pass> -d <domain> --password-not-required
nxc ldap <hosts> -u <user> -p <pass> -d <domain> --trusted-for-delegation
nxc ldap <hosts> -u <user> -p <pass> -d <domain> --admin-count
```

**STEP 5 — BloodHound (avec creds, si bloodhound-python installé)**

`bloodhound-python -u <user> -p <pass> -d <domain> -ns <dc_ip> -c All --zip`

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `ldap_domain_info.txt` | IP → base DN détecté (ou UNREACHABLE) | — |
| `ldap_nullbind.txt` | IPs autorisant l'accès anonyme LDAP | 🔴 |
| `ldap_users_<IP>.txt` | Dump LDIF des users via null bind | 🔴 |
| `ldap_groups_<IP>.txt` | Dump LDIF des groupes via null bind | 🔴 |
| `ldap_computers_<IP>.txt` | Dump LDIF des computers via null bind | 🔴 |
| `ldap_users.txt` | Enumération nxc --users | — |
| `ldap_groups.txt` | Enumération nxc --groups | — |
| `ldap_no_preauth.txt` | Comptes sans pré-authentification Kerberos (AS-REP roastables) | 🔴 |
| `ldap_delegation.txt` | Comptes avec délégation Kerberos | ⚠️ |
| `ldap_admin_count.txt` | Comptes avec adminCount=1 | ⚠️ |
| `bloodhound/` | Fichiers ZIP BloodHound | — |
| `ldap_summary.txt` | Résumé : null bind hosts, checks exécutés | — |

---

### `check_rdp.py` — RDP (3389)

```bash
python3 check_rdp.py -t output/hosts_rdp.txt
python3 check_rdp.py -t output/hosts_rdp.txt -u admin -p 'P@ss' -d corp.local
```

#### Ce que fait le script

**STEP 1 — NLA & OS (sans creds)**

`nxc rdp <hosts_file>` — parse chaque ligne avec regex pour extraire :
```
RDP 10.10.10.1 3389 DC01 [*] Windows Server 2016 (name:DC01) (domain:lab.local) (nla:True)
```
Extrait IP, hostname, OS, statut NLA.

**STEP 2 — Test connexion (avec creds)**

`nxc rdp <hosts_file> -u <user> -p <pass> -d <domain>`
Cherche `[+]` dans la sortie pour identifier les connexions réussies.

**STEP 3 — Screenshot (avec creds)**

`nxc rdp <hosts_file> -u <user> -p <pass> -d <domain> --screenshot --screentime 3`
Les screenshots sont sauvés dans les logs nxc.

Fichier intermédiaire : `rdp_nxc_raw.txt` (sortie brute complète).

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `rdp_results.txt` | Tableau : IP, hostname, OS, NLA status | — |
| `rdp_no_nla.txt` | IPs sans NLA — vecteur d'attaque potentiel | ⚠️ |
| `rdp_login_success.txt` | IPs où les creds ont fonctionné | 🔴 |
| `rdp_summary.txt` | Résumé : hosts détectés, NLA disabled, logins réussis | — |

---

### `check_ssh.py` — SSH (22)

```bash
python3 check_ssh.py -t output/hosts_ssh.txt
python3 check_ssh.py -t output/hosts_ssh.txt -u root -p admin --port 2222
```

#### Ce que fait le script

**STEP 1 — Banner grab (sans creds)**

Connexion socket Python directe (timeout 5s) : `socket.connect((ip, port)) → recv(256)`
Récupère la bannière SSH brute (ex: `SSH-2.0-OpenSSH_8.2p1 Ubuntu`).

**STEP 2 — Audit algorithmes (sans creds)**

`ssh-audit --no-colors -p <port> <ip>` pour chaque host.
Fallback si ssh-audit absent : `nxc ssh <ip>`.
Parse la sortie pour détecter les lignes `(fail)` ou `(warn)` et les algorithmes faibles connus :
- KEX : `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, variantes ecdh nist
- Ciphers : `arcfour*`, `des-cbc`, `3des-cbc`, `blowfish-cbc`, `aes*-cbc`
- MACs : `hmac-md5*`, `hmac-sha1*`, `umac-64`

**STEP 3 — Auth methods (sans creds)**

```bash
ssh -o BatchMode=yes -o ConnectTimeout=5 -o PreferredAuthentications=none dummy@<ip>
```
Parse `Authentications that can continue:` dans le stderr pour identifier si l'auth par mot de passe est activée.

**STEP 4 — Test creds (avec creds)**

`nxc ssh <hosts_file> --port <port> -u <user> -p <pass>`
Cherche `[+]`, `pwned`, ou `success` dans la sortie.

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `ssh_banners.txt` | IP : bannière SSH (une ligne par host répondant) | — |
| `ssh_audit_<IP>.txt` | Sortie complète ssh-audit par host | — |
| `ssh_weak_algos.txt` | Hosts avec algos faibles : `[IP]` + liste des issues | ⚠️ |
| `ssh_password_auth.txt` | Hosts acceptant l'auth par mot de passe | ⚠️ |
| `ssh_login_success.txt` | Logins réussis (avec creds) | 🔴 |
| `ssh_summary.txt` | Résumé : comptes, banners, weak algos, password auth | — |

---

### `check_http.py` — HTTP/HTTPS (80/443/8080/8443/8000)

```bash
python3 check_http.py -t output/hosts_http.txt
python3 check_http.py -t output/hosts_http.txt --ports 80,443,8443 --workers 20
```

Arguments supplémentaires : `--ports` (défaut : `80,443,8080,8443,8000`), `--timeout` (défaut : 10s), `--workers` (défaut : 10)

#### Ce que fait le script

Traitement parallèle via `ThreadPoolExecutor` (10 workers par défaut).
Pour chaque IP × port, teste HTTP **et** HTTPS.

**STEP 1 — Title + server header**

`curl -sk -m <timeout> --max-redirs 3 -D - <url>`
Parse les headers (status code, `Server:`, `X-Powered-By:`) et le `<title>` dans le body.

**STEP 2 — Détection ADCS**

Vérifie 4 chemins sur chaque URL découverte :
- `/certsrv/` — ADCS web enrollment
- `/certenroll/` — enrollment DLL
- `/adcs/`
- `/CertSrv/Default.asp`

HTTP 200, 401, ou 403 → endpoint ADCS détecté (candidat ESC8).

**STEP 3 — Détection WebDAV**

`curl -sk -X OPTIONS <url>` — analyse les headers `DAV:` et `Allow:`.
Si PROPFIND, COPY, ou MOVE dans Allow → WebDAV activé (surface de coercion PrinterBug/PetitPotam).

**STEP 4 — Services Microsoft**

Vérifie 4 services avec codes 200/301/302/401/403 :
- `/owa/`, `/exchange/` → OWA
- `/rdweb/` → RD Web Access
- `/adfs/ls/` → ADFS
- `/selfupdate/` → WSUS

**STEP 5 — Tech detection**

`whatweb --no-errors -q <url>` si whatweb installé (séquentiel pour ne pas saturer).

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `http_titles.txt` | `IP:PORT SCHEME STATUS "Title" [Server: value]` pour chaque service | — |
| `http_adcs.txt` | Endpoints ADCS détectés avec code HTTP | 🔴 |
| `http_webdav.txt` | URLs avec WebDAV activé + Allow header | 🔴 |
| `http_owa.txt` | URLs OWA/Exchange | — |
| `http_rdweb.txt` | URLs RD Web Access | — |
| `http_adfs.txt` | URLs ADFS | — |
| `http_wsus.txt` | URLs WSUS | — |
| `http_whatweb.txt` | Sortie whatweb | — |
| `http_summary.txt` | Résumé : comptes par catégorie + findings critiques | — |

---

### `check_mssql.py` — MSSQL (1433)

```bash
python3 check_mssql.py -t output/hosts_mssql.txt
python3 check_mssql.py -t 192.168.1.10 -u sa -p 'Password1'
python3 check_mssql.py -t 10.0.0.0/24  -u admin -H aad3b435:abc123 -d CORP
```

#### Ce que fait le script

**STEP 1 — Version et info (sans creds)**

`nxc mssql <hosts>` — extrait les IPs qui répondent + version SQL Server depuis la sortie.

**STEP 2 — Creds SA par défaut (si aucun -u/-H fourni)**

Teste 6 combinaisons avec `--no-bruteforce` :
```
sa : <vide>  |  sa : sa  |  sa : Password1
sa : password  |  sa : admin  |  sa : 123456
```
Les succès (`[+]` ou `Pwn3d!`) sont enregistrés avec IP, user, password.
**Note :** ce step est skippé automatiquement si des credentials explicites sont fournis.

**STEP 3 — Checks authentifiés (avec creds ou si default creds trouvés)**

Si aucun -u explicite mais des default creds ont été trouvés, utilise le premier hit automatiquement.

```sql
-- Version + user + sysadmin check
SELECT @@version, system_user, is_srvrolemember('sysadmin')

-- Databases
SELECT name FROM sys.databases

-- xp_cmdshell test
nxc mssql <hosts> -x 'whoami'

-- Linked servers
SELECT name FROM sys.servers
```

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `mssql_hosts_info.txt` | Sortie nxc brute avec version/hostname | — |
| `mssql_default_creds.txt` | `IP \t user \t password` pour chaque hit | 🔴 |
| `mssql_accessible.txt` | Résultats des queries (version, DB list, sysadmin status) | — |
| `mssql_cmdexec.txt` | Sortie `whoami` via xp_cmdshell si disponible | 🔴 |
| `mssql_linked_servers.txt` | Serveurs SQL liés (pivoting potentiel) | ⚠️ |
| `mssql_summary.txt` | Résumé : hosts vivants, default creds, user utilisé | — |

---

### `check_dns.py` — DNS (53)

```bash
python3 check_dns.py -t output/hosts_dns.txt
python3 check_dns.py -t 192.168.1.10 -d corp.local
python3 check_dns.py -t 192.168.1.0/24 --range 192.168.1.0/24
```

Argument supplémentaire : `--range` pour le reverse lookup (défaut : /24 du premier host)

#### Ce que fait le script

**STEP 1 — SOA / Détection de domaine**

Pour chaque serveur DNS, tente :
- `dig SOA <domain_candidat> @<ip>` sur une liste de domaines courants (`corp`, `local`, `lan`, `internal`…) + domaines fournis via `-d`
- `dig +short -t SOA . @<ip>` (root SOA)
- `dig @<ip> -t NS .` (root NS)
- `dig @<ip> -t ANY _msdcs` (hint AD)

Extrait le domaine depuis le champ `defaultNamingContext` ou le premier NS du SOA.

**STEP 2 — Zone transfer AXFR**

Pour chaque combinaison serveur × domaine (avec et sans point final) :
`dig axfr <domain> @<ip>`

Un AXFR est considéré réussi si la sortie contient plus d'un enregistrement `IN` (filtre les erreurs et les SOA seuls).
Sauvegarde le dump complet dans `dns_zones/<ip>_<domain>.txt`.

**STEP 3 — Subdomain enumeration**

29 noms courants testés : `dc, dc01, dc02, ad, ldap, kerberos, kdc, mail, smtp, mx, vpn, remote, gateway, www, web, ftp, intranet, sharepoint, exchange, fs, files, ntp, syslog, proxy, wpad, …`
`dig +short <name>.<domain> @<ip>` pour chaque combinaison.

**STEP 4 — Reverse lookup PTR**

Sweep du range cible (limité à 256 hosts max) via `dig +short -x <ip> @<dns_server>`.
Utilise le premier serveur DNS détecté.

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `dns_soa.txt` | Sortie brute des requêtes SOA par serveur | — |
| `dns_axfr_success.txt` | `[CRITICAL] IP — domaine — N records — chemin` | 🔴 |
| `dns_zones/<ip>_<domain>.txt` | Dump AXFR complet | 🔴 |
| `dns_hosts.txt` | `fqdn \t IP` — hostnames résolus | — |
| `dns_reverse.txt` | `IP \t hostname` — PTR records | — |
| `dns_summary.txt` | Résumé : domaines détectés, AXFR, hosts, PTR | — |

---

### `check_ftp.py` — FTP (21)

```bash
python3 check_ftp.py -t output/hosts_ftp.txt
python3 check_ftp.py -t 10.10.10.5 -u ftpuser -p secret
```

#### Ce que fait le script

**STEP 1 — Banner grab**

Connexion `ftplib.FTP` + `ftp.connect(ip, 21)` + `ftp.getwelcome()` pour chaque IP.

**STEP 2 — Login anonyme**

Tente 3 combinaisons via ftplib dans l'ordre :
```
anonymous : anonymous@
<vide>    : <vide>
ftp       : ftp
```

**STEP 3 — Listing fichiers + accès écriture (si login anonyme OK)**

`ftp.retrlines('LIST <path>')` de manière récursive jusqu'à profondeur 3.
Signale les fichiers avec extensions intéressantes : `.conf .config .txt .log .bak .key .pem .db .sql .xlsx .docx .pdf`

Test d'écriture : `ftp.mkd('._nopainnoscan_test')` sur `/` et les 10 premiers dossiers. Supprime le répertoire si créé avec succès.

**STEP 4 — nxc FTP (si nxc disponible)**

`nxc ftp <responsive_hosts> -u anonymous -p anonymous@`
Si creds personnalisés : `nxc ftp <hosts> -u <user> -p <pass>`
Fallback via ftplib si nxc absent.

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `ftp_banners.txt` | `IP \t bannière` (NO RESPONSE si hors ligne) | — |
| `ftp_anonymous.txt` | `IP \t user=... \t pass=...` pour chaque accès anonyme réussi | 🔴 |
| `ftp_writable.txt` | `IP \t /chemin` pour chaque répertoire accessible en écriture | 🔴 |
| `ftp_files_<IP>.txt` | Listing complet (max depth 3), fichiers intéressants marqués | ⚠️ |
| `ftp_login_success.txt` | IPs où les creds personnalisés ont fonctionné | 🔴 |
| `ftp_summary.txt` | Résumé : hosts scannés, accès anonyme, paths writables | — |

---

### `check_snmp.py` — SNMP UDP (161)

```bash
python3 check_snmp.py -t output/hosts_snmp.txt
python3 check_snmp.py -t 192.168.1.0/24 -c mycompany,snmpread
python3 check_snmp.py -t 10.10.10.5 --version 1,2c
```

Arguments supplémentaires : `-c` (community strings supplémentaires), `--version` (défaut : `1,2c`)

#### Ce que fait le script

**STEP 1 — Community string brute force**

Community strings testées par défaut :
```
public, private, community, manager, admin, secret, internal, cisco, router, switch, monitor, default
```
(+ les strings passées via `-c`)

Méthode principale : `onesixtyone -c <communities_file> -i <hosts_file>`
Parse `IP [community] <description>` dans la sortie.

Fallback si onesixtyone absent : `snmpwalk -v<version> -c <community> <ip> system` pour chaque IP × community × version.

**STEP 2 — Enumération système**

Pour chaque host accessible, exécute snmpwalk sur ces OIDs :
- `system` — sysDescr, sysName, sysLocation, sysContact
- `interfaces` — liste des interfaces réseau
- `hrSWRunName` — processus en cours
- `hrSWInstalledName` — logiciels installés
- `hrStorageTable` — volumes de stockage

Parse sysDescr et sysName pour le résumé.

**STEP 3 — OIDs Windows spécifiques**

- `1.3.6.1.4.1.77.1.2.25` — comptes utilisateurs Windows
- `1.3.6.1.4.1.77.1.4.2` — partages Windows

Sauvegardé dans `snmp_windows_users_<IP>.txt` si des données sont trouvées.

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `snmp_accessible.txt` | `IP \t community` pour chaque combinaison valide | ⚠️ |
| `snmp_data_<IP>.txt` | Dump snmpwalk complet par section (SYSTEM, INTERFACES, …) | — |
| `snmp_windows_users_<IP>.txt` | Users et shares Windows via OIDs propriétaires | ⚠️ |
| `snmp_summary.txt` | `Host / Community / sysName / sysDescr` par host accessible | — |

---

### `check_ipmi.py` — IPMI UDP (623)

```bash
python3 check_ipmi.py -t output/hosts_ipmi.txt
python3 check_ipmi.py -t 192.168.1.50 -u ADMIN -p ADMIN
```

Argument supplémentaire : `-u` accepte une liste de usernames séparés par des virgules (défaut : `ADMIN,admin,Administrator,root`)

#### Ce que fait le script

**STEP 1 — Présence IPMI**

`ipmitool -I lanplus -H <ip> -U '' -P '' -C 3 chassis status`
Détecte une réponse IPMI via mots-clés : `chassis`, `session`, `unauthorized`, `rakp`, `authentication`, `rmcp`, `error`.

**STEP 2 — Cipher Zero (CVE-2013-4786)**

`ipmitool -I lanplus -C 0 -H <ip> -U <user> -P anypassword chassis status`
Le cipher suite 0 désactive l'authentification — si la commande réussit et retourne `system power` ou `chassis` → host vulnérable.
Testé pour chaque username de la liste.

**STEP 3 — Auth anonyme / null**

Tente `user=''` et `user='anonymous'` avec `P=''`.
Succès si la sortie contient `system power`, `chassis`, ou `power state`.

**STEP 4 — RAKP hash capture**

Utilise `ipmipwner` si installé (hashes hashcat-ready avec `$rakp$`).
Sinon, `ipmitool -vvv` : cherche `rakp 2` dans la sortie et extrait les patterns hexadécimaux de 32+ chars comme matériau de hash.
Testé pour chaque username : ADMIN, admin, Administrator, root, USERID.

**STEP 5 — Creds par défaut**

8 combinaisons testées via `ipmitool chassis status` :
```
ADMIN:ADMIN        (Supermicro)
admin:admin        (iDRAC, iLO)
root:calvin        (Dell iDRAC)
USERID:PASSW0RD    (IBM IMM)
admin:password
Administrator:""
root:""
admin:""
```
Si `-u` et `-p` fournis, ces creds sont testés en priorité.

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `ipmi_hosts_info.txt` | `IP | present=True/False | output_brut` | — |
| `ipmi_cipher0.txt` | `[CRITICAL] IP VULNERABLE to cipher zero (user=...)` | 🔴 |
| `ipmi_anonymous.txt` | `[CRITICAL] IP ALLOWS anonymous/null authentication` | 🔴 |
| `ipmi_hashes.txt` | `[CRITICAL] IP | user=... | RAKP hash material` | 🔴 |
| `ipmi_default_creds.txt` | `[CRITICAL] IP | user:password` | 🔴 |
| `ipmi_summary.txt` | Compteurs : present, cipher0, anon, hashes, default creds | — |

---

### `check_winrm.py` — WinRM (5985/5986)

```bash
python3 check_winrm.py -t output/hosts_winrm.txt
python3 check_winrm.py -t output/hosts_winrm.txt -u jdoe -p 'P@ss' -d corp.local
```

Argument supplémentaire : `--port` (défaut : 5985)

#### Ce que fait le script

**STEP 1 — Détection + auth method (sans creds)**

- `nxc winrm <hosts>` — sweep général
- Pour chaque IP, `curl -sk http://<ip>:5985/wsman -D -` et `https://<ip>:5986/wsman` pour récupérer les headers
- Parse `WWW-Authenticate:` : `Negotiate` (Kerberos/NTLM), `Basic`, ou autre

**STEP 2 — Test authentification (avec creds)**

`nxc winrm <hosts> -u <user> -p <pass> -d <domain>`
Cherche `(Pwn3d!)`, `STATUS_SUCCESS`, ou `[+]` dans la sortie.

**STEP 3 — Exécution commandes (avec creds, si auth réussie)**

3 commandes via `nxc winrm -x` :
```
whoami /all   →  contexte utilisateur complet
hostname      →  nom de la machine
ipconfig /all →  config réseau
```

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `winrm_hosts_info.txt` | Sortie nxc brute + `IP:PORT [SCHEME] Auth=<method>` par header curl | — |
| `winrm_accessible.txt` | Sortie nxc complète + section `[CRITICAL] Successful authentications` | 🔴 |
| `winrm_cmd_results.txt` | Sortie des 3 commandes Windows par host accessible | 🔴 |
| `winrm_summary.txt` | Résumé : targets, creds utilisés, résultat auth | — |

---

### `check_kerberos.py` — Kerberos (88)

```bash
# Enum users + AS-REP sans creds
python3 check_kerberos.py -t output/hosts_kerberos.txt -d corp.local

# AS-REP + Kerberoast avec creds
python3 check_kerberos.py -t output/hosts_kerberos.txt -d corp.local -u jdoe -p 'P@ss'

# Avec liste d'utilisateurs connue (sortie check_ldap par exemple)
python3 check_kerberos.py -t output/hosts_kerberos.txt -d corp.local --users output/ldap/ldap_users.txt
```

Arguments supplémentaires : `--users` (fichier de usernames), `--wordlist` (wordlist pour user enum)

#### Ce que fait le script

**STEP 1 — Détection domaine**

`nxc smb <dc_ip>` et parse `domain:<value>` dans la sortie pour auto-détecter le domaine si `-d` non fourni.

**STEP 2 — Enumération utilisateurs (sans creds)**

Si `kerbrute` installé :
`kerbrute userenum --dc <dc_ip> -d <domain> <wordlist>`
Parse `VALID USERNAME:` dans la sortie.

Fallback impacket :
`GetNPUsers.py <domain>/ -dc-ip <dc_ip> -no-pass -usersfile <wordlist>`
Les users sans pré-auth génèrent un hash AS-REP, les autres génèrent une erreur parseable.

Wordlist intégrée (si `--wordlist` non fourni) : 30 usernames courants AD (administrator, admin, krbtgt, svc, helpdesk, backup, sql, exchange, sharepoint…)

**STEP 3 — AS-REP Roasting**

*Avec creds :* `nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --asreproast <outfile>`

*Sans creds (si user list disponible) :*
`GetNPUsers.py <domain>/ -dc-ip <dc_ip> -no-pass -usersfile <valid_users> -format hashcat`

**STEP 4 — Kerberoasting (avec creds uniquement)**

`nxc ldap <dc_ip> -u <user> -p <pass> -d <domain> --kerberoasting <outfile>`
Fallback : `GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc_ip> -request -format hashcat`

#### Fichiers de sortie

| Fichier | Contenu | Criticité |
|---|---|---|
| `krb_domain_info.txt` | Domaine détecté | — |
| `kerberos_valid_users.txt` | Usernames valides via Kerberos | — |
| `kerberos_asrep_hashes.txt` | Hashes AS-REP — cracking : `hashcat -m 18200` | 🔴 |
| `kerberos_spn_hashes.txt` | Hashes SPN — cracking : `hashcat -m 13100` | 🔴 |
| `kerberos_summary.txt` | Résumé : users trouvés, hashes capturés | — |
| `getnpusers_*_raw.txt` | Sortie brute GetNPUsers | — |
| `kerbrute_raw.txt` | Sortie brute kerbrute | — |

---

## Légende criticité

| Icône | Signification |
|---|---|
| 🔴 | Critique — à exploiter / documenter en priorité |
| ⚠️ | Important — à investiguer |

---

## Exemple de session complète

```bash
# 1. Discovery (root requis)
sudo python3 ad_recon_userless.py -t 10.10.0.0/24 -o /tmp/pentest -r 3000

# 2. Checks sans creds
python3 check_smb.py      -t /tmp/pentest/10.10.0.0_24/hosts_smb.txt     -o /tmp/pentest/smb
python3 check_ldap.py     -t /tmp/pentest/10.10.0.0_24/hosts_ldap.txt    -o /tmp/pentest/ldap
python3 check_kerberos.py -t /tmp/pentest/10.10.0.0_24/hosts_kerberos.txt -d corp.local -o /tmp/pentest/krb
python3 check_dns.py      -t /tmp/pentest/10.10.0.0_24/hosts_dns.txt     -d corp.local -o /tmp/pentest/dns
python3 check_http.py     -t /tmp/pentest/10.10.0.0_24/hosts_http.txt    -o /tmp/pentest/http
python3 check_mssql.py    -t /tmp/pentest/10.10.0.0_24/hosts_mssql.txt   -o /tmp/pentest/mssql
python3 check_ftp.py      -t /tmp/pentest/10.10.0.0_24/hosts_ftp.txt     -o /tmp/pentest/ftp
python3 check_snmp.py     -t /tmp/pentest/10.10.0.0_24/hosts_snmp.txt    -o /tmp/pentest/snmp
python3 check_ipmi.py     -t /tmp/pentest/10.10.0.0_24/hosts_ipmi.txt    -o /tmp/pentest/ipmi
python3 check_rdp.py      -t /tmp/pentest/10.10.0.0_24/hosts_rdp.txt     -o /tmp/pentest/rdp
python3 check_ssh.py      -t /tmp/pentest/10.10.0.0_24/hosts_ssh.txt     -o /tmp/pentest/ssh

# 3. Une fois des creds obtenus (default MSSQL, null bind LDAP, etc.)
python3 check_smb.py      -t /tmp/pentest/10.10.0.0_24/hosts_smb.txt -u jdoe -p 'P@ss' -d corp.local -o /tmp/pentest/smb_auth
python3 check_kerberos.py -t /tmp/pentest/10.10.0.0_24/hosts_kerberos.txt -d corp.local -u jdoe -p 'P@ss' -o /tmp/pentest/krb_auth
python3 check_ldap.py     -t /tmp/pentest/10.10.0.0_24/hosts_ldap.txt -u jdoe -p 'P@ss' -d corp.local -o /tmp/pentest/ldap_auth
python3 check_winrm.py    -t /tmp/pentest/10.10.0.0_24/hosts_winrm.txt -u jdoe -p 'P@ss' -d corp.local -o /tmp/pentest/winrm_auth
```
