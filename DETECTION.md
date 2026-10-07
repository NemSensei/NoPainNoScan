# Logique de détection — ce qui est remonté en « positif »

Référence de ce qui déclenche un **finding** dans chaque check, le fichier produit, et
la criticité affichée par `generate_report.py`. À jour après la passe anti-faux-positifs.

> Criticité rapport : 🔴 **critical** · ⚠️ **warning** · ℹ️ **info** (non remonté dans les bandeaux).

## Règle transverse nxc — `[+]` vs `(Pwn3d!)`/`(admin)`

Centralisée dans [`npns_common.py`](npns_common.py) :

| Helper | Vrai quand | Signification |
|---|---|---|
| `nxc_login_ok(line)` | la ligne contient `[+]` | creds **valides** — mais accès pas forcément exploitable |
| `nxc_is_admin(line)` | la ligne contient `(Pwn3d!)` **ou** `(admin)` | accès **privilégié réel** (session/exec/admin) |

`(Pwn3d!)` (nxc historique) et `(admin)` (builds récents) sont **tous deux** matchés → robuste aux updates Exegol.
**Jamais** traiter un simple `[+]` comme accès exploitable.

---

## Matrice de détection

### RDP — [`check_rdp.py`](check_rdp.py)
| Finding | Critère | Fichier | Crit. |
|---|---|---|---|
| Accès RDP interactif | ligne nxc avec `(Pwn3d!)`/`(admin)` | `rdp_login_success.txt` | 🔴 |
| Creds valides, session non garantie | `[+]` **sans** marqueur admin | `rdp_valid_creds.txt` | ℹ️ (non remonté) |
| NLA désactivé | `(nla:False)` dans la sortie | `rdp_no_nla.txt` | ⚠️ |

> **Corrigé** : avant, tout `[+]` partait dans `rdp_login_success.txt` → faux critique (creds OK mais droits « Remote Desktop Users » manquants).

### WinRM — [`check_winrm.py`](check_winrm.py)
| Finding | Critère | Fichier | Crit. |
|---|---|---|---|
| Shell WinRM (exec) | `(Pwn3d!)`/`(admin)` | `winrm_accessible.txt` | 🔴 |
| Creds valides, pas de shell | `[+]` sans marqueur | `winrm_valid_creds.txt` | ℹ️ |
| Brut nxc (troubleshooting) | — | `winrm_auth_raw.txt` | — |

> **Corrigé** : le `or "[+]"` annulait le filtre, et le dump complet dans `winrm_accessible.txt` faisait **toujours** remonter WinRM en critique. step3 (exec) ne tourne que sur les hôtes à accès réel.

### MSSQL — [`check_mssql.py`](check_mssql.py)
| Finding | Critère | Fichier | Crit. |
|---|---|---|---|
| Creds SA par défaut | `[+]` sur un couple par défaut | `mssql_default_creds.txt` | 🔴 |
| xp_cmdshell (RCE) | `(Pwn3d!)`/`(admin)` + sortie commande | `mssql_cmdexec.txt` | 🔴 |
| Instance accessible / data | `[+]`/`sysadmin`/`@@version` | `mssql_accessible.txt` | ℹ️ |
| Linked servers | lignes de `sys.servers` | `mssql_linked_servers.txt` | ⚠️ |

> **Corrigé** : xp_cmdshell ne se base plus sur `[+]` ou `"\\"` (qui ramassait la ligne d'auth et tout `DOMAIN\user`) mais sur le marqueur admin + la vraie sortie de `whoami`.
> **Note (laissé en l'état, non critique)** : `mssql_accessible.txt` reste verbeux (reprend la sortie des requêtes).

### IPMI — [`check_ipmi.py`](check_ipmi.py)
| Finding | Critère | Fichier | Crit. |
|---|---|---|---|
| Cipher Zero (CVE-2013-4786) | `chassis status` réussit avec `-C 0` | `ipmi_cipher0.txt` | 🔴 |
| Auth anonyme/null | `chassis status` réussit en `-U '' -P ''` | `ipmi_anonymous.txt` | 🔴 |
| Hash RAKP (crackable -m 7300) | ligne `$rakp$` **via ipmipwner uniquement** | `ipmi_hashes.txt` | 🔴 |
| Utilisateurs énumérés (≠ hash) | RAKP 2 sans « unauthorized name » (ipmitool) | `ipmi_users.txt` | ℹ️ |
| Creds par défaut | `chassis status` réussit avec couple par défaut | `ipmi_default_creds.txt` | 🔴 |

> **Corrigé** : `ipmitool -vvv` n'émet pas de hash crackable. Avant, tout `rakp 2` (y compris l'**erreur** « unauthorized name » = user inexistant) remontait un faux « RAKP hash captured [CRITICAL] » avec un pseudo-hash = hex arbitraire. L'énumération part désormais dans `ipmi_users.txt` (ℹ️), les hashes réels seulement via `ipmipwner`.

### HTTP — [`check_http.py`](check_http.py)
| Finding | Critère | Fichier | Crit. |
|---|---|---|---|
| ADCS / ESC8 candidate | `/certsrv/*` ou `/certenroll/` → **200 ou 401** | `http_adcs.txt` | 🔴 |
| WebDAV | en-tête `DAV:` / `Allow: PROPFIND` | `http_webdav.txt` | ⚠️ |
| OWA/RDWeb/ADFS/WSUS | chemins connus présents | `http_{owa,rdweb,adfs,wsus}.txt` | ℹ️ |

> **Corrigé** : `403` ne déclenche plus (un portail d'auth global renvoie 401/403 partout ≠ ADCS) ; `/adcs/` (pas un chemin ADCS par défaut) retiré. 401 = enrôlement NTLM = signal ESC8 fort.

### SMB — [`check_smb.py`](check_smb.py)
Flux : **1. recon** → **2. null session** → **3. shares** → **4. GPP**. Les steps 3 et 4
ne ciblent que les hôtes où l'auth réussit (reco step 1) → bien plus rapide sur gros scope.

| Finding | Critère | Fichier | Crit. |
|---|---|---|---|
| Hôtes joignables SMB | ligne `SMB <ip> <port>` au sweep | (dans `smb_hosts_info.txt`) | ℹ️ |
| Auth réussie (creds valides) | `[+]` au sweep authentifié | `smb_login_success.txt` | ℹ️ |
| Admin (creds) | `(Pwn3d!)`/`(admin)` au sweep | `smb_admin.txt` | ℹ️ |
| SMB signing désactivé | `(signing:False)` | `smb_unsigned.txt` | 🔴 |
| SMBv1 | `(SMBv1:True)` | `smb_v1.txt` | 🔴 |
| Partage inscriptible | share `READ,WRITE`/`WRITE` (hors `$`) | `smb_shares_write.txt` | 🔴 |
| Shares accessibles (R/W) | tout share non-`$` avec READ/WRITE (creds) | `smb_shares_accessible.txt` | ⚠️ |
| Null session | partages via session nulle | `smb_shares_null.txt` | ⚠️ |
| Creds GPP (SYSVOL) | `-M gpp_password`/`-M gpp_autologin` → ligne cred (hors négatives) | `sysvol_gpp.txt` (brut: `sysvol_gpp_raw.txt`) | 🔴 |

> Pas de faux positif admin (ne s'appuie pas sur `(Pwn3d!)` pour les shares). STEP 1-4 nettoient l'ANSI (`strip_ansi`) avant parsing et **excluent les partages `$`** des fichiers shares. Robustesse gros scope : `run_nxc()` redirige vers fichier, **tue le groupe de processus sur timeout et conserve la sortie partielle** (fini le « plus rien ne remonte »), timeouts scalés sur le nb d'hôtes, `--threads` transmis (défaut 100). **Spidering retiré volontairement** (`--spider` SYSVOL/NETLOGON + `-M spider_plus`) — trop bruyant ; GPP couvre les secrets SYSVOL, le reste se fait à la main. **⚠ Reste** : regex null-session fixée (plus de mauvais classement `READ,WRITE`).

### LDAP, Kerberos, SSH, DNS, SNMP, FTP
Détection inchangée sur cette passe (**en attente** selon ta consigne), sauf le bug SSH ci-dessous. Points connus à fiabiliser : Kerberos (suffixe realm qui casse la userlist AS-REP + clock-skew), LDAP (`rc==0` log succès sur bind échoué ; `--password-not-required` mal étiqueté « no_preauth »), SNMP (version de brute non réutilisée → énum vide), DNS (crash IPv6 `cidr_from_ip`), FTP (listing non borné / filtre trop large).

---

## Bug hors faux-positif corrigé aussi
- **SSH** [`check_ssh.py`](check_ssh.py) : fallback `nxc ssh {ip} -p {port}` → `--port {port}`. En nxc `-p` = **mot de passe**, pas le port.
