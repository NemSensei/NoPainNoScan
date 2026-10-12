# TODO

- [ ] LDAP : ajouter les OS obsolètes et les comptes Domain Admins
- [ ] Kerberos : voir si redondant avec ldap (asrep/kerberoast)
- [ ] FTP : affinage des interesting files (.txt retiré, reste à borner le listing)
- [ ] SMB/DC : grep du contenu des scripts sysvol (.ps1/.vbs/.bat) pour mdp en dur :voir comment adpeas trouve les secrets dans sysvol/netlogon
- [ ] afficher les commandes lancées (sortie + rapport, pour les pocs)
- [ ] timer d'avancement

## Nouveaux checks (dans l'esprit du projet)

### AD-core sans creds (priorité — pur esprit "userless", cf. AS-REP credless déjà en place)

- [ ] **Pre-Windows 2000 / mdp machine par défaut.** Comptes machine pré-créés
  dont le mot de passe = nom de machine en minuscules. `nxc ldap/smb --pre2k`
  ou l'outil `pre2k`. SANS creds → premier pied dans le domaine. C'est le check
  userless qui manque le plus. Potentiel : win direct fréquent, zéro bruit.
  (nouveau script `check_pre2k.py` ou étape dans check_ldap/check_smb).

- [ ] **Timeroasting.** Récupère des hashes de comptes machine via NTP
  (SAM-based), SANS aucun compte. `NetExec --timeroast` ou `timeroast.py`.
  Complète check_kerberos.py (même esprit "roasting sans creds" qu'AS-REP).
  Potentiel : hashes crackables obtenus avant tout accès.

- [ ] **Trusts domaine/forêt** dans check_ldap.py (avec creds). `trustAttributes`,
  SID filtering, trusts externes/bidirectionnels → chemins d'attaque inter-
  domaines. Complément naturel de la délégation déjà présente + BloodHound.
  Potentiel : finding classique de presta aujourd'hui absent.

### Fermer la boucle découverte → check (ports --exotic déjà scannés mais jamais sondés)

- [ ] **NFS (2049).** `showmount -e`, détection `no_root_squash`, montage des
  exports world-readable. Quasi systématique en interne. (--exotic trouve déjà
  le port, rien ne l'exploite).

- [ ] **Datastores non authentifiés.** Redis (`PING`/`INFO`), MongoDB
  (listDatabases), Elasticsearch (`/_cat/indices`), Memcached — tous en accès
  sans auth. Ports déjà découverts par --exotic. Potentiel : wins unauth rapides
  et fréquents. (regrouper dans un check_datastores.py ou un script par service).

- [ ] **VNC (5900/5901).** Absence d'auth / auth faible → accès graphique direct.
  Port déjà découvert par --exotic.

### Moderne, haute valeur

- [ ] **SCCM / MECM.** Distribution point, PXE, Network Access Account, relais
  client-push. `sccmhunter` / modules nxc. Absent aujourd'hui, de plus en plus
  central dans les ADs d'entreprise. Potentiel élevé.

- [ ] **ADCS ESC8 (web enrollment / relais HTTP).** check_http.py DÉTECTE déjà
  l'endpoint ADCS ; ajouter l'étape "relayable" (NTLM → /certsrv/). Faible
  effort, extension d'un check existant.

## Refactos (dette technique)

- [ ] **Consolider `run()` et `parse_targets()` dans `npns_common.py`.**
  État actuel : les 2 fonctions sont dupliquées dans les 14 `check_*.py`, et
  elles ont divergé — `check_smb.py` appelle la sienne `load_hosts` (vs
  `parse_targets` ailleurs), signatures incohérentes (`-> list`, `-> list[str]`,
  rien), et `run()` a un timeout par défaut différent selon le fichier
  (30/60/120/300/600). Le timeout n'impose PAS la duplication : c'est un arg par
  défaut, chaque appelant passe `run(cmd, timeout=N)` si besoin. Prendre la
  version `parse_targets` de `check_ldap.py` (la plus complète : fichier | IP |
  CIDR via `nmap -sL`) comme référence. Migration : ajouter les 2 fns dans
  `npns_common.py` → supprimer les defs locales + importer dans chaque script →
  renommer `load_hosts` en `parse_targets` → vérifier qu'aucun `def run(` /
  `def parse_targets(` / `def load_hosts(` ne subsiste dans les `check_*`.
  NE PAS toucher au `parse_targets` de `ad_recon_userless.py` (découverte
  masscan/fping, légitimement différent). Potentiel : 1 seul endroit à corriger
  au lieu de 14, supprime les corrections oubliées sur certains scripts,
  prérequis du passage futur en argv sans shell (point sécu).

- [ ] **Scinder les gros fichiers (collecte / rendu / logique par check).**
  `generate_report.py` (1223 l.) mélange 3 métiers : lire les sorties
  (`hosts_*.txt`, `*.json`), agréger/classer les findings, générer le HTML.
  Découper en `report/collect.py` (sorties → structures Python) + `report/
  render.py` (structures → HTML), `generate_report.py` devient le point
  d'entrée. Idem `check_ldap.py` (745 l.) et `check_dc.py` (657 l.) : isoler
  chaque sous-check (null bind, MachineAccountQuota, LAPS, AS-REP…) en une
  fonction pure testable. Potentiel : débloque les tests unitaires (parsing
  testable sans générer de HTML / sans réseau), limite les régressions quand on
  touche la mise en page ou un seul check. Priorité basse (confort de
  maintenance, pas un bug) — à faire conjointement avec l'ajout de tests.
