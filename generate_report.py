#!/usr/bin/env python3
"""
generate_report.py — HTML report from NoPainNoScan outputs

Usage:
    python3 generate_report.py -d <scan_dir> [-o report.html] [-n "Client Name"]

Scans <scan_dir> recursively for all NoPainNoScan output files and generates
a self-contained HTML report (no CDN, no external dependencies).
"""

import argparse
import html as _html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Utils
# ─────────────────────────────────────────────────────────────────────────────

def h(v) -> str:
    """HTML-escape a value."""
    return _html.escape(str(v))


def find_file(base: Path, name: str) -> Path | None:
    hits = sorted(base.rglob(name), key=lambda p: p.stat().st_mtime, reverse=True)
    return hits[0] if hits else None


def find_files(base: Path, pattern: str) -> list[Path]:
    return sorted(base.rglob(pattern))


def read_lines(path: Path | None) -> list[str]:
    if not path or not path.exists():
        return []
    return [
        l.strip() for l in path.read_text(errors="replace").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]


def jload(path: Path | None):
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Data collection
# ─────────────────────────────────────────────────────────────────────────────

def collect(base: Path) -> dict:
    d: dict = {}

    # Discovery
    d["alive"] = read_lines(find_file(base, "hosts_alive.txt"))
    svcs = ["dc", "smb", "ldap", "rdp", "winrm", "ssh", "http",
            "mssql", "dns", "kerberos", "ftp", "snmp", "ipmi"]
    d["by_service"] = {s: read_lines(find_file(base, f"hosts_{s}.txt")) for s in svcs}
    ps = jload(find_file(base, "ports_summary.json"))
    if ps:
        cnt = Counter(p for ports in ps.values() for p in ports)
        d["top_ports"] = cnt.most_common(15)
    else:
        d["top_ports"] = []

    # SMB
    d["smb"] = {
        "scanned": bool(find_file(base, "smb_hosts_info.txt") or find_file(base, "smb_unsigned.txt")),
        "unsigned":    read_lines(find_file(base, "smb_unsigned.txt")),
        "v1":          read_lines(find_file(base, "smb_v1.txt")),
        "null_shares": read_lines(find_file(base, "smb_shares_null.txt")),
        "read_shares": read_lines(find_file(base, "smb_shares_read.txt")),
        "write_shares":read_lines(find_file(base, "smb_shares_write.txt")),
        "sysvol":      read_lines(find_file(base, "sysvol_files.txt")),
        "spider":      read_lines(find_file(base, "smb_spider.txt")),
    }

    # LDAP
    user_files = find_files(base, "ldap_users_*.txt")
    grp_files  = find_files(base, "ldap_groups_*.txt")
    cmp_files  = find_files(base, "ldap_computers_*.txt")
    d["ldap"] = {
        "scanned":         bool(find_file(base, "ldap_nullbind.txt") or find_file(base, "ldap_domain_info.txt")),
        "nullbind":        read_lines(find_file(base, "ldap_nullbind.txt")),
        "no_preauth":      read_lines(find_file(base, "ldap_no_preauth.txt")),
        "delegation":      read_lines(find_file(base, "ldap_delegation.txt")),
        "users_count":     sum(len(read_lines(f)) for f in user_files),
        "groups_count":    sum(len(read_lines(f)) for f in grp_files),
        "computers_count": sum(len(read_lines(f)) for f in cmp_files),
        "users_sample":    read_lines(user_files[0])[:30] if user_files else [],
    }

    # RDP
    d["rdp"] = {
        "scanned":       bool(find_file(base, "rdp_results.txt") or find_file(base, "rdp_no_nla.txt")),
        "no_nla":        read_lines(find_file(base, "rdp_no_nla.txt")),
        "login_success": read_lines(find_file(base, "rdp_login_success.txt")),
        "results":       read_lines(find_file(base, "rdp_results.txt")),
    }

    # SSH
    d["ssh"] = {
        "scanned":       bool(find_file(base, "ssh_banners.txt")),
        "banners":       read_lines(find_file(base, "ssh_banners.txt")),
        "weak_algos":    read_lines(find_file(base, "ssh_weak_algos.txt")),
        "password_auth": read_lines(find_file(base, "ssh_password_auth.txt")),
        "login_success": read_lines(find_file(base, "ssh_login_success.txt")),
    }

    # HTTP
    d["http"] = {
        "scanned": bool(find_file(base, "http_titles.txt")),
        "titles":  read_lines(find_file(base, "http_titles.txt")),
        "adcs":    read_lines(find_file(base, "http_adcs.txt")),
        "webdav":  read_lines(find_file(base, "http_webdav.txt")),
        "owa":     read_lines(find_file(base, "http_owa.txt")),
        "rdweb":   read_lines(find_file(base, "http_rdweb.txt")),
        "adfs":    read_lines(find_file(base, "http_adfs.txt")),
        "wsus":    read_lines(find_file(base, "http_wsus.txt")),
    }

    # MSSQL
    d["mssql"] = {
        "scanned":       bool(find_file(base, "mssql_hosts_info.txt") or find_file(base, "mssql_accessible.txt")),
        "accessible":    read_lines(find_file(base, "mssql_accessible.txt")),
        "default_creds": read_lines(find_file(base, "mssql_default_creds.txt")),
        "cmdexec":       read_lines(find_file(base, "mssql_cmdexec.txt")),
        "linked":        read_lines(find_file(base, "mssql_linked_servers.txt")),
    }

    # DNS
    d["dns"] = {
        "scanned": bool(find_file(base, "dns_soa.txt")),
        "axfr":    read_lines(find_file(base, "dns_axfr_success.txt")),
        "hosts":   read_lines(find_file(base, "dns_hosts.txt")),
        "soa":     read_lines(find_file(base, "dns_soa.txt")),
    }

    # FTP
    d["ftp"] = {
        "scanned":       bool(find_file(base, "ftp_banners.txt") or find_file(base, "ftp_anonymous.txt")),
        "banners":       read_lines(find_file(base, "ftp_banners.txt")),
        "anonymous":     read_lines(find_file(base, "ftp_anonymous.txt")),
        "writable":      read_lines(find_file(base, "ftp_writable.txt")),
        "login_success": read_lines(find_file(base, "ftp_login_success.txt")),
    }

    # SNMP
    d["snmp"] = {
        "scanned":     bool(find_file(base, "snmp_accessible.txt")),
        "accessible":  read_lines(find_file(base, "snmp_accessible.txt")),
        "data_files":  find_files(base, "snmp_data_*.txt"),
    }

    # IPMI
    d["ipmi"] = {
        "scanned":       bool(find_file(base, "ipmi_hosts_info.txt") or find_file(base, "ipmi_cipher0.txt")),
        "cipher0":       read_lines(find_file(base, "ipmi_cipher0.txt")),
        "anonymous":     read_lines(find_file(base, "ipmi_anonymous.txt")),
        "hashes":        read_lines(find_file(base, "ipmi_hashes.txt")),
        "default_creds": read_lines(find_file(base, "ipmi_default_creds.txt")),
    }

    # WinRM
    d["winrm"] = {
        "scanned":     bool(find_file(base, "winrm_hosts_info.txt")),
        "hosts_info":  read_lines(find_file(base, "winrm_hosts_info.txt")),
        "accessible":  read_lines(find_file(base, "winrm_accessible.txt")),
    }

    # Kerberos
    d["kerberos"] = {
        "scanned":     bool(find_file(base, "kerberos_valid_users.txt") or find_file(base, "kerberos_asrep_hashes.txt")),
        "valid_users": read_lines(find_file(base, "kerberos_valid_users.txt")),
        "asrep":       read_lines(find_file(base, "kerberos_asrep_hashes.txt")),
        "spn":         read_lines(find_file(base, "kerberos_spn_hashes.txt")),
    }

    return d


def get_criticals(d: dict) -> list[tuple[str, str, str]]:
    """Return list of (service, message, level) tuples."""
    c = []
    smb = d["smb"]
    if smb["unsigned"]:    c.append(("SMB",      f"{len(smb['unsigned'])} hosts SMB signing disabled — NTLM relay possible", "critical"))
    if smb["v1"]:          c.append(("SMB",      f"{len(smb['v1'])} hosts with SMBv1 enabled (EternalBlue)", "critical"))
    if smb["write_shares"]:c.append(("SMB",      f"{len(smb['write_shares'])} writable shares found", "critical"))
    if smb["sysvol"]:      c.append(("SMB",      f"{len(smb['sysvol'])} interesting files in SYSVOL/NETLOGON", "warning"))

    ldap = d["ldap"]
    if ldap["nullbind"]:   c.append(("LDAP",     f"{len(ldap['nullbind'])} hosts allow anonymous LDAP bind", "critical"))
    if ldap["no_preauth"]: c.append(("LDAP",     f"{len(ldap['no_preauth'])} accounts without Kerberos pre-auth (AS-REP roastable)", "critical"))
    if ldap["delegation"]: c.append(("LDAP",     f"{len(ldap['delegation'])} accounts with unconstrained delegation", "critical"))

    rdp = d["rdp"]
    if rdp["no_nla"]:         c.append(("RDP",   f"{len(rdp['no_nla'])} hosts without NLA", "warning"))
    if rdp["login_success"]:  c.append(("RDP",   f"{len(rdp['login_success'])} successful RDP logins", "critical"))

    ssh = d["ssh"]
    if ssh["login_success"]:  c.append(("SSH",   f"{len(ssh['login_success'])} successful SSH logins", "critical"))
    if ssh["weak_algos"]:     c.append(("SSH",   f"{len(ssh['weak_algos'])} hosts with weak SSH algorithms", "warning"))

    http = d["http"]
    if http["adcs"]:          c.append(("HTTP",  f"{len(http['adcs'])} ADCS endpoints detected — ESC* attacks", "critical"))
    if http["webdav"]:        c.append(("HTTP",  f"{len(http['webdav'])} hosts with WebDAV enabled", "warning"))

    mssql = d["mssql"]
    if mssql["default_creds"]:c.append(("MSSQL", f"{len(mssql['default_creds'])} hosts with default credentials", "critical"))
    if mssql["cmdexec"]:      c.append(("MSSQL", f"{len(mssql['cmdexec'])} hosts with xp_cmdshell enabled (RCE)", "critical"))

    if d["dns"]["axfr"]:      c.append(("DNS",   f"{len(d['dns']['axfr'])} successful zone transfer(s)", "critical"))

    ftp = d["ftp"]
    if ftp["anonymous"]:      c.append(("FTP",   f"{len(ftp['anonymous'])} hosts with anonymous FTP access", "critical"))
    if ftp["writable"]:       c.append(("FTP",   f"{len(ftp['writable'])} writable FTP paths", "critical"))

    if d["snmp"]["accessible"]:c.append(("SNMP", f"{len(d['snmp']['accessible'])} hosts accessible via SNMP", "critical"))

    ipmi = d["ipmi"]
    if ipmi["cipher0"]:       c.append(("IPMI",  f"{len(ipmi['cipher0'])} hosts vulnerable to cipher zero", "critical"))
    if ipmi["hashes"]:        c.append(("IPMI",  f"{len(ipmi['hashes'])} RAKP hashes captured (hashcat -m 7300)", "critical"))
    if ipmi["default_creds"]: c.append(("IPMI",  f"{len(ipmi['default_creds'])} hosts with default IPMI credentials", "critical"))
    if ipmi["anonymous"]:     c.append(("IPMI",  f"{len(ipmi['anonymous'])} hosts with anonymous IPMI auth", "critical"))

    if d["winrm"]["accessible"]:c.append(("WinRM",f"{len(d['winrm']['accessible'])} hosts accessible via WinRM", "critical"))

    krb = d["kerberos"]
    if krb["asrep"]:          c.append(("Kerberos", f"{len(krb['asrep'])} AS-REP hashes captured (hashcat -m 18200)", "critical"))
    if krb["spn"]:            c.append(("Kerberos", f"{len(krb['spn'])} Kerberoast hashes captured (hashcat -m 13100)", "critical"))

    return c


# ─────────────────────────────────────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────────────────────────────────────

def badge(level: str) -> str:
    icons = {"critical": "⚠", "warning": "⚠", "ok": "✓", "info": "ℹ", "skip": "–"}
    return f'<span class="badge bdg-{level}">{icons.get(level,"")} {level.upper()}</span>'


def stat_card(value, label: str, level: str = "info") -> str:
    return (f'<div class="stat-card sc-{level}">'
            f'<div class="sc-val">{h(str(value))}</div>'
            f'<div class="sc-lbl">{h(label)}</div>'
            f'</div>')


def ip_table(items: list[str], col: str = "IP / Host", limit: int = 300) -> str:
    if not items:
        return '<p class="empty">No entries.</p>'
    rows = "".join(f"<tr><td>{h(i)}</td></tr>" for i in items[:limit])
    extra = (f'<tr><td class="more">… {len(items)-limit} more</td></tr>'
             if len(items) > limit else "")
    return (f'<table><thead><tr><th>{h(col)}</th></tr></thead>'
            f'<tbody>{rows}{extra}</tbody></table>')


def text_table(items: list[str], col: str = "Value", limit: int = 300) -> str:
    return ip_table(items, col, limit)


def two_col(rows: list[tuple], h1: str, h2: str) -> str:
    if not rows:
        return '<p class="empty">No entries.</p>'
    body = "".join(f"<tr><td>{h(a)}</td><td>{h(b)}</td></tr>" for a, b in rows)
    return (f'<table><thead><tr><th>{h(h1)}</th><th>{h(h2)}</th></tr></thead>'
            f'<tbody>{body}</tbody></table>')


def raw_block(items: list[str], limit: int = 100) -> str:
    if not items:
        return ""
    shown = "\n".join(items[:limit])
    extra = f"\n… {len(items)-limit} more lines" if len(items) > limit else ""
    uid = f"raw_{id(items)}"
    return (f'<button class="raw-toggle" onclick="toggleRaw(\'{uid}\')">Show raw ({len(items)} lines)</button>'
            f'<pre class="raw-pre" id="{uid}">{h(shown+extra)}</pre>')


def subsec(title: str, content: str, level: str = "") -> str:
    bdg = f' {badge(level)}' if level else ""
    return (f'<div class="subsec">'
            f'<div class="subsec-title">{h(title)}{bdg}</div>'
            f'{content}'
            f'</div>')


def section_wrap(sid: str, title: str, icon: str, lvl: str, scanned: bool, body: str) -> str:
    bdg = badge("skip") if not scanned else badge(lvl)
    dot = f'<span class="dot dot-{lvl}"></span>' if scanned else '<span class="dot dot-skip"></span>'
    return (f'<section class="card" id="{h(sid)}">'
            f'<div class="card-head" onclick="toggle(\'{h(sid)}\')">'
            f'<span class="card-icon">{icon}</span>'
            f'<span class="card-title">{h(title)}</span>'
            f'{bdg}'
            f'<span class="chevron" id="chev-{h(sid)}">▾</span>'
            f'</div>'
            f'<div class="card-body" id="body-{h(sid)}">{body}</div>'
            f'</section>')


def nav_item(sid: str, label: str, lvl: str, scanned: bool) -> str:
    dot_class = f"dot-{lvl}" if scanned else "dot-skip"
    return (f'<a href="#{h(sid)}" class="nav-item">'
            f'<span class="nav-dot {dot_class}"></span>'
            f'{h(label)}</a>')


# ─────────────────────────────────────────────────────────────────────────────
# Section builders
# ─────────────────────────────────────────────────────────────────────────────

def svc_level(findings: list, warn_findings: list = None) -> str:
    if findings:
        return "critical"
    if warn_findings:
        return "warning"
    return "ok"


def build_discovery(d: dict) -> str:
    alive = d["alive"]
    svc   = d["by_service"]
    parts = []

    # Stat row
    stats_html = '<div class="stat-row">'
    stats_html += stat_card(len(alive), "Hosts Alive", "info" if alive else "skip")
    for name, label in [("dc","DCs"), ("smb","SMB"), ("ldap","LDAP"), ("rdp","RDP"),
                         ("ssh","SSH"), ("http","HTTP/S"), ("mssql","MSSQL"),
                         ("ftp","FTP"), ("snmp","SNMP"), ("ipmi","IPMI"),
                         ("winrm","WinRM"), ("kerberos","Kerberos")]:
        cnt = len(svc.get(name, []))
        lvl = "info" if cnt else "skip"
        stats_html += stat_card(cnt, label, lvl)
    stats_html += '</div>'
    parts.append(stats_html)

    # DC list
    if svc.get("dc"):
        parts.append(subsec("Domain Controllers detected", ip_table(svc["dc"]), "info"))

    # Top ports
    if d["top_ports"]:
        rows = [(port, f"{cnt} hosts") for port, cnt in d["top_ports"]]
        parts.append(subsec("Top open ports", two_col(rows, "Port", "Count")))

    if not alive:
        parts.append('<p class="empty">No discovery output found. Run ad_recon_userless.py first.</p>')

    return "".join(parts)


def build_smb(d: dict) -> str:
    s = d["smb"]
    parts = []

    unsigned_lvl = "critical" if s["unsigned"] else "ok"
    v1_lvl       = "critical" if s["v1"]       else "ok"
    write_lvl    = "critical" if s["write_shares"] else "ok"
    sysvol_lvl   = "warning"  if s["sysvol"]   else "ok"

    parts.append(subsec(f"SMB Signing disabled ({len(s['unsigned'])} hosts)",
                        ip_table(s["unsigned"]) if s["unsigned"] else '<p class="empty">All hosts have SMB signing enabled.</p>',
                        unsigned_lvl))

    parts.append(subsec(f"SMBv1 enabled ({len(s['v1'])} hosts)",
                        ip_table(s["v1"]) if s["v1"] else '<p class="empty">No hosts with SMBv1 detected.</p>',
                        v1_lvl))

    if s["null_shares"]:
        parts.append(subsec(f"Null session shares ({len(s['null_shares'])} entries)",
                            text_table(s["null_shares"], "Share / Access"), "warning"))

    parts.append(subsec(f"Writable shares ({len(s['write_shares'])} entries)",
                        text_table(s["write_shares"], "Share") if s["write_shares"]
                        else '<p class="empty">No writable shares found.</p>',
                        write_lvl))

    if s["read_shares"]:
        parts.append(subsec(f"Readable shares ({len(s['read_shares'])} entries)",
                            text_table(s["read_shares"], "Share"), "info"))

    if s["sysvol"] or s["spider"]:
        combined = list(dict.fromkeys(s["sysvol"] + s["spider"]))
        parts.append(subsec(f"SYSVOL / Spider findings ({len(combined)} files)",
                            text_table(combined, "File path"), sysvol_lvl))

    return "".join(parts)


def build_ldap(d: dict) -> str:
    s = d["ldap"]
    parts = []

    nb_lvl  = "critical" if s["nullbind"]   else "ok"
    pra_lvl = "critical" if s["no_preauth"] else "ok"
    del_lvl = "critical" if s["delegation"] else "ok"

    # Stats
    stats = '<div class="stat-row">'
    stats += stat_card(s["users_count"],    "Users found",     "info" if s["users_count"] else "skip")
    stats += stat_card(s["groups_count"],   "Groups found",    "info" if s["groups_count"] else "skip")
    stats += stat_card(s["computers_count"],"Computers found", "info" if s["computers_count"] else "skip")
    stats += '</div>'
    parts.append(stats)

    parts.append(subsec(f"Anonymous LDAP bind ({len(s['nullbind'])} hosts)",
                        ip_table(s["nullbind"]) if s["nullbind"]
                        else '<p class="empty">No anonymous bind allowed.</p>',
                        nb_lvl))

    parts.append(subsec(f"Accounts without Kerberos pre-auth ({len(s['no_preauth'])})",
                        text_table(s["no_preauth"], "Account") if s["no_preauth"]
                        else '<p class="empty">No accounts without pre-auth found.</p>',
                        pra_lvl))

    parts.append(subsec(f"Unconstrained delegation ({len(s['delegation'])} accounts)",
                        text_table(s["delegation"], "Account") if s["delegation"]
                        else '<p class="empty">No delegation accounts found.</p>',
                        del_lvl))

    if s["users_sample"]:
        parts.append(subsec(f"User sample (first {len(s['users_sample'])})",
                            text_table(s["users_sample"], "Username"), "info"))

    return "".join(parts)


def build_rdp(d: dict) -> str:
    s = d["rdp"]
    parts = []

    nla_lvl  = "warning"  if s["no_nla"]        else "ok"
    auth_lvl = "critical" if s["login_success"]  else "info"

    parts.append(subsec(f"Hosts without NLA ({len(s['no_nla'])})",
                        ip_table(s["no_nla"]) if s["no_nla"]
                        else '<p class="empty">All hosts have NLA enabled.</p>',
                        nla_lvl))

    parts.append(subsec(f"Successful logins ({len(s['login_success'])})",
                        text_table(s["login_success"], "Host / Credentials") if s["login_success"]
                        else '<p class="empty">No successful RDP logins.</p>',
                        auth_lvl))

    if s["results"]:
        parts.append(subsec(f"Full results ({len(s['results'])} lines)",
                            raw_block(s["results"])))

    return "".join(parts)


def build_ssh(d: dict) -> str:
    s = d["ssh"]
    parts = []

    stats = '<div class="stat-row">'
    stats += stat_card(len(s["banners"]), "Hosts with SSH", "info" if s["banners"] else "skip")
    stats += stat_card(len(s["weak_algos"]), "Weak algorithms", "warning" if s["weak_algos"] else "ok")
    stats += stat_card(len(s["password_auth"]), "Password auth enabled", "warning" if s["password_auth"] else "ok")
    stats += stat_card(len(s["login_success"]), "Successful logins", "critical" if s["login_success"] else "ok")
    stats += '</div>'
    parts.append(stats)

    if s["banners"]:
        parts.append(subsec("SSH banners / versions", text_table(s["banners"], "IP — Banner"), "info"))

    if s["weak_algos"]:
        parts.append(subsec(f"Hosts with weak algorithms ({len(s['weak_algos'])})",
                            ip_table(s["weak_algos"]), "warning"))

    if s["password_auth"]:
        parts.append(subsec("Password authentication enabled", ip_table(s["password_auth"]), "warning"))

    if s["login_success"]:
        parts.append(subsec("Successful logins", text_table(s["login_success"], "Host / Credentials"), "critical"))

    return "".join(parts)


def build_http(d: dict) -> str:
    s = d["http"]
    parts = []

    stats = '<div class="stat-row">'
    stats += stat_card(len(s["titles"]), "Web services", "info" if s["titles"] else "skip")
    stats += stat_card(len(s["adcs"]),   "ADCS endpoints", "critical" if s["adcs"] else "ok")
    stats += stat_card(len(s["webdav"]), "WebDAV hosts",   "warning"  if s["webdav"] else "ok")
    for svc in ["owa", "rdweb", "adfs", "wsus"]:
        cnt = len(s[svc])
        stats += stat_card(cnt, svc.upper(), "info" if cnt else "skip")
    stats += '</div>'
    parts.append(stats)

    if s["adcs"]:
        parts.append(subsec(f"ADCS endpoints ({len(s['adcs'])})",
                            text_table(s["adcs"], "URL"), "critical"))

    if s["webdav"]:
        parts.append(subsec(f"WebDAV enabled ({len(s['webdav'])} hosts)",
                            ip_table(s["webdav"]), "warning"))

    for svc, label in [("owa","OWA"), ("rdweb","RDWeb"), ("adfs","ADFS"), ("wsus","WSUS")]:
        if s[svc]:
            parts.append(subsec(f"{label} detected ({len(s[svc])} endpoints)",
                                text_table(s[svc], "URL"), "info"))

    if s["titles"]:
        parts.append(subsec(f"All web services ({len(s['titles'])})",
                            text_table(s["titles"], "URL — Title — Server"), "info"))

    return "".join(parts)


def build_mssql(d: dict) -> str:
    s = d["mssql"]
    parts = []

    stats = '<div class="stat-row">'
    stats += stat_card(len(s["accessible"]),    "Accessible instances", "info"     if s["accessible"]    else "skip")
    stats += stat_card(len(s["default_creds"]), "Default creds",        "critical" if s["default_creds"] else "ok")
    stats += stat_card(len(s["cmdexec"]),        "xp_cmdshell (RCE)",   "critical" if s["cmdexec"]       else "ok")
    stats += stat_card(len(s["linked"]),         "Linked servers",       "warning"  if s["linked"]        else "ok")
    stats += '</div>'
    parts.append(stats)

    if s["default_creds"]:
        parts.append(subsec("Default credentials working", text_table(s["default_creds"], "Host — Credentials"), "critical"))
    if s["cmdexec"]:
        parts.append(subsec("xp_cmdshell enabled (RCE)", text_table(s["cmdexec"], "Host / Output"), "critical"))
    if s["linked"]:
        parts.append(subsec("Linked servers", text_table(s["linked"], "Server"), "warning"))
    if s["accessible"]:
        parts.append(subsec("Accessible instances", ip_table(s["accessible"]), "info"))

    return "".join(parts)


def build_dns(d: dict) -> str:
    s = d["dns"]
    parts = []

    axfr_lvl  = "critical" if s["axfr"]  else "ok"

    if s["soa"]:
        parts.append(subsec("Detected domains (SOA)", text_table(s["soa"], "Domain"), "info"))

    parts.append(subsec(f"Zone transfers successful ({len(s['axfr'])})",
                        text_table(s["axfr"], "Server — Domain") if s["axfr"]
                        else '<p class="empty">No zone transfers possible.</p>',
                        axfr_lvl))

    if s["hosts"]:
        parts.append(subsec(f"Discovered hostnames ({len(s['hosts'])})",
                            text_table(s["hosts"], "FQDN — IP"), "info"))

    return "".join(parts)


def build_ftp(d: dict) -> str:
    s = d["ftp"]
    parts = []

    stats = '<div class="stat-row">'
    stats += stat_card(len(s["banners"]),       "FTP servers",        "info"     if s["banners"]       else "skip")
    stats += stat_card(len(s["anonymous"]),     "Anonymous access",   "critical" if s["anonymous"]     else "ok")
    stats += stat_card(len(s["writable"]),      "Writable paths",     "critical" if s["writable"]      else "ok")
    stats += stat_card(len(s["login_success"]), "Credential success", "critical" if s["login_success"] else "ok")
    stats += '</div>'
    parts.append(stats)

    if s["anonymous"]:
        parts.append(subsec("Anonymous access allowed", ip_table(s["anonymous"]), "critical"))
    if s["writable"]:
        parts.append(subsec("Writable paths", text_table(s["writable"], "Host:Path"), "critical"))
    if s["login_success"]:
        parts.append(subsec("Credential logins", text_table(s["login_success"], "Host"), "critical"))
    if s["banners"]:
        parts.append(subsec("FTP banners", text_table(s["banners"], "IP — Banner"), "info"))

    return "".join(parts)


def build_snmp(d: dict) -> str:
    s = d["snmp"]
    parts = []

    lvl = "critical" if s["accessible"] else "ok"
    parts.append(subsec(f"Accessible via SNMP ({len(s['accessible'])} hosts)",
                        text_table(s["accessible"], "IP — Community") if s["accessible"]
                        else '<p class="empty">No SNMP community strings found.</p>',
                        lvl))

    if s["data_files"]:
        names = [f.name for f in s["data_files"]]
        parts.append(subsec(f"SNMP data files ({len(names)})",
                            text_table(names, "File"), "info"))

    return "".join(parts)


def build_ipmi(d: dict) -> str:
    s = d["ipmi"]
    parts = []

    stats = '<div class="stat-row">'
    stats += stat_card(len(s["cipher0"]),       "Cipher Zero vuln",   "critical" if s["cipher0"]       else "ok")
    stats += stat_card(len(s["anonymous"]),     "Anonymous auth",     "critical" if s["anonymous"]     else "ok")
    stats += stat_card(len(s["hashes"]),        "RAKP hashes",        "critical" if s["hashes"]        else "ok")
    stats += stat_card(len(s["default_creds"]), "Default credentials","critical" if s["default_creds"] else "ok")
    stats += '</div>'
    parts.append(stats)

    if s["cipher0"]:
        parts.append(subsec("Cipher Zero (auth bypass) — CVE-2013-4786",
                            ip_table(s["cipher0"]), "critical"))
    if s["anonymous"]:
        parts.append(subsec("Anonymous authentication allowed",
                            ip_table(s["anonymous"]), "critical"))
    if s["hashes"]:
        parts.append(subsec(f"RAKP hashes captured ({len(s['hashes'])}) — hashcat -m 7300",
                            text_table(s["hashes"], "Hash"), "critical"))
    if s["default_creds"]:
        parts.append(subsec("Default credentials working",
                            text_table(s["default_creds"], "Host — User:Pass"), "critical"))

    return "".join(parts)


def build_winrm(d: dict) -> str:
    s = d["winrm"]
    parts = []

    lvl = "critical" if s["accessible"] else "info"
    if s["hosts_info"]:
        parts.append(subsec(f"WinRM hosts detected ({len(s['hosts_info'])} entries)",
                            raw_block(s["hosts_info"]), "info"))
    parts.append(subsec(f"Authenticated access ({len(s['accessible'])} hosts)",
                        text_table(s["accessible"], "Host / Result") if s["accessible"]
                        else '<p class="empty">No successful WinRM authentication.</p>',
                        lvl))
    return "".join(parts)


def build_kerberos(d: dict) -> str:
    s = d["kerberos"]
    parts = []

    stats = '<div class="stat-row">'
    stats += stat_card(len(s["valid_users"]), "Valid users",       "info"     if s["valid_users"] else "skip")
    stats += stat_card(len(s["asrep"]),       "AS-REP hashes",    "critical" if s["asrep"]       else "ok")
    stats += stat_card(len(s["spn"]),         "Kerberoast hashes","critical" if s["spn"]         else "ok")
    stats += '</div>'
    parts.append(stats)

    if s["valid_users"]:
        parts.append(subsec(f"Valid users enumerated ({len(s['valid_users'])})",
                            text_table(s["valid_users"], "Username"), "info"))
    if s["asrep"]:
        parts.append(subsec(f"AS-REP hashes ({len(s['asrep'])}) — hashcat -m 18200",
                            text_table(s["asrep"], "Hash"), "critical"))
    if s["spn"]:
        parts.append(subsec(f"Kerberoast hashes ({len(s['spn'])}) — hashcat -m 13100",
                            text_table(s["spn"], "Hash"), "critical"))

    return "".join(parts)


def section_level(d: dict, key: str) -> str:
    """Compute the top-level badge for a service section."""
    crits = get_criticals(d)
    labels = {c[0] for c in crits if c[2] == "critical"}
    warns  = {c[0] for c in crits if c[2] == "warning"}
    svc_map = {
        "smb": "SMB", "ldap": "LDAP", "rdp": "RDP", "ssh": "SSH",
        "http": "HTTP", "mssql": "MSSQL", "dns": "DNS", "ftp": "FTP",
        "snmp": "SNMP", "ipmi": "IPMI", "winrm": "WinRM", "kerberos": "Kerberos",
    }
    label = svc_map.get(key, key)
    if label in labels:
        return "critical"
    if label in warns:
        return "warning"
    if d[key]["scanned"]:
        return "ok"
    return "skip"


# ─────────────────────────────────────────────────────────────────────────────
# HTML generation
# ─────────────────────────────────────────────────────────────────────────────

CSS = """
:root {
  --bg:#f0f4f8; --card:#fff; --sidebar:#0d1117; --stext:#8b949e;
  --crit:#ef4444; --warn:#f59e0b; --ok:#22c55e; --info:#3b82f6;
  --skip:#6b7280; --border:#e2e8f0; --text:#1e293b; --muted:#64748b;
  --radius:10px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);display:flex;min-height:100vh}

/* ── Sidebar ── */
.sidebar{width:220px;min-height:100vh;background:var(--sidebar);position:fixed;top:0;left:0;overflow-y:auto;display:flex;flex-direction:column}
.sb-logo{padding:1.25rem 1rem 1rem;border-bottom:1px solid #21262d}
.sb-logo h1{color:#fff;font-size:.95rem;font-weight:700}
.sb-logo p{color:var(--stext);font-size:.7rem;margin-top:.2rem}
.sb-sep{padding:.6rem 1rem .2rem;font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#484f58}
.nav-item{display:flex;align-items:center;gap:.5rem;color:var(--stext);text-decoration:none;padding:.35rem 1rem;font-size:.78rem;transition:background .1s,color .1s}
.nav-item:hover{background:#161b22;color:#fff}
.nav-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.dot-critical{background:var(--crit)}.dot-warning{background:var(--warn)}
.dot-ok{background:var(--ok)}.dot-info{background:var(--info)}.dot-skip{background:#374151}

/* ── Main ── */
.main{margin-left:220px;flex:1;padding:1.5rem}

/* ── Report header ── */
.rpt-header{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-radius:var(--radius);padding:1.75rem 2rem;color:#fff;margin-bottom:1.5rem;display:flex;justify-content:space-between;align-items:flex-end}
.rpt-header h1{font-size:1.3rem;font-weight:700;margin-bottom:.25rem}
.rpt-header .meta{font-size:.75rem;color:#94a3b8}
.rpt-header .meta span{display:block}
.rpt-logo{font-size:2.5rem;opacity:.6}

/* ── Stat row ── */
.stat-row{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:1.25rem}
.stat-card{background:var(--card);border-radius:8px;padding:.9rem 1rem;min-width:110px;border-top:3px solid var(--info);box-shadow:0 1px 3px rgba(0,0,0,.06)}
.stat-card.sc-critical{border-top-color:var(--crit)}.stat-card.sc-warning{border-top-color:var(--warn)}
.stat-card.sc-ok{border-top-color:var(--ok)}.stat-card.sc-skip{border-top-color:#374151;opacity:.6}
.sc-val{font-size:1.6rem;font-weight:700;line-height:1}
.sc-lbl{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-top:.2rem}

/* ── Critical banner ── */
.crit-banner{background:#fff1f2;border:1px solid #fecdd3;border-radius:var(--radius);padding:1.25rem 1.5rem;margin-bottom:1.5rem}
.crit-banner h2{color:#b91c1c;font-size:.95rem;margin-bottom:.75rem;display:flex;align-items:center;gap:.4rem}
.crit-item{display:flex;align-items:center;gap:.5rem;padding:.3rem 0;font-size:.8rem;color:#7f1d1d;border-bottom:1px solid #fee2e2}
.crit-item:last-child{border:none}
.crit-svc{font-weight:700;min-width:70px}
.warn-banner{background:#fffbeb;border:1px solid #fde68a;border-radius:var(--radius);padding:1.25rem 1.5rem;margin-bottom:1.5rem}
.warn-banner h2{color:#92400e;font-size:.95rem;margin-bottom:.75rem}
.warn-item{display:flex;align-items:center;gap:.5rem;padding:.3rem 0;font-size:.8rem;color:#78350f;border-bottom:1px solid #fde68a}
.warn-item:last-child{border:none}
.warn-svc{font-weight:700;min-width:70px}

/* ── Cards (sections) ── */
.card{background:var(--card);border-radius:var(--radius);margin-bottom:1rem;box-shadow:0 1px 3px rgba(0,0,0,.07);overflow:hidden}
.card-head{display:flex;align-items:center;gap:.6rem;padding:1rem 1.25rem;cursor:pointer;user-select:none;border-bottom:1px solid var(--border)}
.card-head:hover{background:#f8fafc}
.card-icon{font-size:1.1rem}
.card-title{flex:1;font-weight:600;font-size:.9rem}
.chevron{color:var(--muted);transition:transform .2s;font-size:.8rem}
.card-body{padding:1.25rem;display:block}
.card-body.collapsed{display:none}

/* ── Badge ── */
.badge{font-size:.65rem;font-weight:700;padding:.15rem .5rem;border-radius:99px;text-transform:uppercase;letter-spacing:.04em}
.bdg-critical{background:#fee2e2;color:#b91c1c}.bdg-warning{background:#fef3c7;color:#92400e}
.bdg-ok{background:#dcfce7;color:#15803d}.bdg-info{background:#dbeafe;color:#1d4ed8}
.bdg-skip{background:#f1f5f9;color:var(--muted)}

/* ── Subsections ── */
.subsec{margin-bottom:1.1rem;padding-bottom:1.1rem;border-bottom:1px solid var(--border)}
.subsec:last-child{border:none;margin-bottom:0;padding-bottom:0}
.subsec-title{font-size:.8rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:.6rem;display:flex;align-items:center;gap:.4rem}

/* ── Tables ── */
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{background:#f8fafc;padding:.45rem .6rem;text-align:left;font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:2px solid var(--border)}
td{padding:.4rem .6rem;border-bottom:1px solid #f1f5f9;font-family:monospace;word-break:break-all}
tr:last-child td{border:none}
tr:hover td{background:#f8fafc}
.more{color:var(--muted);font-style:italic;font-family:inherit}

/* ── Raw block ── */
.raw-toggle{font-size:.7rem;color:var(--info);background:none;border:1px solid var(--border);padding:.2rem .6rem;border-radius:4px;cursor:pointer;margin-top:.4rem}
.raw-toggle:hover{background:var(--bg)}
.raw-pre{display:none;background:#0d1117;color:#94a3b8;font-family:monospace;font-size:.7rem;padding:.75rem;border-radius:6px;margin-top:.5rem;max-height:280px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}

/* ── Misc ── */
.empty{color:var(--muted);font-style:italic;font-size:.8rem}
@media(max-width:768px){.sidebar{display:none}.main{margin-left:0}}
"""

JS = """
function toggle(id) {
  const body = document.getElementById('body-' + id);
  const chev = document.getElementById('chev-' + id);
  if (body.classList.contains('collapsed')) {
    body.classList.remove('collapsed');
    chev.textContent = '▾';
  } else {
    body.classList.add('collapsed');
    chev.textContent = '▸';
  }
}
function toggleRaw(id) {
  const el = document.getElementById(id);
  el.style.display = el.style.display === 'block' ? 'none' : 'block';
}
"""


def generate_html(d: dict, crits: list, engagement: str, base_dir: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Sidebar nav ────────────────────────────────────────────────────────────
    sections_meta = [
        ("discovery", "🌐 Discovery",   "info"),
        ("smb",       "📁 SMB",         section_level(d, "smb")),
        ("ldap",      "📂 LDAP",        section_level(d, "ldap")),
        ("kerberos",  "🎟 Kerberos",    section_level(d, "kerberos")),
        ("rdp",       "🖥 RDP",         section_level(d, "rdp")),
        ("ssh",       "🔐 SSH",         section_level(d, "ssh")),
        ("http",      "🌍 HTTP/S",      section_level(d, "http")),
        ("mssql",     "🗄 MSSQL",       section_level(d, "mssql")),
        ("dns",       "🔎 DNS",         section_level(d, "dns")),
        ("ftp",       "📤 FTP",         section_level(d, "ftp")),
        ("snmp",      "📡 SNMP",        section_level(d, "snmp")),
        ("ipmi",      "⚙ IPMI",        section_level(d, "ipmi")),
        ("winrm",     "💻 WinRM",       section_level(d, "winrm")),
    ]

    nav_items = ""
    for sid, label, lvl in sections_meta:
        scanned = sid == "discovery" or (sid in d and d[sid].get("scanned", False))
        nav_items += nav_item(sid, label, lvl, scanned)

    # ── Top stats ──────────────────────────────────────────────────────────────
    n_crits = sum(1 for c in crits if c[2] == "critical")
    n_warns = sum(1 for c in crits if c[2] == "warning")
    top_stats = '<div class="stat-row">'
    top_stats += stat_card(len(d["alive"]), "Hosts Alive", "info" if d["alive"] else "skip")
    top_stats += stat_card(n_crits, "Critical Findings", "critical" if n_crits else "ok")
    top_stats += stat_card(n_warns, "Warnings", "warning" if n_warns else "ok")
    scanned_count = sum(1 for k in ["smb","ldap","rdp","ssh","http","mssql","dns","ftp","snmp","ipmi","winrm","kerberos"]
                        if d[k].get("scanned"))
    top_stats += stat_card(scanned_count, "Services Scanned", "info")
    top_stats += '</div>'

    # ── Critical banner ────────────────────────────────────────────────────────
    crit_items  = [c for c in crits if c[2] == "critical"]
    warn_items  = [c for c in crits if c[2] == "warning"]

    crit_html = ""
    if crit_items:
        rows = "".join(
            f'<div class="crit-item"><span class="crit-svc">{h(svc)}</span>{h(msg)}</div>'
            for svc, msg, _ in crit_items
        )
        crit_html = (f'<div class="crit-banner">'
                     f'<h2>⚠ Critical findings ({len(crit_items)})</h2>{rows}</div>')

    warn_html = ""
    if warn_items:
        rows = "".join(
            f'<div class="warn-item"><span class="warn-svc">{h(svc)}</span>{h(msg)}</div>'
            for svc, msg, _ in warn_items
        )
        warn_html = (f'<div class="warn-banner">'
                     f'<h2>⚠ Warnings ({len(warn_items)})</h2>{rows}</div>')

    # ── Build section cards ────────────────────────────────────────────────────
    disc_lvl = "critical" if n_crits else ("warning" if n_warns else "ok")

    cards = section_wrap(
        "discovery", "Host Discovery", "🌐", disc_lvl, True, build_discovery(d))

    for sid, icon, builder, title in [
        ("smb",      "📁", build_smb,      "SMB"),
        ("ldap",     "📂", build_ldap,     "LDAP"),
        ("kerberos", "🎟", build_kerberos, "Kerberos"),
        ("rdp",      "🖥", build_rdp,      "RDP"),
        ("ssh",      "🔐", build_ssh,      "SSH"),
        ("http",     "🌍", build_http,     "HTTP / HTTPS"),
        ("mssql",    "🗄", build_mssql,    "MSSQL"),
        ("dns",      "🔎", build_dns,      "DNS"),
        ("ftp",      "📤", build_ftp,      "FTP"),
        ("snmp",     "📡", build_snmp,     "SNMP"),
        ("ipmi",     "⚙", build_ipmi,     "IPMI"),
        ("winrm",    "💻", build_winrm,    "WinRM"),
    ]:
        lvl = section_level(d, sid)
        body = builder(d) if d[sid]["scanned"] else '<p class="empty">Not scanned — no output files found for this service.</p>'
        cards += section_wrap(sid, title, icon, lvl, d[sid]["scanned"], body)

    # ── Assemble ──────────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NoPainNoScan — {h(engagement)}</title>
<style>{CSS}</style>
</head>
<body>

<aside class="sidebar">
  <div class="sb-logo">
    <h1>🔍 NoPainNoScan</h1>
    <p>{h(engagement)}</p>
    <p style="margin-top:.15rem">{h(now)}</p>
  </div>
  <div class="sb-sep">Sections</div>
  <nav>{nav_items}</nav>
</aside>

<main class="main">
  <div class="rpt-header">
    <div>
      <h1>Internal Pentest Report</h1>
      <div class="meta">
        <span><b>Engagement :</b> {h(engagement)}</span>
        <span><b>Scan dir   :</b> {h(base_dir)}</span>
        <span><b>Generated  :</b> {h(now)}</span>
      </div>
    </div>
    <div class="rpt-logo">🛡</div>
  </div>

  {top_stats}
  {crit_html}
  {warn_html}
  {cards}
</main>

<script>{JS}</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="generate_report.py — HTML report from NoPainNoScan outputs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 generate_report.py -d /tmp/pentest/ -o report.html
  python3 generate_report.py -d . -n "ClientCorp" -o /tmp/report.html
        """
    )
    parser.add_argument("-d", "--dir",        required=True,
                        help="Scan output directory (scanned recursively)")
    parser.add_argument("-o", "--output",     default="nopainnoscan_report.html",
                        help="Output HTML file (default: nopainnoscan_report.html)")
    parser.add_argument("-n", "--name",       default="Internal Pentest",
                        help="Engagement / client name")
    args = parser.parse_args()

    base = Path(args.dir)
    if not base.exists():
        print(f"[X] Directory not found: {base}")
        raise SystemExit(1)

    print(f"[*] Scanning output files in: {base.resolve()}")
    d = collect(base)

    scanned = sum(1 for k in ["smb","ldap","rdp","ssh","http","mssql","dns",
                               "ftp","snmp","ipmi","winrm","kerberos"]
                  if d[k].get("scanned"))
    print(f"[*] Hosts alive: {len(d['alive'])} — Services with data: {scanned}/12")

    crits = get_criticals(d)
    n_crit = sum(1 for c in crits if c[2] == "critical")
    n_warn = sum(1 for c in crits if c[2] == "warning")
    print(f"[*] Critical findings: {n_crit}  —  Warnings: {n_warn}")

    html_out = generate_html(d, crits, args.name, str(base.resolve()))

    out = Path(args.output)
    out.write_text(html_out, encoding="utf-8")
    print(f"[+] Report written → {out.resolve()}  ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
