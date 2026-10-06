"""registry.py - Central contract describing the runnable NoPainNoScan scripts.

This module is metadata-only: it declares WHAT each script is and WHICH CLI
arguments / system tools it needs. It does NOT execute anything — the execution
engine (Agent 2) reads this registry to build command lines, and the UI/parsers
(Agents 3/4/5) use it to know what runs and what to expect.

Each entry is derived directly from the argparse block and the tool-availability
checks of the corresponding standalone script at the project root.

Public API:
    CheckDefinition      - dataclass describing one runnable script
    CheckArgument        - dataclass describing one CLI argument
    REGISTRY             - dict {id: CheckDefinition} of all 13 checks + discovery
    list_checks()        - return all CheckDefinition objects (list)
    get_check(id)        - return one CheckDefinition or None
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CheckArgument:
    """One CLI argument accepted by a script.

    Attributes:
        name:     canonical flag, e.g. "--target" (long form preferred).
        short:    short flag if any, e.g. "-t".
        dest:     python-side name used in params_json, e.g. "target".
        type:     logical type: "str" | "int" | "bool" | "list".
        required: whether the script refuses to start without it.
        default:  default value applied by the script when omitted (or None).
        help:     short human description.
    """
    name: str
    dest: str
    type: str = "str"
    short: Optional[str] = None
    required: bool = False
    default: Any = None
    help: str = ""


@dataclass(frozen=True)
class CheckDefinition:
    """Full description of one runnable NoPainNoScan script.

    Attributes:
        id:            short stable identifier, e.g. "smb".
        script:        filename of the standalone script at PROJECT_ROOT.
        label:         human-friendly name for the UI.
        description:   one-line summary of what the check does.
        supports_creds:True if the script accepts -u/-p/-H/-d credentials and
                       runs additional authenticated steps with them.
        required_tools:system binaries/tools the script needs. Tools marked
                       optional degrade gracefully (feature skipped, no crash).
        optional_tools:tools that enhance the check but are not mandatory.
        arguments:     list of CheckArgument accepted by the script.
        needs_root:    True if the script requires root/raw sockets.
        auto_yes_flag: flag the runner appends to run the script non-interactively
                       (e.g. "--yes"); None if the script has no interactive prompts.
    """
    id: str
    script: str
    label: str
    description: str
    supports_creds: bool
    required_tools: list[str]
    arguments: list[CheckArgument]
    optional_tools: list[str] = field(default_factory=list)
    needs_root: bool = False
    auto_yes_flag: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to a plain dict (JSON-friendly) for the API/UI."""
        return asdict(self)


# --------------------------------------------------------------------------- #
# Shared argument sets
# --------------------------------------------------------------------------- #
# The common contract shared by every check script.
_ARG_TARGET = CheckArgument(
    name="--target", short="-t", dest="target", type="str", required=True,
    help="File with hosts (one per line), single IP, or CIDR",
)
_ARG_OUTPUT = CheckArgument(
    name="--output", short="-o", dest="output", type="str", required=False,
    default=None, help="Output directory (auto-created; per-run timestamped default)",
)

# Credential arguments (present only on checks with supports_creds=True,
# except FTP/IPMI which expose a reduced subset — see their entries).
_ARG_USERNAME = CheckArgument(
    name="--username", short="-u", dest="username", type="str",
    help="Username for authenticated checks",
)
_ARG_PASSWORD = CheckArgument(
    name="--password", short="-p", dest="password", type="str",
    help="Password for authenticated checks",
)
_ARG_HASH = CheckArgument(
    name="--hash", short="-H", dest="hash", type="str",
    help="NTLM hash LM:NT for pass-the-hash",
)


def _domain_arg(default: Any = None) -> CheckArgument:
    return CheckArgument(
        name="--domain", short="-d", dest="domain", type="str", default=default,
        help="Domain (FQDN, e.g. corp.local)",
    )


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
REGISTRY: dict[str, CheckDefinition] = {

    # -- Phase 0: network discovery (different contract: --verify, no creds) --
    "discovery": CheckDefinition(
        id="discovery",
        script="ad_recon_userless.py",
        label="Discovery (userless recon)",
        description="Phase 0 network discovery: host sweep + masscan port scan, "
                    "produces the hosts_*.txt files consumed by every other check.",
        supports_creds=False,
        needs_root=True,
        required_tools=["masscan", "fping", "arp-scan", "nmap"],
        optional_tools=[],
        arguments=[
            CheckArgument(name="--target", short="-t", dest="target", type="str",
                          required=True,
                          help="CIDR/IP or a targets file (one CIDR/IP per line)"),
            CheckArgument(name="--output", short="-o", dest="output", type="str",
                          default=".", help="Output directory"),
            CheckArgument(name="--rate", short="-r", dest="rate", type="int",
                          default=5000, help="masscan rate in packets/second"),
            CheckArgument(name="--verify", dest="verify", type="bool",
                          default=False,
                          help="Second nmap SYN pass to confirm masscan results"),
        ],
    ),

    # -- SMB ----------------------------------------------------------------- #
    "smb": CheckDefinition(
        id="smb",
        script="check_smb.py",
        label="SMB (139/445)",
        description="SMB signing, SMBv1, null-session and authenticated shares, "
                    "SYSVOL/NETLOGON spidering.",
        supports_creds=True,
        required_tools=["nxc"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            _ARG_USERNAME, _ARG_PASSWORD, _ARG_HASH,
            _domain_arg(default="WORKGROUP"),
            CheckArgument(name="--threads", dest="threads", type="int",
                          default=10, help="Worker threads"),
        ],
    ),

    # -- LDAP ---------------------------------------------------------------- #
    "ldap": CheckDefinition(
        id="ldap",
        script="check_ldap.py",
        label="LDAP (389/3268)",
        description="rootDSE, anonymous null-bind dump, authenticated enumeration, "
                    "BloodHound collection.",
        supports_creds=True,
        required_tools=["ldapsearch"],
        optional_tools=["nxc", "bloodhound-python"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            _ARG_USERNAME, _ARG_PASSWORD, _ARG_HASH, _domain_arg(),
        ],
    ),

    # -- RDP ----------------------------------------------------------------- #
    "rdp": CheckDefinition(
        id="rdp",
        script="check_rdp.py",
        label="RDP (3389)",
        description="NLA status, OS fingerprint, credential test and screenshot.",
        supports_creds=True,
        required_tools=["nxc"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            _ARG_USERNAME, _ARG_PASSWORD, _ARG_HASH, _domain_arg(),
        ],
    ),

    # -- SSH ----------------------------------------------------------------- #
    "ssh": CheckDefinition(
        id="ssh",
        script="check_ssh.py",
        label="SSH (22)",
        description="Banner grab, weak algorithm audit, auth methods, "
                    "credential test. No domain concept.",
        supports_creds=True,
        required_tools=[],
        optional_tools=["ssh-audit", "nxc", "ssh"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            _ARG_USERNAME, _ARG_PASSWORD, _ARG_HASH,
            CheckArgument(name="--port", dest="port", type="int", default=22,
                          help="SSH port"),
        ],
    ),

    # -- HTTP ---------------------------------------------------------------- #
    "http": CheckDefinition(
        id="http",
        script="check_http.py",
        label="HTTP/S (80/443/8080/8443/8000)",
        description="Titles/headers, ADCS, WebDAV, OWA/RDWeb/ADFS/WSUS, tech detection. "
                    "Accepts only -u/-p (no hash/domain).",
        supports_creds=True,
        required_tools=["curl"],
        optional_tools=["whatweb"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            _ARG_USERNAME, _ARG_PASSWORD,
            CheckArgument(name="--ports", dest="ports", type="str",
                          default="80,443,8080,8443,8000",
                          help="Comma-separated ports to test"),
            CheckArgument(name="--timeout", dest="timeout", type="int",
                          default=10, help="Per-request timeout (seconds)"),
            CheckArgument(name="--workers", dest="workers", type="int",
                          default=10, help="Parallel workers"),
        ],
    ),

    # -- MSSQL --------------------------------------------------------------- #
    "mssql": CheckDefinition(
        id="mssql",
        script="check_mssql.py",
        label="MSSQL (1433)",
        description="Version enum, default SA credential spraying, xp_cmdshell, "
                    "linked servers.",
        supports_creds=True,
        required_tools=["nxc"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            _ARG_USERNAME, _ARG_PASSWORD, _ARG_HASH, _domain_arg(),
        ],
    ),

    # -- DNS ----------------------------------------------------------------- #
    "dns": CheckDefinition(
        id="dns",
        script="check_dns.py",
        label="DNS (53)",
        description="SOA/domain detection, AXFR zone transfer, subdomain enum, "
                    "reverse PTR sweep. No credentials; -d is repeatable.",
        supports_creds=False,
        required_tools=["dig"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            CheckArgument(name="--domain", short="-d", dest="domains", type="list",
                          default=None,
                          help="Domain(s) to attempt AXFR on (repeatable)"),
            CheckArgument(name="--range", dest="range", type="str", default=None,
                          help="IP range for reverse lookup (default: /24 of first host)"),
        ],
    ),

    # -- FTP ----------------------------------------------------------------- #
    "ftp": CheckDefinition(
        id="ftp",
        script="check_ftp.py",
        label="FTP (21)",
        description="Banner grab, anonymous login, recursive listing, write test. "
                    "Uses stdlib ftplib; nxc optional. Only -u/-p (defaults anonymous).",
        supports_creds=True,
        required_tools=[],
        optional_tools=["nxc"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            CheckArgument(name="--username", short="-u", dest="username", type="str",
                          default="anonymous", help="Username for credential test"),
            CheckArgument(name="--password", short="-p", dest="password", type="str",
                          default="anonymous@", help="Password for credential test"),
        ],
    ),

    # -- SNMP ---------------------------------------------------------------- #
    "snmp": CheckDefinition(
        id="snmp",
        script="check_snmp.py",
        label="SNMP UDP (161)",
        description="Community string brute force, system enumeration, "
                    "Windows-specific OIDs. No AD credentials.",
        supports_creds=False,
        required_tools=[],
        optional_tools=["onesixtyone", "snmpwalk"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            CheckArgument(name="--community", short="-c", dest="community", type="str",
                          default="", help="Extra community strings, comma-separated"),
            CheckArgument(name="--version", dest="version", type="str",
                          default="1,2c", help="SNMP version(s), comma-separated"),
        ],
    ),

    # -- IPMI ---------------------------------------------------------------- #
    "ipmi": CheckDefinition(
        id="ipmi",
        script="check_ipmi.py",
        label="IPMI UDP (623)",
        description="Presence check, cipher-zero (CVE-2013-4786), anonymous auth, "
                    "RAKP hash capture, default creds. -u is a username list.",
        supports_creds=True,
        required_tools=["ipmitool"],
        optional_tools=["ipmipwner"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            CheckArgument(name="--username", short="-u", dest="username", type="str",
                          default="ADMIN,admin,Administrator,root",
                          help="Comma-separated usernames to test"),
            CheckArgument(name="--password", short="-p", dest="password", type="str",
                          default=None,
                          help="Password to test alongside default creds"),
        ],
    ),

    # -- WinRM --------------------------------------------------------------- #
    "winrm": CheckDefinition(
        id="winrm",
        script="check_winrm.py",
        label="WinRM (5985/5986)",
        description="Detection + auth method, credential test, command execution.",
        supports_creds=True,
        required_tools=["nxc"],
        optional_tools=["curl"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            _ARG_USERNAME, _ARG_PASSWORD, _ARG_HASH, _domain_arg(),
            CheckArgument(name="--port", dest="port", type="int", default=5985,
                          help="WinRM port"),
        ],
    ),

    # -- Kerberos ------------------------------------------------------------ #
    "kerberos": CheckDefinition(
        id="kerberos",
        script="check_kerberos.py",
        label="Kerberos (88)",
        description="User enumeration, AS-REP roasting, Kerberoasting.",
        supports_creds=True,
        required_tools=[],
        optional_tools=["kerbrute", "impacket", "nxc"],
        arguments=[
            _ARG_TARGET, _ARG_OUTPUT,
            _ARG_USERNAME, _ARG_PASSWORD, _ARG_HASH, _domain_arg(),
            CheckArgument(name="--users", dest="users", type="str", default=None,
                          help="File with usernames for AS-REP roasting"),
            CheckArgument(name="--wordlist", dest="wordlist", type="str", default=None,
                          help="Wordlist for user enumeration"),
        ],
    ),
}


# Every check_*.py script runs its phases behind an interactive confirm_step()
# prompt and now accepts a "--yes" flag to accept them all up front. The UI always
# drives them non-interactively, so the runner appends that flag automatically.
# "discovery" (ad_recon_userless.py) has no such prompt and is left untouched.
import dataclasses as _dc  # noqa: E402
for _cid, _cdef in list(REGISTRY.items()):
    if _cid != "discovery":
        REGISTRY[_cid] = _dc.replace(_cdef, auto_yes_flag="--yes")


# --------------------------------------------------------------------------- #
# Lookup helpers
# --------------------------------------------------------------------------- #
def list_checks() -> list[CheckDefinition]:
    """Return every registered CheckDefinition (registry insertion order)."""
    return list(REGISTRY.values())


def get_check(check_id: str) -> Optional[CheckDefinition]:
    """Return the CheckDefinition for `check_id`, or None if unknown."""
    return REGISTRY.get(check_id)
