#!/usr/bin/env python3
"""Triage Active Directory lab exports for the purple-team write-ups.

Two read-only analyses, standard library only:

* ``logs``: reads Windows events exported by Wazuh (alerts.json / archives.json,
  one JSON document per line) and flags the traces left by the lab scenarios
  (Kerberoasting, DCSync, AD CS ESC1, lateral movement, enumeration).
* ``bloodhound``: reads a SharpHound ``users.json`` export and lists the
  account hygiene issues an auditor would report (kerberoastable accounts,
  AS-REP roastable accounts, privileged accounts with old passwords...).

The tool never talks to the network or to a domain controller: it only parses
files that were already exported from the isolated lab.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Extended rights checked by a DCSync (DRSUAPI GetNCChanges) in event 4662.
REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

# RC4-HMAC and RC4-HMAC-EXP: the encryption types Kerberoasting tools request
# because their hashes crack much faster than AES ones.
WEAK_KERBEROS_ETYPES = {"0x17", "0x18"}

# Impacket wmiexec writes command output to a file on ADMIN$ named "__<epoch>".
WMIEXEC_OUTPUT = re.compile(r"\\\\127\.0\.0\.1\\admin\$\\__\d", re.IGNORECASE)

# Service binaries dropped by PsExec-style tools: "%systemroot%\<name>.exe"
# (same pattern as the stock Wazuh rule 92650) or anything in a temp folder.
SUSPICIOUS_SERVICE_PATH = re.compile(
    r'^"?%systemroot%\\\w+\.exe"?$|\\(windows\\)?te?mp\\[^\\]+\.(exe|bat|cmd|ps1)', re.IGNORECASE
)

SAN_UPN = re.compile(r"upn=([^&\s,]+)", re.IGNORECASE)

# Wazuh escapes Windows event fields: every backslash is doubled and line breaks
# become a literal "\n". It also keeps XML entities such as "&gt;" as-is.
WAZUH_ESCAPE = re.compile(r"\\([\\nrt])")
WAZUH_UNESCAPED = {"\\": "\\", "n": "\n", "r": "\r", "t": "\t"}
XML_ENTITIES = {"&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'", "&amp;": "&"}
XML_ENTITY = re.compile("|".join(XML_ENTITIES))

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Event:
    """A Windows event reduced to what the detectors need."""

    event_id: int
    timestamp: str
    computer: str
    # Event data fields with lower-cased keys: Wazuh writes "targetUserName",
    # a raw EVTX export writes "TargetUserName"; both end up as "targetusername".
    data: dict[str, str]

    def get(self, key: str) -> str:
        return self.data.get(key.lower(), "")


@dataclass
class Finding:
    scenario: str
    severity: str
    summary: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class LogReport:
    total_lines: int = 0
    skipped_lines: int = 0
    event_counts: Counter[int] = field(default_factory=Counter)
    findings: list[Finding] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def wazuh_unescape(value: str) -> str:
    """Undo the escaping Wazuh applies to Windows event fields."""
    value = WAZUH_ESCAPE.sub(lambda m: WAZUH_UNESCAPED[m.group(1)], value)
    return XML_ENTITY.sub(lambda m: XML_ENTITIES[m.group(0)], value)


def parse_event(doc: dict[str, Any]) -> Event | None:
    """Convert one exported JSON document to an Event, or None if it is not one.

    Accepts a Wazuh alert / archive line ({"data": {"win": ...}}), whose fields
    are unescaped, or a bare event ({"win": ...}) taken as-is.
    """
    data = doc.get("data")
    from_wazuh = isinstance(data, dict)
    win = data.get("win") if isinstance(data, dict) else doc.get("win")
    if not isinstance(win, dict):
        return None
    system = win.get("system") or {}
    try:
        event_id = int(str(system.get("eventID", "")).strip())
    except ValueError:
        return None
    eventdata = win.get("eventdata") or {}
    clean = wazuh_unescape if from_wazuh else str
    return Event(
        event_id=event_id,
        timestamp=str(system.get("systemTime") or doc.get("timestamp") or ""),
        computer=str(system.get("computer") or ""),
        data={str(k).lower(): clean(str(v)) for k, v in eventdata.items()},
    )


def read_events(lines: Iterable[str], report: LogReport) -> Iterator[Event]:
    """Yield events from JSON lines, counting the lines that cannot be used."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        report.total_lines += 1
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            report.skipped_lines += 1
            continue
        event = parse_event(doc) if isinstance(doc, dict) else None
        if event is None:
            report.skipped_lines += 1
            continue
        report.event_counts[event.event_id] += 1
        yield event


def _source_ip(event: Event) -> str:
    ip = event.get("ipAddress") or "inconnue"
    # The DC logs IPv4 clients as IPv4-mapped IPv6 addresses.
    return ip.removeprefix("::ffff:")


def _is_machine_account(name: str) -> bool:
    return name.endswith("$")


# --------------------------------------------------------------------------- #
# Detectors: each one takes every event and returns its findings
# --------------------------------------------------------------------------- #


def detect_kerberoasting(events: list[Event], threshold: int) -> list[Finding]:
    """4769 service tickets requested with RC4 for user (not machine) accounts."""
    services_by_source: dict[str, set[str]] = defaultdict(set)
    requesters_by_source: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event.event_id != 4769:
            continue
        if event.get("ticketEncryptionType").lower() not in WEAK_KERBEROS_ETYPES:
            continue
        service = event.get("serviceName")
        if not service or _is_machine_account(service) or service.lower() == "krbtgt":
            continue
        source = _source_ip(event)
        services_by_source[source].add(service)
        requesters_by_source[source].add(event.get("targetUserName"))

    findings = []
    for source, services in sorted(services_by_source.items()):
        burst = len(services) >= threshold
        findings.append(
            Finding(
                scenario="Kerberoasting",
                severity="high" if burst else "medium",
                summary=(
                    f"{len(services)} ticket(s) de service RC4 demandé(s) depuis {source}"
                    + (" : rafale typique d'un Kerberoasting" if burst else "")
                ),
                evidence=[
                    "services : " + ", ".join(sorted(services)),
                    "demandeur(s) : " + ", ".join(sorted(requesters_by_source[source])),
                ],
            )
        )
    return findings


def detect_dcsync(events: list[Event]) -> list[Finding]:
    """4662 replication rights exercised by an account that is not a DC."""
    rights_by_account: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event.event_id != 4662:
            continue
        account = event.get("subjectUserName")
        if _is_machine_account(account):
            continue  # domain controllers replicate with their machine account
        properties = event.get("properties").lower()
        for guid, right in REPLICATION_GUIDS.items():
            if guid in properties:
                rights_by_account[f"{event.get('subjectDomainName')}\\{account}"].add(right)

    return [
        Finding(
            scenario="DCSync",
            severity="critical",
            summary=f"Réplication d'annuaire demandée par le compte non-DC {account}",
            evidence=["droits : " + ", ".join(sorted(rights))],
        )
        for account, rights in sorted(rights_by_account.items())
    ]


def detect_adcs_esc1(events: list[Event]) -> list[Finding]:
    """4887 certificates issued with a SAN UPN that is not the requester's."""
    findings = []
    for event in events:
        if event.event_id != 4887:
            continue
        requester = event.get("requester")
        requester_sam = requester.split("\\")[-1].lower()
        for upn in SAN_UPN.findall(event.get("attributes")):
            if upn.split("@")[0].lower() != requester_sam:
                findings.append(
                    Finding(
                        scenario="AD CS ESC1",
                        severity="critical",
                        summary=f"Certificat émis pour {upn} à la demande de {requester}",
                        evidence=[
                            f"request id : {event.get('requestId') or '?'}",
                            f"attributs : {event.get('attributes')}",
                            f"horodatage : {event.timestamp}",
                        ],
                    )
                )
    return findings


def detect_lateral_movement(events: list[Event], threshold: int) -> list[Finding]:
    """Suspicious service installs, wmiexec-style processes and NTLM fan-out."""
    findings = []
    targets_by_source: dict[tuple[str, str], set[str]] = defaultdict(set)
    for event in events:
        if event.event_id == 7045 and SUSPICIOUS_SERVICE_PATH.search(event.get("imagePath")):
            findings.append(
                Finding(
                    scenario="Mouvement latéral",
                    severity="high",
                    summary=(
                        f"Service suspect installé sur {event.computer} : "
                        f"{event.get('serviceName')}"
                    ),
                    evidence=[
                        f"binaire : {event.get('imagePath')}",
                        f"horodatage : {event.timestamp}",
                    ],
                )
            )
        elif event.event_id == 1 and WMIEXEC_OUTPUT.search(event.get("commandLine")):
            findings.append(
                Finding(
                    scenario="Mouvement latéral",
                    severity="high",
                    summary=f"Commande à distance de type wmiexec sur {event.computer}",
                    evidence=[
                        f"parent : {event.get('parentImage')}",
                        f"ligne de commande : {event.get('commandLine')}",
                    ],
                )
            )
        elif (
            event.event_id == 4624
            and event.get("logonType") == "3"
            and event.get("authenticationPackageName").upper() == "NTLM"
            and not _is_machine_account(event.get("targetUserName"))
        ):
            key = (_source_ip(event), event.get("targetUserName"))
            targets_by_source[key].add(event.computer)

    for (source, account), computers in sorted(targets_by_source.items()):
        if len(computers) >= threshold:
            findings.append(
                Finding(
                    scenario="Mouvement latéral",
                    severity="high",
                    summary=(
                        f"Le compte {account} s'authentifie en NTLM depuis {source} "
                        f"sur {len(computers)} machines"
                    ),
                    evidence=["machines : " + ", ".join(sorted(computers))],
                )
            )
    return findings


def detect_enumeration(events: list[Event], threshold: int) -> list[Finding]:
    """4798/4799 group and membership lookups in bulk by one account."""
    lookups: Counter[str] = Counter()
    for event in events:
        if event.event_id in (4798, 4799):
            account = event.get("subjectUserName")
            if not _is_machine_account(account):
                lookups[account] += 1
    return [
        Finding(
            scenario="Cartographie",
            severity="low",
            summary=f"{count} énumérations de groupes / comptes locaux par {account}",
            evidence=["événements 4798 / 4799"],
        )
        for account, count in sorted(lookups.items())
        if count >= threshold
    ]


def analyze_logs(
    lines: Iterable[str],
    kerberoast_threshold: int = 3,
    lateral_threshold: int = 3,
    enumeration_threshold: int = 20,
) -> LogReport:
    report = LogReport()
    events = list(read_events(lines, report))
    report.findings = [
        *detect_kerberoasting(events, kerberoast_threshold),
        *detect_dcsync(events),
        *detect_adcs_esc1(events),
        *detect_lateral_movement(events, lateral_threshold),
        *detect_enumeration(events, enumeration_threshold),
    ]
    report.findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.scenario))
    return report


# --------------------------------------------------------------------------- #
# BloodHound users.json
# --------------------------------------------------------------------------- #


def _epoch_to_datetime(value: Any) -> datetime | None:
    """SharpHound stores pwdlastset as Unix seconds; 0 or -1 means "never"."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


def analyze_bloodhound_users(
    export: dict[str, Any], now: datetime, password_age_days: int = 365
) -> list[Finding]:
    users = export.get("data")
    if not isinstance(users, list):
        raise ValueError("export SharpHound invalide : clé 'data' absente")

    kerberoastable, asrep, stale_admins, never_expire = [], [], [], []
    for user in users:
        props = user.get("Properties") or {}
        name = str(props.get("name") or user.get("ObjectIdentifier") or "?")
        if not props.get("enabled", True) or name.upper().startswith("KRBTGT@"):
            continue
        admin = bool(props.get("admincount"))
        if props.get("hasspn"):
            spns = ", ".join(props.get("serviceprincipalnames") or []) or "SPN non listé"
            kerberoastable.append(f"{name}{' (admincount)' if admin else ''} : {spns}")
        if props.get("dontreqpreauth"):
            asrep.append(name)
        if props.get("pwdneverexpires"):
            never_expire.append(name)
        last_set = _epoch_to_datetime(props.get("pwdlastset"))
        if admin and last_set is not None and (now - last_set).days >= password_age_days:
            stale_admins.append(
                f"{name} : mot de passe changé il y a {(now - last_set).days} jours"
            )

    findings = []
    if kerberoastable:
        privileged = any("(admincount)" in line for line in kerberoastable)
        findings.append(
            Finding(
                "Kerberoasting",
                "high" if privileged else "medium",
                f"{len(kerberoastable)} compte(s) utilisateur avec SPN (kerberoastable)",
                kerberoastable,
            )
        )
    if asrep:
        findings.append(
            Finding(
                "AS-REP roasting",
                "high",
                f"{len(asrep)} compte(s) sans pré-authentification Kerberos",
                asrep,
            )
        )
    if stale_admins:
        findings.append(
            Finding(
                "Hygiène des comptes",
                "medium",
                f"{len(stale_admins)} compte(s) privilégié(s) avec un mot de passe ancien",
                stale_admins,
            )
        )
    if never_expire:
        findings.append(
            Finding(
                "Hygiène des comptes",
                "low",
                f"{len(never_expire)} compte(s) dont le mot de passe n'expire jamais",
                never_expire,
            )
        )
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings


# --------------------------------------------------------------------------- #
# Output and CLI
# --------------------------------------------------------------------------- #


def render_markdown(title: str, findings: list[Finding], report: LogReport | None = None) -> str:
    out = [f"# {title}", ""]
    if report is not None:
        out += [
            f"Lignes lues : {report.total_lines} (ignorées : {report.skipped_lines})",
            "",
            "| Event ID | Nombre |",
            "|---:|---:|",
            *(f"| {eid} | {n} |" for eid, n in sorted(report.event_counts.items())),
            "",
        ]
    if not findings:
        out.append("Aucun constat.")
        return "\n".join(out) + "\n"
    out += ["| Criticité | Scénario | Constat |", "|---|---|---|"]
    out += [f"| {f.severity} | {f.scenario} | {f.summary} |" for f in findings]
    out.append("")
    for i, f in enumerate(findings, 1):
        out.append(f"## {i}. [{f.severity}] {f.summary}")
        # Some event fields (4887 attributes) span several lines.
        out += ["- " + line.replace("\n", " ; ") for line in f.evidence]
        out.append("")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    logs = sub.add_parser("logs", help="analyser un export Wazuh (JSON lines)")
    logs.add_argument("file", type=Path)
    logs.add_argument(
        "--kerberoast-threshold",
        type=int,
        default=3,
        help="services RC4 distincts depuis une même IP (défaut : 3)",
    )
    logs.add_argument(
        "--lateral-threshold",
        type=int,
        default=3,
        help="machines distinctes en NTLM pour un même compte (défaut : 3)",
    )
    logs.add_argument(
        "--enumeration-threshold",
        type=int,
        default=20,
        help="événements 4798/4799 par compte (défaut : 20)",
    )
    logs.add_argument("--format", choices=("md", "json"), default="md")

    bh = sub.add_parser("bloodhound", help="analyser un users.json de SharpHound")
    bh.add_argument("file", type=Path)
    bh.add_argument("--password-age-days", type=int, default=365)
    bh.add_argument("--format", choices=("md", "json"), default="md")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "logs":
            with args.file.open(encoding="utf-8-sig") as fh:
                report = analyze_logs(
                    fh,
                    args.kerberoast_threshold,
                    args.lateral_threshold,
                    args.enumeration_threshold,
                )
            findings = report.findings
            text = render_markdown("Triage des journaux du lab AD", findings, report)
        else:
            export = json.loads(args.file.read_text(encoding="utf-8-sig"))
            findings = analyze_bloodhound_users(
                export, datetime.now(timezone.utc), args.password_age_days
            )
            report = None
            text = render_markdown("Revue des comptes (export BloodHound)", findings)
    except (OSError, ValueError) as exc:  # JSONDecodeError is a ValueError
        print(f"erreur : {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload: dict[str, Any] = {"findings": [asdict(f) for f in findings]}
        if report is not None:
            payload["event_counts"] = {str(k): v for k, v in sorted(report.event_counts.items())}
            payload["skipped_lines"] = report.skipped_lines
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
