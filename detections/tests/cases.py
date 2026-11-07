"""Test cases for detections/wazuh/local_rules.xml.

Each case is a synthetic Windows event and the Wazuh rule it must trigger
("none" = must not trigger any ad_lab rule). Two commands:

    python cases.py build OUT_DIR     write events.jsonl in the format the Windows
                                      agent sends (JSON wrapping the raw event XML)
    python cases.py check ARCHIVES    compare a Wazuh archives.json with the cases

The events are fictitious and only describe the lab (lab.internal).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

SECURITY = ("Microsoft-Windows-Security-Auditing", "Security", 0, "0x8020000000000000")
SYSTEM = ("Service Control Manager", "System", 4, "0x8080000000000000")
SYSMON = (
    "Microsoft-Windows-Sysmon",
    "Microsoft-Windows-Sysmon/Operational",
    4,
    "0x8000000000000000",
)
REPLICATION = "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
DECOY_GUID = "%{00000000-0000-0000-0000-000000000000}"

Case = tuple[str, tuple[str, str, int, str], int, str, dict[str, str]]


def kerberos_tgs(service: str, etype: str, ip: str) -> dict[str, str]:
    return {
        "TargetUserName": "alice@LAB.INTERNAL",
        "ServiceName": service,
        "TicketEncryptionType": etype,
        "IpAddress": ip,
    }


def ntlm_logon(user: str) -> dict[str, str]:
    return {
        "TargetUserName": user,
        "LogonType": "3",
        "AuthenticationPackageName": "NTLM",
        "IpAddress": "10.10.10.50",
    }


CASES: list[Case] = [
    # Scenario 1: discovery
    (
        "100101",
        SECURITY,
        4662,
        "DC01",
        {"SubjectUserName": "alice", "ObjectName": DECOY_GUID, "Properties": "%%7684"},
    ),
    *[("100102", SECURITY, 4799, "CLIENT01", {"SubjectUserName": "alice"})] * 19,
    ("100103", SECURITY, 4799, "CLIENT01", {"SubjectUserName": "alice"}),
    ("none", SECURITY, 4799, "CLIENT01", {"SubjectUserName": "CLIENT01$"}),
    # Scenario 2: Kerberoasting
    ("100110", SECURITY, 4769, "DC01", kerberos_tgs("svc_sql", "0x17", "::ffff:10.10.10.50")),
    ("100110", SECURITY, 4769, "DC01", kerberos_tgs("svc_web", "0x17", "::ffff:10.10.10.50")),
    ("100111", SECURITY, 4769, "DC01", kerberos_tgs("svc_backup", "0x17", "::ffff:10.10.10.50")),
    ("none", SECURITY, 4769, "DC01", kerberos_tgs("SRV01$", "0x17", "::ffff:10.10.10.30")),
    ("none", SECURITY, 4769, "DC01", kerberos_tgs("svc_web", "0x12", "::ffff:10.10.10.30")),
    ("100112", SECURITY, 4769, "DC01", kerberos_tgs("svc_legacy", "0x12", "::ffff:10.10.10.30")),
    # Scenario 3: lateral movement (92650 is a stock Wazuh rule)
    (
        "92650",
        SYSTEM,
        7045,
        "SRV01",
        {
            "ServiceName": "BTOBTO",
            "ImagePath": "%systemroot%\\aBcDeFgH.exe",
            "AccountName": "LocalSystem",
        },
    ),
    (
        "100130",
        SYSTEM,
        7045,
        "SRV01",
        {
            "ServiceName": "updsvc",
            "ImagePath": "C:\\Windows\\Temp\\updsvc.exe",
            "AccountName": "LocalSystem",
        },
    ),
    (
        "none",
        SYSTEM,
        7045,
        "SRV01",
        {
            "ServiceName": "Sysmon64",
            "ImagePath": "C:\\Windows\\Sysmon64.exe",
            "AccountName": "LocalSystem",
        },
    ),
    (
        "100131",
        SYSMON,
        1,
        "CLIENT01",
        {
            "ParentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1762596060.12 2>&1",
        },
    ),
    ("100132", SECURITY, 4624, "DC01", ntlm_logon("localadmin")),
    ("100132", SECURITY, 4624, "SRV01", ntlm_logon("localadmin")),
    ("100133", SECURITY, 4624, "CLIENT01", ntlm_logon("localadmin")),
    ("none", SECURITY, 4624, "CLIENT01", ntlm_logon("CLIENT01$")),
    # Scenario 4: AD CS ESC1
    (
        "100141",
        SECURITY,
        4887,
        "SRV01",
        {
            "RequestId": "12",
            "Requester": "LAB\\alice",
            "Attributes": (
                "CertificateTemplate:VulnUserTemplate\nSAN:upn=administrator@lab.internal"
            ),
        },
    ),
    (
        "100140",
        SECURITY,
        4886,
        "SRV01",
        {
            "RequestId": "15",
            "Requester": "LAB\\carol",
            "Attributes": "CertificateTemplate:VulnUserTemplate\nSAN:upn=carol@lab.internal",
        },
    ),
    (
        "none",
        SECURITY,
        4887,
        "SRV01",
        {"RequestId": "14", "Requester": "LAB\\bob", "Attributes": "CertificateTemplate:User"},
    ),
    # Scenario 5: DCSync
    (
        "100151",
        SECURITY,
        4662,
        "DC01",
        {
            "SubjectUserName": "svc_backup",
            "SubjectDomainName": "LAB",
            "ObjectName": "%{11111111-2222-3333-4444-555555555555}",
            "Properties": REPLICATION,
        },
    ),
    (
        "100150",
        SECURITY,
        4662,
        "DC01",
        {
            "SubjectUserName": "DC02$",
            "SubjectDomainName": "LAB",
            "ObjectName": "%{11111111-2222-3333-4444-555555555555}",
            "Properties": REPLICATION,
        },
    ),
]


def to_agent_message(case: Case) -> str:
    """Render a case as the agent sends it: {"Message": ..., "Event": "<Event>...</Event>"}."""
    _, (provider, channel, level, keywords), event_id, host, data = case
    fields = "".join(f"<Data Name='{k}'>{escape(v)}</Data>" for k, v in data.items())
    xml = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='{provider}'/><EventID>{event_id}</EventID><Version>0</Version>"
        f"<Level>{level}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords>"
        "<TimeCreated SystemTime='2026-11-08T10:00:00.000000Z'/><EventRecordID>1</EventRecordID>"
        "<Correlation/><Execution ProcessID='4' ThreadID='8'/>"
        f"<Channel>{channel}</Channel><Computer>{host}.lab.internal</Computer><Security/>"
        f"</System><EventData>{fields}</EventData></Event>"
    )
    return json.dumps({"Message": f"lab test event {event_id}", "Event": xml})


def check(archives: Path) -> int:
    lines = archives.read_text(encoding="utf-8").splitlines()
    # The manager also archives its own events (SCA, rootcheck...): keep ours only.
    docs: list[dict[str, Any]] = [
        doc for doc in map(json.loads, filter(None, lines)) if doc.get("location") == "EventChannel"
    ]
    archives.write_text("".join(json.dumps(d) + "\n" for d in docs), encoding="utf-8")
    failures = 0
    for case, doc in zip(CASES, docs, strict=False):
        expected = case[0]
        got = doc.get("rule", {}).get("id", "none")
        ok = got == expected or (expected == "none" and not got.startswith("1001"))
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} event {case[2]:<5} expected {expected:<7} got {got}")
    if len(docs) != len(CASES):
        print(f"FAIL {len(docs)} events archived, {len(CASES)} expected")
        failures += 1
    print(f"{len(CASES) - failures}/{len(CASES)} cases passed")
    return 1 if failures else 0


def main() -> int:
    command, path = sys.argv[1], Path(sys.argv[2])
    if command == "build":
        path.mkdir(parents=True, exist_ok=True)
        (path / "events.jsonl").write_text(
            "\n".join(to_agent_message(c) for c in CASES) + "\n", encoding="utf-8"
        )
        return 0
    return check(path)


if __name__ == "__main__":
    sys.exit(main())
