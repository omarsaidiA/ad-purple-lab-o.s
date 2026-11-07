"""Tests for scripts/ad_triage.py.

wazuh_archives_sample.jsonl is real Wazuh 4.14 output: the synthetic events of
detections/tests/cases.py replayed through a wazuh-manager container by
detections/tests/run.sh (regenerate it with that script).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import ad_triage

FIXTURES = Path(__file__).parent / "fixtures"
ARCHIVES = FIXTURES / "wazuh_archives_sample.jsonl"
USERS = FIXTURES / "bloodhound_users_sample.json"
NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)


def wazuh_line(event_id: int, computer: str = "DC01.lab.internal", **eventdata: str) -> str:
    return json.dumps(
        {
            "data": {
                "win": {
                    "system": {"eventID": str(event_id), "computer": computer},
                    "eventdata": eventdata,
                }
            }
        }
    )


@pytest.fixture
def report() -> ad_triage.LogReport:
    with ARCHIVES.open(encoding="utf-8") as fh:
        return ad_triage.analyze_logs(fh)


def by_scenario(findings: list[ad_triage.Finding], scenario: str) -> list[ad_triage.Finding]:
    return [f for f in findings if f.scenario == scenario]


# --- parsing ---------------------------------------------------------------


def test_reads_every_event_of_the_wazuh_export(report: ad_triage.LogReport) -> None:
    assert report.total_lines == 41
    assert report.skipped_lines == 0
    assert report.event_counts[4799] == 21
    assert report.event_counts[4769] == 6
    assert report.event_counts[7045] == 3


def test_skips_lines_that_are_not_windows_events() -> None:
    lines = ['{"rule": {"id": "5715"}, "data": {"srcuser": "root"}}', "not json", "", "[1, 2]"]
    report = ad_triage.analyze_logs(lines)
    assert (report.total_lines, report.skipped_lines) == (3, 3)


def test_undoes_wazuh_escaping() -> None:
    assert ad_triage.wazuh_unescape(r"LAB\\alice") == "LAB\\alice"
    assert ad_triage.wazuh_unescape(r"\\\\127.0.0.1\\ADMIN$") == r"\\127.0.0.1\ADMIN$"
    assert ad_triage.wazuh_unescape(r"Template:User\nSAN:upn=a") == "Template:User\nSAN:upn=a"
    assert ad_triage.wazuh_unescape("1&gt; out 2&gt;&amp;1") == "1> out 2>&1"


def test_bare_events_are_taken_as_is_with_case_insensitive_keys() -> None:
    doc = {"win": {"system": {"eventID": "4887"}, "eventdata": {"Requester": r"LAB\\alice"}}}
    event = ad_triage.parse_event(doc)
    assert event is not None
    assert event.get("requester") == r"LAB\\alice"


def test_rejects_documents_without_numeric_event_id() -> None:
    assert ad_triage.parse_event({"win": {"system": {"eventID": "abc"}}}) is None


# --- detectors on the Wazuh export ----------------------------------------


def test_kerberoasting_burst_ignores_machine_accounts_and_aes(
    report: ad_triage.LogReport,
) -> None:
    [finding] = by_scenario(report.findings, "Kerberoasting")
    assert finding.severity == "high"
    assert "3 ticket(s)" in finding.summary
    assert "10.10.10.50" in finding.summary and "::ffff:" not in finding.summary
    assert finding.evidence[0] == "services : svc_backup, svc_sql, svc_web"


def test_dcsync_flags_user_account_but_not_domain_controller(
    report: ad_triage.LogReport,
) -> None:
    [finding] = by_scenario(report.findings, "DCSync")
    assert finding.severity == "critical"
    assert finding.summary.endswith("LAB\\svc_backup")
    assert "DS-Replication-Get-Changes-All" in finding.evidence[0]


def test_esc1_flags_san_for_another_user_only(report: ad_triage.LogReport) -> None:
    [finding] = by_scenario(report.findings, "AD CS ESC1")
    assert finding.summary == (
        "Certificat émis pour administrator@lab.internal à la demande de LAB\\alice"
    )


def test_lateral_movement_signals(report: ad_triage.LogReport) -> None:
    summaries = [f.summary for f in by_scenario(report.findings, "Mouvement latéral")]
    assert "Service suspect installé sur SRV01.lab.internal : BTOBTO" in summaries
    assert "Service suspect installé sur SRV01.lab.internal : updsvc" in summaries
    assert not any("Sysmon64" in s for s in summaries)
    assert "Commande à distance de type wmiexec sur CLIENT01.lab.internal" in summaries
    assert any("localadmin" in s and "3 machines" in s for s in summaries)
    assert not any("CLIENT01$" in s for s in summaries)


def test_enumeration_by_user_account_only(report: ad_triage.LogReport) -> None:
    [finding] = by_scenario(report.findings, "Cartographie")
    assert finding.summary.startswith("20 énumérations") and finding.summary.endswith("alice")


def test_findings_are_sorted_by_severity(report: ad_triage.LogReport) -> None:
    ranks = [ad_triage.SEVERITY_ORDER[f.severity] for f in report.findings]
    assert ranks == sorted(ranks)


# --- detector edge cases ---------------------------------------------------


def test_single_rc4_ticket_is_only_medium() -> None:
    line = wazuh_line(
        4769,
        serviceName="svc_sql",
        ticketEncryptionType="0x17",
        ipAddress="10.10.10.50",
        targetUserName="alice",
    )
    [finding] = ad_triage.analyze_logs([line]).findings
    assert finding.severity == "medium"


def test_esc1_ignores_san_matching_the_requester() -> None:
    line = wazuh_line(4887, requester=r"LAB\\alice", attributes="SAN:upn=alice@lab.internal")
    assert ad_triage.analyze_logs([line]).findings == []


def test_enumeration_threshold() -> None:
    lines = [wazuh_line(4799, subjectUserName="alice")] * 19
    assert ad_triage.analyze_logs(lines).findings == []
    assert ad_triage.analyze_logs(lines, enumeration_threshold=10).findings


# --- BloodHound ------------------------------------------------------------


def test_bloodhound_review() -> None:
    export = json.loads(USERS.read_text(encoding="utf-8"))
    findings = ad_triage.analyze_bloodhound_users(export, NOW)
    text = json.dumps([f.summary for f in findings] + [e for f in findings for e in f.evidence])

    assert "SVC_SQL@LAB.INTERNAL (admincount)" in text
    assert "CAROL@LAB.INTERNAL" in text
    assert "KRBTGT" not in text  # built-in account, never reported
    assert "OLD_SVC" not in text  # disabled accounts are skipped
    assert findings[0].severity == "high"


def test_bloodhound_rejects_unknown_format() -> None:
    with pytest.raises(ValueError):
        ad_triage.analyze_bloodhound_users({"nodes": []}, NOW)


# --- CLI -------------------------------------------------------------------


def test_cli_markdown_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert ad_triage.main(["logs", str(ARCHIVES)]) == 0
    out = capsys.readouterr().out
    assert "| critical | AD CS ESC1 |" in out
    assert "SAN:upn=administrator@lab.internal" in out  # multi-line field flattened

    assert ad_triage.main(["bloodhound", str(USERS), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]


def test_cli_reports_missing_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert ad_triage.main(["logs", str(tmp_path / "absent.jsonl")]) == 2
    assert "erreur" in capsys.readouterr().err
