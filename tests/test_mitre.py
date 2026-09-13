"""MITRE ATT&CK mapping regression tests."""

from core.mitre import ENTERPRISE_TACTICS, build_mitre_coverage, enrich_alert, enrich_detection


def test_detection_mapping_resolves_named_tactics_and_techniques():
    mapped = enrich_detection({"id": "100200", "mitre": ["T1110"]})
    technique = mapped["mitre_mapping"]["techniques"][0]
    tactic = mapped["mitre_mapping"]["tactics"][0]

    assert technique["id"] == "T1110"
    assert technique["name"] == "Brute Force"
    assert tactic == {"id": "TA0006", "name": "Credential Access"}


def test_alert_mapping_uses_canonical_fast_rule_catalogue():
    alert = enrich_alert(
        {
            "event_id": "alert-1",
            "rule_id": "100221",
            "mitre_ids": ["T1036.003", "T1105"],
        }
    )
    ids = [item["id"] for item in alert["mitre_mapping"]["techniques"]]
    tactics = [item["name"] for item in alert["mitre_mapping"]["tactics"]]

    assert ids == ["T1036.003", "T1105"]
    assert "Defense Evasion" in tactics
    assert "Command and Control" in tactics
    assert alert["wazuh_mitre_ids"] == ["T1036.003", "T1105"]


def test_coverage_distinguishes_mapped_from_observed():
    activity = [
        {"rule_id": "100200", "count": 4, "last_triggered": "2026-09-13T12:00:00Z", "last_agent": "ebi-VMware"},
        {"rule_id": "100211", "count": 0, "last_triggered": "", "last_agent": ""},
        {"rule_id": "100221", "count": 1, "last_triggered": "2026-09-13T12:05:00Z", "last_agent": "ebi-VMware"},
    ]
    payload = build_mitre_coverage(activity, window_minutes=1440)
    by_tactic = {item["name"]: item for item in payload["tactics"]}

    assert len(payload["tactics"]) == len(ENTERPRISE_TACTICS) == 14
    assert payload["summary"]["mapped_tactics"] == 4
    assert payload["summary"]["observed_tactics"] == 3
    assert payload["summary"]["mapped_techniques"] == 4
    assert by_tactic["Credential Access"]["mapped"] is True
    assert by_tactic["Credential Access"]["observed"] is True
    assert by_tactic["Discovery"]["mapped"] is True
    assert by_tactic["Discovery"]["observed"] is False
    assert by_tactic["Initial Access"]["mapped"] is False
