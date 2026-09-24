from pathlib import Path


JS = Path("static/security-ops.js")
CSS = Path("static/security-ops.css")


def test_incident_details_show_alert_context():
    text = JS.read_text(encoding="utf-8")
    for field in (
        "Host / Agent",
        "Agent IP",
        "Source IP",
        "Destination IP",
        "Rule ID",
        "Severity / Level",
        "Process",
        "Executable",
        "MITRE Tactic",
        "MITRE Technique",
        "Event ID",
    ):
        assert field in text


def test_incident_details_have_context_grid_styles():
    css = CSS.read_text(encoding="utf-8")
    assert ".case-detail-grid" in css
    assert ".case-detail.wide" in css
