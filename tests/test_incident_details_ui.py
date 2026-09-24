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


def test_incident_details_expand_inline_and_show_save_feedback():
    js = JS.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    assert "incident-detail-row" in js
    assert "toggleCase" in js
    assert 'b.textContent=expanded?"Close":"Open"' in js
    assert "Saved ✓" in js
    assert "Save failed:" in js
    assert "case-panel" not in js
    assert ".case-detail-grid" in css
    assert ".incident-detail-row" in css
    assert ".case-save-feedback.success" in css
