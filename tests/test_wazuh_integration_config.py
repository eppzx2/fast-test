"""Static regression tests for FAST's Wazuh integration files.

These tests do not require Docker or a running Wazuh Manager. They catch
configuration mistakes that previously made a deployed Manager fail to load.
"""

from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "docker" / "rules" / "local_rules.xml"


def _rules():
    text = RULES_PATH.read_text(encoding="utf-8")
    root = ET.fromstring(f"<fast_rules>{text}</fast_rules>")
    return root.findall(".//rule")


def test_custom_rule_ids_are_unique():
    rule_ids = [rule.attrib["id"] for rule in _rules()]
    assert len(rule_ids) == len(set(rule_ids))


def test_frequency_context_rules_use_if_matched():
    for rule in _rules():
        has_if_matched = (
            rule.find("if_matched_sid") is not None
            or rule.find("if_matched_group") is not None
        )
        has_frequency = "frequency" in rule.attrib
        has_timeframe = "timeframe" in rule.attrib

        if has_if_matched:
            assert has_frequency and has_timeframe, (
                f"Rule {rule.attrib['id']} uses if_matched_* without frequency/timeframe"
            )

        if has_frequency or has_timeframe:
            assert has_frequency and has_timeframe, (
                f"Rule {rule.attrib['id']} must define both frequency and timeframe"
            )
            assert has_if_matched, (
                f"Rule {rule.attrib['id']} uses frequency/timeframe without if_matched_*"
            )


def test_ssh_failed_auth_rule_promotes_wazuh_5760_to_fast_100200():
    rules_by_id = {rule.attrib["id"]: rule for rule in _rules()}
    rule = rules_by_id["100200"]

    assert rule.findtext("if_sid") == "5760"
    assert rule.find("if_matched_sid") is None
    assert rule.find("if_matched_group") is None
    assert rule.find("same_source_ip") is None
    assert "frequency" not in rule.attrib
    assert "timeframe" not in rule.attrib
    assert rule.attrib["level"] == "10"
    assert rule.findtext("description") == (
        "FAST SSH failed authentication detected from source IP ($(srcip))."
    )


def test_portscan_rule_uses_deterministic_fast_kernel_marker():
    rules_by_id = {rule.attrib["id"]: rule for rule in _rules()}
    base = rules_by_id["100210"]
    correlation = rules_by_id["100211"]

    assert base.findtext("if_sid") == "4100"
    assert base.findtext("match") == "FAST_PORTSCAN"
    assert correlation.findtext("if_matched_sid") == "100210"
    assert correlation.find("same_source_ip") is not None


def test_lolbin_confirmation_is_same_event_child():
    rules_by_id = {rule.attrib["id"]: rule for rule in _rules()}
    rule = rules_by_id["100221"]

    assert rule.findtext("if_sid") == "100220"
    assert rule.find("if_matched_sid") is None


def test_cdb_list_is_registered_and_validated_during_deploy():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")

    assert "<list>etc/lists/ioc-ips</list>" in deploy
    assert "/var/ossec/bin/wazuh-analysisd -t" in deploy

    copy_list = deploy.index('sample_output/ioc-ips')
    copy_rules = deploy.index('docker/rules/local_rules.xml')
    assert copy_list < copy_rules, "CDB list must exist before rules reference it"


def test_manager_log_health_is_scoped_to_current_container_start():
    for relative_path in ("deploy.sh", "bin/fast", "refresh_iocs.sh"):
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        assert ".State.StartedAt" in text, relative_path
        assert 'docker logs --since "$started_at" "$MANAGER_CONTAINER"' in text, relative_path
        assert 'docker logs "$MANAGER_CONTAINER" 2>&1 | grep -c "CRITICAL"' not in text


def test_deploy_rejects_stale_or_mixed_wazuh_certificate_bundles():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")

    assert "certificate_bundle_is_consistent" in deploy
    assert "root-ca-manager.pem" in deploy
    assert "root-ca-manager.key" in deploy
    assert "cmp -s /certificates/root-ca.pem /certificates/root-ca-manager.pem" in deploy
    assert "cmp -s /certificates/root-ca.key /certificates/root-ca-manager.key" in deploy
    assert "openssl verify -CAfile /certificates/root-ca.pem" in deploy
    assert 'docker compose down >/dev/null 2>&1 || true' in deploy
    assert 'rm -rf "$WAZUH_CERT_DIR"' in deploy
    assert "generate-indexer-certs.yml" in deploy
    assert "docker compose up -d --force-recreate" in deploy
    assert "--reset-certs" in deploy


def test_deploy_verifies_filebeat_to_indexer_tls_before_success():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")

    assert "wait_for_filebeat_indexer_healthy" in deploy
    assert "/usr/share/filebeat/bin/filebeat test output" in deploy
    assert "Filebeat → Indexer" in deploy
    check_call = deploy.rindex("if ! wait_for_filebeat_indexer_healthy; then")
    success_banner = deploy.index("✅ DEPLOYMENT COMPLETE")
    assert check_call < success_banner


def test_fast_status_requires_healthy_filebeat_indexer_pipeline():
    fast = (ROOT / "bin" / "fast").read_text(encoding="utf-8")

    assert "filebeat_indexer_health" in fast
    assert "/usr/share/filebeat/bin/filebeat test output" in fast
    assert "Filebeat -> Indexer alert pipeline" in fast
    assert '&& [ "$fb_health" = "healthy" ]' in fast


def test_bruteforce_simulation_does_not_hide_transport_failures():
    script = (ROOT / "tests" / "acceptance" / "sim" / "simulate_brute_force.sh").read_text(encoding="utf-8")

    assert "MIN_REAL_FAILURES=5" in script
    assert "NumberOfPasswordPrompts=1" in script
    assert "real_failures" in script
    assert "2>/dev/null || true" not in script


def test_port_scan_simulation_is_non_root_safe_and_prefilter_logged():
    script = (ROOT / "tests" / "acceptance" / "sim" / "simulate_port_scan.sh").read_text(encoding="utf-8")
    setup = (ROOT / "tests" / "acceptance" / "sim" / "setup_prereqs.sh").read_text(encoding="utf-8")

    assert 'SCAN_TYPE="-sS"' in script
    assert 'SCAN_TYPE="-sT"' in script
    assert "nmap $SCAN_TYPE" not in script
    assert "nmap failed" in script
    assert "|| true" not in script.split("if command -v nmap", 1)[1].split("else", 1)[0]

    for port in ("56001", "56008", "56012"):
        assert port in script
        assert port in setup

    assert '<location>journald</location>' in setup
    assert 'iptables -t mangle -C PREROUTING' in setup
    assert 'iptables -t mangle -I PREROUTING 1' in setup
    assert 'FAST_SCAN_PREFIX="FAST_PORTSCAN "' in setup
    assert '--dports "$PORTS_CSV"' in setup
    assert "ufw enable" not in setup
    assert "ufw deny" not in setup
    assert "-j ACCEPT" not in setup
    assert "-j DROP" not in setup


def test_lolbin_setup_collects_audit_log_and_simulation_is_offline():
    setup = (ROOT / "tests" / "acceptance" / "sim" / "setup_prereqs.sh").read_text(encoding="utf-8")
    script = (ROOT / "tests" / "acceptance" / "sim" / "simulate_lolbin.sh").read_text(encoding="utf-8")

    assert '<log_format>audit</log_format>' in setup
    assert '<location>/var/log/audit/audit.log</location>' in setup
    assert "audit-wazuh-c" in setup
    assert "auditctl -l" in setup
    assert "systemctl restart wazuh-agent" in setup

    assert "systemctl is-active --quiet auditd" in script
    assert 'OSSEC_CONF="/var/ossec/etc/ossec.conf"' in script
    assert 'elif [ -r "$OSSEC_CONF" ]; then' in script
    assert "skipping the read-only config preflight" in script
    assert "sudo -n auditctl -l" in script
    assert "http://127.0.0.1:9/fast-lolbin-test" in script
    assert "http://example.com/" not in script
