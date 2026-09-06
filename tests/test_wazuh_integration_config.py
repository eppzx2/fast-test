"""Static regression tests for FAST's Wazuh integration files.

These tests do not require Docker or a running Wazuh Manager. They catch
configuration mistakes that previously made a deployed Manager fail to load.
"""

from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "docker" / "rules" / "local_rules.xml"


def _rules():
    # Wazuh rule files may contain multiple top-level <group> elements.
    # Wrap them in a synthetic root so Python's XML parser can validate
    # the XML structure without changing the file Wazuh consumes.
    text = RULES_PATH.read_text(encoding="utf-8")
    root = ET.fromstring(f"<fast_rules>{text}</fast_rules>")
    return root.findall(".//rule")


def test_custom_rule_ids_are_unique():
    rule_ids = [rule.attrib["id"] for rule in _rules()]
    assert len(rule_ids) == len(set(rule_ids))


def test_frequency_context_rules_use_if_matched():
    """Wazuh frequency/timeframe context requires if_matched_*.

    Conversely, if_matched_sid/if_matched_group are time-window correlation
    primitives and must carry both frequency and timeframe. Same-event
    parent/child chaining must use if_sid/if_group instead.
    """
    for rule in _rules():
        has_if_matched = (
            rule.find("if_matched_sid") is not None
            or rule.find("if_matched_group") is not None
        )
        has_frequency = "frequency" in rule.attrib
        has_timeframe = "timeframe" in rule.attrib

        if has_if_matched:
            assert has_frequency and has_timeframe, (
                f"Rule {rule.attrib['id']} uses if_matched_* without "
                "frequency/timeframe"
            )

        if has_frequency or has_timeframe:
            assert has_frequency and has_timeframe, (
                f"Rule {rule.attrib['id']} must define both frequency and timeframe"
            )
            assert has_if_matched, (
                f"Rule {rule.attrib['id']} uses frequency/timeframe without "
                "if_matched_sid/if_matched_group"
            )


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
        assert (
            'docker logs "$MANAGER_CONTAINER" 2>&1 | grep -c "CRITICAL"'
            not in text
        ), relative_path


def test_deploy_rejects_stale_or_mixed_wazuh_certificate_bundles():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")

    # The official Wazuh generator copies root-ca.* to root-ca-manager.*.
    # FAST must reject a bundle where those files no longer match and must
    # validate leaf certificates against that same CA before reusing them.
    assert "certificate_bundle_is_consistent" in deploy
    assert "root-ca-manager.pem" in deploy
    assert "root-ca-manager.key" in deploy
    assert "cmp -s /certificates/root-ca.pem /certificates/root-ca-manager.pem" in deploy
    assert "cmp -s /certificates/root-ca.key /certificates/root-ca-manager.key" in deploy
    assert "openssl verify -CAfile /certificates/root-ca.pem" in deploy

    # Repair must release old bind mounts, remove the entire stale set,
    # regenerate it, and remount fresh files into recreated containers.
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

    # The success banner must only appear after the output/TLS check.
    check_call = deploy.rindex("if ! wait_for_filebeat_indexer_healthy; then")
    success_banner = deploy.index("✅ DEPLOYMENT COMPLETE")
    assert check_call < success_banner
