"""Hardening regressions for Wazuh CDB export."""

from pathlib import Path

from core import wazuh_export


def test_cdb_export_skips_invalid_and_ipv6_values(tmp_path):
    iocs = [
        {"ioc_value": "1.2.3.4", "ioc_type": "ip", "confidence_score": 25},
        {"ioc_value": "192.0.2.7/24", "ioc_type": "ip", "confidence_score": 25},
        {"ioc_value": "not-an-ip:evil", "ioc_type": "ip", "confidence_score": 100},
        {"ioc_value": "2001:db8::1", "ioc_type": "ip", "confidence_score": 100},
    ]
    assert wazuh_export.export_to_cdb_list(iocs, output_dir=str(tmp_path))
    lines = (Path(tmp_path) / "ioc-ips").read_text().splitlines()
    assert lines == ["1.2.3.4:1", "192.0.2.0/24:1"]


def test_cdb_stats_count_invalid_as_filtered(tmp_path):
    iocs = [
        {"ioc_value": "1.2.3.4", "ioc_type": "ip", "confidence_score": 25},
        {"ioc_value": "bad", "ioc_type": "ip", "confidence_score": 100},
    ]
    stats = wazuh_export.get_export_stats(iocs)
    assert stats == {"total": 2, "ip_type": 2, "exported": 1, "filtered_out": 1}
