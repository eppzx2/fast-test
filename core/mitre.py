"""MITRE ATT&CK mapping helpers for FAST detections.

FAST maps only techniques that are explicitly declared by its current custom
rules. The module does not claim full ATT&CK coverage and does not generate
synthetic detections. Runtime observation counts come from the Wazuh Indexer.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.detections import DETECTION_BY_ID, DETECTIONS

ENTERPRISE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance"},
    {"id": "TA0042", "name": "Resource Development"},
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"},
]

TACTIC_BY_ID = {item["id"]: item for item in ENTERPRISE_TACTICS}

TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic_ids": ["TA0006"],
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic_ids": ["TA0007"],
    },
    "T1036.003": {
        "id": "T1036.003",
        "name": "Masquerading: Rename System Utilities",
        "tactic_ids": ["TA0005"],
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic_ids": ["TA0011"],
    },
}


def _technique_detail(technique_id: str) -> dict:
    technique_id = str(technique_id or "").strip()
    base = TECHNIQUES.get(technique_id) or {
        "id": technique_id,
        "name": "Mapped ATT&CK technique",
        "tactic_ids": [],
    }
    tactics = [TACTIC_BY_ID[tactic_id] for tactic_id in base["tactic_ids"] if tactic_id in TACTIC_BY_ID]
    return {
        **base,
        "tactics": [{"id": item["id"], "name": item["name"]} for item in tactics],
    }


def technique_details(technique_ids) -> list[dict]:
    """Normalize technique IDs into stable FAST-owned ATT&CK metadata."""
    seen = set()
    details = []
    for value in technique_ids or []:
        technique_id = str(value or "").strip()
        if not technique_id or technique_id in seen:
            continue
        seen.add(technique_id)
        details.append(_technique_detail(technique_id))
    return details


def enrich_detection(detection: dict) -> dict:
    """Attach named tactic/technique metadata without changing rule semantics."""
    details = technique_details(detection.get("mitre") or [])
    tactic_map = {}
    for technique in details:
        for tactic in technique.get("tactics", []):
            tactic_map[tactic["id"]] = tactic
    return {
        **detection,
        "mitre_mapping": {
            "techniques": details,
            "tactics": list(tactic_map.values()),
        },
    }


def enrich_alert(alert: dict) -> dict:
    """Attach the canonical FAST rule mapping to a real Wazuh alert."""
    rule_id = str(alert.get("rule_id") or "")
    detection = DETECTION_BY_ID.get(rule_id)
    if not detection:
        return {**alert, "mitre_mapping": {"techniques": [], "tactics": []}}
    mapped = enrich_detection(detection)["mitre_mapping"]
    return {
        **alert,
        "mitre_mapping": mapped,
        "wazuh_mitre_ids": list(alert.get("mitre_ids") or []),
    }


def _latest_timestamp(values: list[str]) -> str:
    parsed = []
    for value in values:
        if not value:
            continue
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
            parsed.append((dt, str(value)))
        except (TypeError, ValueError):
            continue
    return max(parsed, default=(None, ""), key=lambda item: item[0] or datetime.min.replace(tzinfo=timezone.utc))[1]


def build_mitre_coverage(activity: list[dict], *, window_minutes: int = 1440) -> dict:
    """Build a truthful ATT&CK coverage view from rule mappings + Wazuh activity.

    "mapped" means a FAST rule declares the ATT&CK technique. "observed" means
    at least one real alert for that mapped rule was stored in Wazuh during the
    requested window. Neither state implies prevention or complete ATT&CK
    coverage.
    """
    by_rule = {str(item.get("rule_id") or ""): item for item in activity or []}
    technique_rows: dict[str, dict] = {}

    for detection in DETECTIONS:
        metric = by_rule.get(detection["id"], {})
        count = int(metric.get("count") or 0)
        last_triggered = str(metric.get("last_triggered") or "")
        last_agent = str(metric.get("last_agent") or "")
        for technique in technique_details(detection.get("mitre") or []):
            row = technique_rows.setdefault(
                technique["id"],
                {
                    **technique,
                    "rule_ids": [],
                    "detections": [],
                    "alerts": 0,
                    "last_triggered_values": [],
                    "last_agents": [],
                },
            )
            row["rule_ids"].append(detection["id"])
            row["detections"].append(detection["name"])
            row["alerts"] += count
            if last_triggered:
                row["last_triggered_values"].append(last_triggered)
            if last_agent:
                row["last_agents"].append(last_agent)

    techniques = []
    for row in technique_rows.values():
        techniques.append(
            {
                "id": row["id"],
                "name": row["name"],
                "tactic_ids": row["tactic_ids"],
                "tactics": row["tactics"],
                "rule_ids": sorted(set(row["rule_ids"])),
                "detections": sorted(set(row["detections"])),
                "alerts": row["alerts"],
                "observed": row["alerts"] > 0,
                "last_triggered": _latest_timestamp(row["last_triggered_values"]),
                "last_agents": sorted(set(row["last_agents"])),
            }
        )
    techniques.sort(key=lambda item: item["id"])

    tactics = []
    for tactic in ENTERPRISE_TACTICS:
        mapped_techniques = [item for item in techniques if tactic["id"] in item.get("tactic_ids", [])]
        alerts = sum(int(item.get("alerts") or 0) for item in mapped_techniques)
        rule_ids = sorted({rule_id for item in mapped_techniques for rule_id in item.get("rule_ids", [])})
        tactics.append(
            {
                **tactic,
                "mapped": bool(mapped_techniques),
                "observed": alerts > 0,
                "alerts": alerts,
                "technique_count": len(mapped_techniques),
                "detection_count": len(rule_ids),
                "technique_ids": [item["id"] for item in mapped_techniques],
            }
        )

    return {
        "framework": "MITRE ATT&CK Enterprise",
        "scope": "Current FAST custom detections only",
        "window_minutes": int(window_minutes),
        "summary": {
            "mapped_tactics": sum(1 for item in tactics if item["mapped"]),
            "observed_tactics": sum(1 for item in tactics if item["observed"]),
            "mapped_techniques": len(techniques),
            "observed_techniques": sum(1 for item in techniques if item["observed"]),
            "alerts": sum(int(item.get("alerts") or 0) for item in techniques),
        },
        "tactics": tactics,
        "techniques": techniques,
        "note": "Mapped means a FAST rule declares the technique; observed means Wazuh stored at least one real alert in the selected window.",
    }
