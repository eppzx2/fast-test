# MITRE ATT&CK Mapping

FAST maps its current custom Wazuh detections to MITRE ATT&CK Enterprise and overlays real Wazuh alert activity on top of that static rule mapping.

## Current mappings

| FAST rule | Detection | MITRE technique | Tactic |
| --- | --- | --- | --- |
| 100200 | SSH Failed Authentication | T1110 Brute Force | Credential Access |
| 100211 | Port Scan | T1046 Network Service Scanning | Discovery |
| 100221 | LOLBin / Masquerading | T1036.003 Masquerading: Rename System Utilities | Defense Evasion |
| 100221 | LOLBin / Masquerading | T1105 Ingress Tool Transfer | Command and Control |

The mapping is based on the MITRE IDs already declared by the FAST Wazuh rules. It does not invent techniques from alert text.

## UI semantics

The MITRE ATT&CK tab shows all Enterprise tactics so the user can see both current coverage and gaps.

- **Mapped** means a current FAST rule explicitly declares at least one technique under that tactic.
- **Observed** means Wazuh stored at least one real alert for a mapped FAST rule inside the selected time window.
- **Not mapped** means the current FAST detection catalogue has no rule mapped to that tactic.

Mapped coverage is not the same as prevention, complete detection coverage, or proof that every technique variant is detected.

## Data sources

Static mapping source: `core/detections.py` plus `core/mitre.py`.

Live observation source: the Wazuh Indexer `wazuh-alerts-*` indices through the existing read-only `rule_activity()` integration.

The endpoint used by the UI is:

```text
GET /api/security/mitre?minutes=1440
```

The same canonical mapping is also attached to detection-health responses, detection-validation responses, incident cases, and the read-only FAST alert endpoint.

## Design boundary

The browser never modifies Wazuh or executes attack simulations. MITRE activity counts are derived only from real indexed Wazuh alerts. The feature is therefore a mapping and visibility layer, not an emulation engine.
