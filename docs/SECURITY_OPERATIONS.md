# FAST Security Operations Layer

The `feature/fast-ui` branch adds six product-focused capabilities without replacing the existing IOC collector, Wazuh rules, deployment flow, or legacy API behavior.

## 1. Authentication and RBAC

FAST authentication is **opt-in** so existing local/demo installs keep working. Enable it in `.env`:

```env
FAST_AUTH_ENABLED=1
FAST_SESSION_SECRET=<long-random-secret>
FAST_ADMIN_USER=admin
FAST_ADMIN_PASSWORD=<strong-password>
```

Roles:

- `viewer` — read-only security visibility.
- `analyst` — viewer access plus incident status/assignee/notes updates.
- `admin` — analyst access plus intelligence sync and audit-log visibility.

Additional users can be supplied through `FAST_USERS_JSON`. When the UI is served over HTTPS, set `FAST_SESSION_COOKIE_SECURE=1`.

The browser never receives Wazuh API or Indexer credentials. State-changing authenticated API requests require the session CSRF token.

## 2. Incident workflow and correlation

`Incidents` reads **real FAST alerts from Wazuh Indexer**. FAST stores only analyst-owned metadata in `fast_operations.db`:

- status (`new`, `investigating`, `resolved`, `false_positive`)
- assignee
- analyst notes
- updater and update time

The original Wazuh document is not modified. Correlation is read-only and groups multiple real FAST alert documents that share an asset/source within the correlation window. It never creates synthetic Wazuh alerts.

## 3. Asset risk

Architecture > Asset Catalog now combines the live Wazuh agent inventory with real FAST detections from the last 24 hours. The risk score is intentionally transparent and limited in scope:

- agent connectivity state
- maximum FAST rule level
- FAST alert volume
- distinct FAST rule diversity

It is **not** presented as a vulnerability or enterprise risk score until vulnerability/compliance sources are integrated.

## 4. Detection engineering health

The Detections view now displays:

- rule ID / name / MITRE mapping
- configured rule level/status
- exact Wazuh alert count for the last 24 hours
- latest trigger time and latest agent
- connected Wazuh agent coverage

Agent coverage describes Wazuh connectivity and does not claim every rule applies to every OS.

## 5. Detection Validation Lab

The former Attack Simulation screen is now a validation workflow. Existing repo scripts are still launched from the correct lab terminal, not from the public web UI. FAST then checks Wazuh for the expected rule:

- `PASS` — expected rule fired within `FAST_VALIDATION_FRESH_MINUTES`
- `STALE` — rule was seen in the last 24 hours but outside the freshness window
- `WAITING` — no matching real alert was seen

This preserves the real flow:

```text
Attack → Wazuh Agent → Wazuh SIEM → Alert → FAST
```

## 6. Audit trail

FAST records product-side actions such as:

- login/logout
- IOC intelligence sync
- IOC export
- incident workflow updates

The audit table is visible in System Health. When authentication is enabled it is Admin-only.

## Data boundaries

Wazuh remains authoritative for agents and alert telemetry. FAST does not write to Wazuh through these product features and the web container still receives no Docker socket. Analyst state and audit records are stored separately in `FAST_OPS_DB_PATH`.

## Test / deploy

```bash
cd ~/fast-test-ui
git pull --ff-only origin feature/fast-ui
./bin/fast restart
./bin/fast status
```

For authentication testing, edit `.env`, restart FAST, and sign in through the new login page. Leave `FAST_AUTH_ENABLED=0` if you first want to regression-test the existing local workflow unchanged.
