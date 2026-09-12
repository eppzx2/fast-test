# FAST Platform UI

The platform UI keeps the existing Overview and IOC Database behavior, removes the duplicate Threat Feeds navigation entry, and adds security-operations views backed by real Wazuh telemetry.

## Detection Validation

FAST does **not** generate fake alerts and does not execute attack scripts from the browser. Use the existing scripts under `tests/acceptance/sim/` against the connected lab target. FAST checks `wazuh-alerts-*` in the Wazuh Indexer for the expected rule:

- `100200` — SSH failed authentication
- `100211` — correlated port scan
- `100221` — LOLBin / masquerading

Validation states are evidence-based: `PASS`, `STALE`, or `WAITING`.

The flow remains:

`Attack -> Wazuh Agent -> Wazuh SIEM -> Alert -> FAST`

## Incidents and correlation

The Incidents view turns real FAST/Wazuh alerts into triageable cases. FAST stores only analyst-owned metadata (status, assignee and notes) in a separate SQLite operations database. The original Wazuh alert is never modified.

The correlation layer groups repeated or multi-stage real FAST alerts by asset/source/time window. It is read-only and does not synthesize Wazuh events.

## Detection Engineering

The Detections view combines the static FAST rule catalogue with live Wazuh data: 24-hour alert counts, last trigger, latest agent and connected-agent coverage.

## Architecture and Asset Catalog

Architecture represents FAST as the platform, Wazuh as the active SIEM core, and TALON as an active FAST module. SOAR, PAM, EPM and DLP are explicitly labelled **Coming Soon / Future Integration**.

Asset Catalog calls the Wazuh server API and displays real agent ID, hostname, OS, IP, status, Wazuh version and last keepalive. FAST adds a transparent risk score using only agent health and real FAST detections from the last 24 hours. It is not presented as vulnerability risk until additional data sources exist.

## Authentication / RBAC

Authentication is opt-in to preserve existing local deployments. When enabled, FAST supports Viewer, Analyst and Admin roles, session authentication and CSRF checks for state-changing API requests. Wazuh credentials remain server-side.

See `docs/SECURITY_OPERATIONS.md` for configuration and role details.

## Audit trail

FAST records product-side actions such as login/logout, intelligence sync/export and incident workflow changes. The audit view is Admin-only when authentication is enabled.

## Connectivity

`docker/docker-compose.fast.yml` joins the Wazuh single-node Docker network (`single-node_default` by default), so the UI backend can use internal service DNS:

- Wazuh server API: `https://wazuh.manager:55000`
- Wazuh Indexer: `https://wazuh.indexer:9200`

The defaults match the official Wazuh Docker demo credentials. If those credentials are changed, set the matching `FAST_WAZUH_*` variables in the project's git-ignored `.env` file. Credentials are used only server-side and are never returned by the UI configuration APIs.

Self-signed TLS verification is disabled by default for the internal demo network. For a hardened deployment, set `FAST_WAZUH_VERIFY_TLS=1` or provide `FAST_WAZUH_CA_BUNDLE`.
