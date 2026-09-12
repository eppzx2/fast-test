# FAST Platform UI: live Wazuh views

The platform UI keeps the existing IOC/feeds/detections functionality and adds two read-only views backed by real Wazuh data.

## Attack Simulation

The UI does **not** generate fake alerts and does not execute attacks from the browser. Use the existing scripts under `tests/acceptance/sim/` against the connected lab target. The UI polls `wazuh-alerts-*` in the Wazuh Indexer and displays recent FAST-owned detections:

- `100200` — SSH failed authentication
- `100211` — correlated port scan
- `100221` — LOLBin / masquerading

The demo flow is:

`Attack Simulation -> Wazuh Agent -> Wazuh SIEM -> Alert -> FAST / TALON`

## Architecture and Asset Catalog

Architecture now represents FAST as the platform, Wazuh as the active SIEM core, and TALON as an active FAST module. SOAR, PAM, EPM and DLP are explicitly labelled **Coming Soon / Future Integration**.

Asset Catalog calls the Wazuh server API and displays real agent ID, hostname, OS, IP, status, Wazuh version and last keepalive. No synthetic assets are created if Wazuh is unavailable.

## Connectivity

`docker/docker-compose.fast.yml` joins the Wazuh single-node Docker network (`single-node_default` by default), so the UI backend can use internal service DNS:

- Wazuh server API: `https://wazuh.manager:55000`
- Wazuh Indexer: `https://wazuh.indexer:9200`

The defaults match the official Wazuh Docker demo credentials. If those credentials are changed, set the matching `FAST_WAZUH_*` variables in the project's git-ignored `.env` file. Credentials are used only server-side and are never returned by `/api/ui-config`.

Self-signed TLS verification is disabled by default for the internal demo network. For a hardened deployment, set `FAST_WAZUH_VERIFY_TLS=1` or provide `FAST_WAZUH_CA_BUNDLE`.
