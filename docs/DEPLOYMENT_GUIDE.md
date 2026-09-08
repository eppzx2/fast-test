# F.A.S.T. — Deployment Guide

This guide covers a clean FAST deployment: Wazuh Manager/Indexer/Dashboard,
IOC collection, the FAST web dashboard, Linux/Windows agents, health checks,
and the Linux detection test prerequisites.

## Recommended topology

Use a cloud Ubuntu VM for FAST/Wazuh and connect endpoints over Tailscale. This
avoids exposing Wazuh management ports directly to the public Internet.

```text
Endpoint/Target ── Tailscale ──> Cloud VM
                               ├─ Wazuh Manager
                               ├─ Wazuh Indexer
                               ├─ Wazuh Dashboard
                               └─ FAST IOC Collector
```

## Requirements

- Docker + Docker Compose plugin
- Git
- about 4 GB RAM minimum for the single-node Wazuh stack
- about 10 GB free disk for a practical test deployment

Check:

```bash
docker --version
docker compose version
docker info >/dev/null && echo Docker_OK
git --version
```

## 1. Optional: Tailscale

Install Tailscale on the Manager VM and the endpoint/runner hosts. On Linux:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4
```

Use the VM's Tailscale IPv4 as the Manager address for agents.

## 2. Clone and configure FAST

```bash
git clone <this-repo-url> fast-test
cd fast-test
```

Threat feeds are fetched independently. For the supported current URLhaus and
MalwareBazaar Community APIs, configure a free abuse.ch Auth-Key locally:

```bash
cp .env.example .env
# edit .env:
# ABUSECH_AUTH_KEY=<your-key>
```

`.env` is ignored by git. Without the key, FAST keeps legacy compatibility
fallbacks where possible, but the supported MalwareBazaar API requires the key.

The FAST web dashboard binds to `127.0.0.1:5000` by default. To intentionally
expose it on a Tailscale interface, set this in `.env`:

```text
FAST_WEB_BIND=<MANAGER_TAILSCALE_IP>
```

## 3. Deploy

Recommended entrypoint:

```bash
./bin/fast up --ip <MANAGER_TAILSCALE_IP>
```

Or let FAST auto-detect an address:

```bash
./bin/fast up
```

The deployment:

1. clones the pinned Wazuh v4.9.0 Docker stack if missing;
2. validates the Wazuh TLS bundle;
3. automatically deletes/regenerates a stale, incomplete, or mixed certificate
   set while preserving named data volumes;
4. starts Manager/Indexer/Dashboard;
5. verifies Manager processes and current-start logs;
6. builds the IOC Collector image;
7. fetches, normalizes, deduplicates, scores, and stores IOCs;
8. validates the IPv4/CIDR Wazuh CDB export;
9. installs the CDB list and FAST custom rules;
10. runs `wazuh-analysisd -t` before the final Manager restart;
11. verifies Manager health after restart;
12. verifies Filebeat can securely publish alerts to the Wazuh Indexer before
    reporting deployment success.

If you explicitly want to discard the current TLS files and regenerate them:

```bash
./bin/fast up --reset-certs
```

This does **not** delete named Wazuh/Indexer data volumes.

For an offline/demo IOC seed using the bundled fixture instead of live feeds:

```bash
./bin/fast demo
```

## 4. Verify health

```bash
./bin/fast status
```

Important healthy lines:

```text
Wazuh Manager health (current start only): healthy
Filebeat -> Indexer alert pipeline: healthy
FAST                 [ HEALTHY ]
```

`HEALTHY` requires the Manager, Indexer, and Dashboard containers to be running,
Manager analysis processes to be healthy, and the Filebeat → Indexer alert path
to pass its output test.

If Filebeat → Indexer is unhealthy, Threat Hunting can be empty even while the
Manager itself is generating alerts. FAST deliberately reports that state as
`DEGRADED`.

## 5. Wazuh Dashboard

Open:

```text
https://<MANAGER_TAILSCALE_IP>
```

Upstream Wazuh 4.9 single-node defaults are:

```text
username: admin
password: SecretPassword
```

Change default credentials and restrict access before production/internet use.
The generated certificates are local/self-signed, so a browser trust warning is
normal in a lab deployment.

## 6. FAST IOC web dashboard

When started through `./bin/fast up`, it runs as the
`fast-ioc-collector-web` container.

Default URL on the Manager host:

```text
http://127.0.0.1:5000
```

If `FAST_WEB_BIND` was deliberately set to a Tailscale address, use:

```text
http://<MANAGER_TAILSCALE_IP>:5000
```

Useful API routes:

- `GET /api/health`
- `GET /api/iocs`
- `POST /api/fetch`
- `GET /api/export?format=csv|json`
- `GET /api/stats`

Flask debug mode is disabled by default.

## 7. Connect a Linux target

On the Linux endpoint:

```bash
cd fast-test
sudo ./linux/install-wazuh-agent.sh --ip <MANAGER_TAILSCALE_IP>
```

Optional name:

```bash
sudo ./linux/install-wazuh-agent.sh --ip <MANAGER_TAILSCALE_IP> --name my-linux-target
```

The installer checks Manager reachability, installs Wazuh Agent 4.9.0, starts
the service, and reports recent connection logs.

## 8. Connect a Windows endpoint

Open PowerShell as Administrator:

```powershell
cd fast-test\windows
.\install-wazuh-agent.ps1 -ManagerIP "<MANAGER_TAILSCALE_IP>"
```

Optional name:

```powershell
.\install-wazuh-agent.ps1 -ManagerIP "<MANAGER_TAILSCALE_IP>" -AgentName "my-windows-host"
```

The installer handles reinstall/upgrade service state, accepts MSI success code
`3010` as reboot-required success, starts `WazuhSvc`, and checks recent logs.

Confirm agents from the Manager:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Agents should show `Active`.

## 9. Prepare a Linux target for FAST detection simulations

The SSH failed-authentication stress test, port-scan test, and LOLBin test are
Linux-oriented. Run once on the **Linux target**:

```bash
cd ~/fast-test
git pull
sudo ./tests/acceptance/sim/setup_prereqs.sh
```

The setup:

- ensures OpenSSH is running;
- ensures the Wazuh agent collects journald;
- installs a **logging-only** `mangle/PREROUTING` rule for FAST test ports
  `56001..56012` with the `FAST_PORTSCAN` marker;
- does not add ACCEPT/DROP policy and does not enable UFW;
- installs/enables auditd and watches `execve` with key `audit-wazuh-c`;
- ensures the Wazuh agent collects `/var/log/audit/audit.log` using audit format;
- backs up the agent config once before modifying it;
- restarts the agent only when its collection config changes.

Current detection IDs:

```text
SSH failed authentication:  Wazuh 5760 -> FAST 100200 (level 10)
Port-scan probe:            Wazuh 4100 -> FAST 100210 (level 3)
Port-scan correlation:      FAST 100210 -> FAST 100211 (level 7, 8+ probes/60s)
LOLBin signal:              Wazuh 80792 -> FAST 100220 (level 6)
LOLBin confirmation:        FAST 100220 -> FAST 100221 (level 12)
```

Important: `100200` is currently a **same-event child** of Wazuh rule `5760`.
The brute-force simulator still sends multiple verified failed-password attempts
as a repeatable stress scenario, but FAST `100200` itself is no longer a
5-events-in-60-seconds correlation rule.

Simulation details: `docs/SIMULATION_GUIDE.md`.

## 10. Refresh IOCs safely

```bash
./refresh_iocs.sh
```

The refresh script fails rather than silently replacing the live CDB when:

- every provider returns zero data;
- no usable IPv4/CIDR CDB can be produced;
- Wazuh analysis validation fails;
- the Manager does not recover after restart;
- Filebeat → Indexer output is unhealthy.

Example cron entry:

```cron
0 3 * * * /full/path/to/fast-test/refresh_iocs.sh >> /var/log/fast-refresh.log 2>&1
```

## Troubleshooting

### Docker permission denied

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker ps
```

A new login/SSH session may be required for group membership to apply.

### Mixed/stale TLS certificate error

Normally FAST auto-detects and regenerates the bundle. To force it:

```bash
./bin/fast up --reset-certs
```

### Threat Hunting says `No results`

First check:

```bash
./bin/fast status
```

If the Filebeat → Indexer pipeline is unhealthy, fix that before debugging agent
rules. If it is healthy, confirm Manager-side alerts:

```bash
docker exec single-node-wazuh.manager-1 \
  sh -c 'wc -l /var/ossec/logs/alerts/alerts.json; tail -n 10 /var/ossec/logs/alerts/alerts.json'
```

### SSH base alert appears but FAST `100200` does not

Confirm the deployed custom rule file contains `100200` with `<if_sid>5760</if_sid>`
and validate the Manager configuration:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
```

### Agent not Active

Linux target:

```bash
sudo systemctl status wazuh-agent --no-pager
sudo grep -aE 'Connected to the server|ERROR|WARNING' /var/ossec/logs/ossec.log | tail -30
```

Manager:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

## Stop / remove

Preserve data:

```bash
./bin/fast down
```

A destructive full Wazuh reset removes named volumes and indexed/agent state.
Only do this intentionally:

```bash
cd wazuh-docker/single-node
docker compose down -v
cd ../..
rm -rf wazuh-docker
```

For most clean re-tests, `./bin/fast up --reset-certs` is enough and preserves
data.

**Last updated:** 2026-09-08
