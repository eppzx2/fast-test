# F.A.S.T. — OSINT Threat Aggregation + Fast-Deploy SIEM

**F.A.S.T.** = Fully Automated SIEM & Threat-Intel Tool.

FAST combines OSINT threat feeds with a pinned Wazuh 4.9.0 single-node SIEM.
It fetches and normalizes IOCs, deduplicates/scorers them in SQLite, produces a
validated Wazuh CDB list, loads custom detections, and verifies the
Manager → Filebeat → Indexer alert path.

## Quick start

```bash
git clone <this-repo-url> fast-test
cd fast-test
./bin/fast up
./bin/fast status
```

Useful commands:

```bash
./bin/fast up                 # deploy/start FAST
./bin/fast up --reset-certs   # force a clean Wazuh TLS bundle rebuild
./bin/fast down               # stop while preserving named data volumes
./bin/fast restart
./bin/fast status
./refresh_iocs.sh             # fetch fresh IOCs + verify Manager/Indexer pipeline
```

Full deployment steps: `docs/DEPLOYMENT_GUIDE.md`.

## Threat feeds

FAST integrates:

| Feed | Data | Access |
|---|---|---|
| Feodo Tracker | botnet C2 IPv4s | public feed |
| URLhaus | malicious URLs | current Community export uses abuse.ch Auth-Key; legacy compatibility fallback retained |
| MalwareBazaar | malware hashes/metadata | current Community API requires free abuse.ch Auth-Key |
| Spamhaus DROP | malicious IPv4 netblocks | current JSON DROP dataset |

For the supported abuse.ch APIs, create a free Auth-Key and keep it local:

```bash
cp .env.example .env
# edit .env and set ABUSECH_AUTH_KEY=...
```

`.env` is ignored by git. `python-dotenv` loads it for local CLI and the
collector container because the project is mounted at `/app`. If a provider is
unavailable, other feeds continue; however the CLI now exits non-zero when
**all** feeds fail so deploy/refresh cannot silently claim success with no new
data.

## Detection pipeline

```text
Threat feeds
   ↓
fetch → normalize UTC → dedup/merge feeds+tags → confidence score
   ↓
validated IPv4/CIDR CDB list
   ↓
Wazuh Manager rules/analysisd
   ↓
alerts.json → Filebeat (TLS verified) → Wazuh Indexer → Threat Hunting
```

FAST health checks include the Filebeat → Indexer output test. A running
Manager alone is not enough for `FAST [ HEALTHY ]`.

### Custom simulation detections

| Rule | Detection | Level |
|---|---|---:|
| `100200` | 5 SSH failed-password events (`5760`) from one source in 60s | 10 |
| `100210` | individual deterministic FAST port-scan probe | 3 |
| `100211` | 8+ probes from one source in 60s | 7 |
| `100220` | `httpd`-named process from unexpected path | 6 |
| `100221` | confirmed wget-masquerading LOLBin | 12 |

Brute force and port scan have been validated end-to-end on the project Linux
target. See `docs/SIMULATION_GUIDE.md` and `docs/runbook.md` for the current
commands and troubleshooting stages.

## Target agents

Linux:

```bash
sudo ./linux/install-wazuh-agent.sh --ip <MANAGER_IP>
```

Windows (elevated PowerShell):

```powershell
.\windows\install-wazuh-agent.ps1 -ManagerIP "<MANAGER_IP>"
```

The installers now fail if the service does not start, perform connection
checks, and handle reinstall/upgrade edge cases more safely.

## Web dashboard

The Flask UI is available on port 5000. Docker binds it to **localhost only by
default**:

```text
http://127.0.0.1:5000
```

To intentionally expose it on another interface, set `FAST_WEB_BIND` in `.env`
(for example a Tailscale address) before `./bin/fast up`. Flask debug mode is
off by default.

API routes:

- `GET /api/health`
- `GET /api/iocs`
- `POST /api/fetch`
- `GET /api/export?format=csv|json`
- `GET /api/stats`

## Collector CLI

```bash
python -m pip install -r requirements.txt
python cli.py --init-db
python cli.py --fetch
python cli.py --show
python cli.py --export csv
python cli.py --export json
python cli.py --export wazuh
```

Wazuh CDB export accepts only validated IPv4/IPv4-CIDR keys; malformed and
IPv6 values are skipped rather than written into the live CDB file.

## Data semantics

SQLite uniqueness is `(ioc_value, ioc_type)`. Repeated observations:

- merge distinct source feeds;
- merge tags without duplicates;
- keep the earliest `first_seen`;
- keep the latest `last_seen`;
- recalculate confidence from distinct feed count (`25/50/75/100`).

Normalized timestamps are stored as ISO-8601 UTC values.

## Tests and CI

Every push to `main` runs `.github/workflows/ci.yml` with:

- Python syntax compilation;
- Bash syntax validation for deploy/management/agent/simulation scripts;
- deterministic unit tests;
- static Wazuh rule/deploy regression tests.

External-feed live tests are disabled in ordinary CI and can be enabled
explicitly:

```bash
FAST_LIVE_FEEDS=1 python -m pytest tests/test_fetchers.py -v
```

Live Wazuh acceptance tests require a real Manager + Linux target:

```bash
export TARGET_HOST=<TARGET_IP>
export TARGET_SSH_USER=<TARGET_USER>
python -m pytest tests/acceptance -v
```

## Security notes

The upstream Wazuh 4.9 Docker compose uses default credentials and exposes
several service ports. Before production/internet exposure:

- change the upstream default Wazuh credentials;
- restrict Indexer/API/agent ports with the cloud firewall/security group;
- prefer Tailscale/VPN for administration;
- keep `.env` secrets out of git;
- do not bind the FAST Flask UI publicly unless intentionally protected.

FAST automatically detects/regenerates mixed or stale Wazuh TLS certificate
bundles while preserving named Docker data volumes.

## Project layout

```text
core/                         IOC fetch/normalize/db/scoring/export
bin/fast                      unified lifecycle/status CLI
deploy.sh                     Wazuh + collector deployment
docker/rules/local_rules.xml  IOC + simulation detection rules
refresh_iocs.sh               safe IOC refresh
linux/                        Linux Wazuh agent installer
windows/                      Windows Wazuh agent installer
tests/                        unit/static + live acceptance tests
docs/                         deployment/runbook/simulation guides
app.py                        Flask IOC dashboard
```
