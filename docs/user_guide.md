# FAST IOC Collector — User Guide

This guide covers the IOC collector independently of the full Wazuh deployment.
For Wazuh deployment, agents, TLS recovery, and attack simulations, use
`docs/DEPLOYMENT_GUIDE.md` and `docs/SIMULATION_GUIDE.md`.

## Setup

```bash
git clone <repo-url> fast-test
cd fast-test
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

For the supported current URLhaus/MalwareBazaar Community APIs:

```bash
cp .env.example .env
# edit .env and set ABUSECH_AUTH_KEY=...
```

`.env` is git-ignored and loaded automatically by the collector.

## CLI

Initialize SQLite:

```bash
python cli.py --init-db
```

Fetch all feeds:

```bash
python cli.py --fetch
```

Each provider is isolated: one provider can fail while others continue. If
**every** provider returns zero data, or no records can be normalized/stored,
the command exits non-zero so automation does not treat an empty refresh as
success.

Inspect data:

```bash
python cli.py --show
python cli.py --count
```

Exports:

```bash
python cli.py --export csv
python cli.py --export json
python cli.py --export both
python cli.py --export wazuh
```

The Wazuh export writes `sample_output/ioc-ips` and succeeds only when there is
at least one usable IPv4/IPv4-CIDR IOC. Invalid and IPv6 values are skipped.

## Web dashboard

Local development:

```bash
python app.py
```

Default URL:

```text
http://localhost:5000
```

Flask debug mode is disabled unless `FAST_WEB_DEBUG=1` is explicitly set.

API routes:

- `GET /api/health` — liveness + IOC count
- `GET /api/iocs` — paginated/filtered IOC list
- `POST /api/fetch` — refresh feeds
- `GET /api/export?format=csv|json` — export file
- `GET /api/stats` — type/feed/confidence counts

`POST /api/fetch` returns HTTP 503 when all providers return zero data instead
of pretending the refresh succeeded.

When FAST runs the web dashboard through Docker, its host port binds to
`127.0.0.1:5000` by default. Set `FAST_WEB_BIND` in the local `.env` only when
you intentionally want another interface (for example a Tailscale IP).

## Data behavior

SQLite uniqueness is `(ioc_value, ioc_type)`. Repeated observations merge:

- provider names;
- tags;
- earliest `first_seen`;
- latest `last_seen`;
- confidence score based on distinct provider count.

Times are normalized to UTC ISO-8601.

## Safe refresh into Wazuh

For a deployed FAST environment use:

```bash
./refresh_iocs.sh
```

It validates the new CDB, runs Wazuh analysis validation, restarts the Manager,
and verifies Manager + Filebeat → Indexer health. It exits non-zero on failure.

## Tests

Offline deterministic suite:

```bash
python -m pytest -q tests --ignore=tests/acceptance
```

Provider live checks are opt-in:

```bash
FAST_LIVE_FEEDS=1 python -m pytest tests/test_fetchers.py -v
```

GitHub Actions runs Python compilation, Bash syntax checks, and the deterministic
offline suite on every push/PR.

## Troubleshooting

If one feed is empty, inspect collector logs and the provider's service status.
For current abuse.ch Community endpoints, confirm `ABUSECH_AUTH_KEY` exists in
your local `.env`. Do not commit that file.

If every feed fails, `python cli.py --fetch` now exits with status 1. Fix the
provider/network/auth problem before running Wazuh refresh again.

If the SQLite DB is disposable and you intentionally want a clean collector DB:

```bash
rm -f ioc_database.db
python cli.py --init-db
```

Do not remove Wazuh Docker volumes just to reset the IOC collector.

**Last updated:** 2026-09-06
