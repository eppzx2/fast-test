# FAST UI and Tailscale access (feature/fast-ui)

This branch uses one FAST deployment. The UI is started by the normal FAST
command together with the Wazuh stack; there is no separate preview deployment.

## 1. Deploy FAST

```bash
./bin/fast up
```

This starts and verifies:

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Filebeat -> Indexer alert delivery
- IOC collection/database
- FAST web UI

Local endpoints are:

```text
FAST UI:         http://127.0.0.1:5000
Wazuh Dashboard: https://127.0.0.1:5601
```

The Wazuh Dashboard is intentionally bound only to localhost. The official
Wazuh Docker compose file normally publishes the Dashboard on host port 443,
but FAST overrides that mapping. This prevents a collision with Tailscale
Funnel, which uses HTTPS 443 for the public FAST UI.

## 2. Share the UI

After `./bin/fast up` is healthy, run:

```bash
./bin/fast-share
```

The helper configures two different Tailscale surfaces:

```text
Internet
   |
   | Tailscale Funnel / HTTPS 443
   v
https://<node>.<tailnet>.ts.net
   |
   v
127.0.0.1:5000  -> FAST UI

Tailnet devices only
   |
   | Tailscale Serve / HTTPS 8443
   v
https://<node>.<tailnet>.ts.net:8443
   |
   v
127.0.0.1:5601  -> Wazuh Dashboard
```

This separation is intentional. The FAST presentation UI can be public, while
the Wazuh administration interface is not exposed to the public internet.

Typical output:

```text
FAST ACCESS READY
Public FAST UI:    https://kali.example-tailnet.ts.net
Wazuh Dashboard:   https://kali.example-tailnet.ts.net:8443  (tailnet only)
Local FAST UI:     http://127.0.0.1:5000
Local Wazuh:       https://127.0.0.1:5601
```

Anyone with the Public FAST UI URL can open the FAST dashboard. A device must be
connected to the same tailnet to use the Wazuh Dashboard link.

## Open Wazuh button

The FAST UI derives the Wazuh URL automatically:

- when the FAST UI is opened locally, the button points to
  `https://localhost:5601`;
- when the FAST UI is opened through its `*.ts.net` Funnel URL, the button
  points to the same Tailscale hostname on port `8443`.

Therefore `Open Wazuh` works through the tailnet-only Tailscale Serve endpoint
without exposing Wazuh publicly. `FAST_WAZUH_DASHBOARD_URL` can still be set in
`.env` if an explicit URL is required.

## Sharing controls

Show the current configuration:

```bash
./bin/fast-share status
```

Disable only the FAST sharing endpoints:

```bash
./bin/fast-share off
```

Enable them again:

```bash
./bin/fast-share on
```

The helper does not run a global `tailscale funnel reset`, so unrelated
Tailscale routes on the machine are not intentionally removed.

## Existing/stale preview cleanup

Older UI development versions used a separate `fast-ui-preview` container on
port 5001. It is no longer part of the final deployment model. If that old
container still exists locally, it can be removed once:

```bash
docker rm -f fast-ui-preview 2>/dev/null || true
```

Running `./bin/fast-share` replaces the FAST Funnel mapping on HTTPS 443 with
the current UI backend on port 5000.

## Tailscale requirements

Tailscale Funnel requires MagicDNS, HTTPS certificates, and permission to use
Funnel in the tailnet. The sharing helper checks that Tailscale is connected and
that both local backends are reachable before changing the routes.

## Security boundary

The public FAST UI container does not receive the Docker socket and cannot run
host-level deployment commands. Wazuh remains behind Tailscale Serve and is not
published with Funnel. Deployment stays terminal-controlled through:

```bash
./bin/fast up
```

This keeps the public presentation surface separate from privileged SIEM
administration.
