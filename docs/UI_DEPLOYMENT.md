# FAST UI Deployment (feature/fast-ui)

This guide deploys the UI development branch without changing the existing
`main` FAST/Wazuh deployment.

## Goal

The preview runs in its own Docker container on `127.0.0.1:5001` and is exposed
through **Tailscale Funnel** as a public HTTPS URL. The IOC database used by the
preview is a copy, not the live `main` database.

```text
Teacher/browser
      |
      | public HTTPS
      v
https://<node>.<tailnet>.ts.net
      |
      | Tailscale Funnel
      v
127.0.0.1:5001
      |
      v
fast-ui-preview container
      |
      v
preview IOC database copy
```

The existing Wazuh stack and the normal `~/fast-test` deployment continue to
run independently.

## First-time checkout

On the Cloud Ubuntu host:

```bash
cd ~
git clone --branch feature/fast-ui --single-branch \
  https://github.com/eppzx2/fast-test.git fast-test-ui
cd ~/fast-test-ui
```

If this checkout already exists:

```bash
cd ~/fast-test-ui
git pull --ff-only origin feature/fast-ui
```

## Deploy

Run one command:

```bash
./deploy-fast-ui.sh
```

The script:

1. safely updates `feature/fast-ui` when there are no tracked local changes;
2. checks Docker and Tailscale;
3. copies the current IOC database into an isolated preview data directory;
4. builds the dedicated `docker/fast-ui.Dockerfile` image;
5. starts `fast-ui-preview` bound only to `127.0.0.1:5001`;
6. waits for `/api/health` to become healthy;
7. enables Tailscale Funnel in the background;
8. prints the public HTTPS URL.

Typical output ends with:

```text
FAST UI DEPLOYED
Public URL:      https://your-node.your-tailnet.ts.net
Local backend:   http://127.0.0.1:5001
Wazuh button:    https://100.x.y.z
```

Anyone with the public URL can open the FAST UI without installing Tailscale.
The `Open Wazuh Dashboard` button uses the Manager's Tailscale address by
default, so that button is only usable from a device that can reach the tailnet
unless another Wazuh URL is explicitly configured.

## Existing IOC data

By default, the script looks for:

```text
~/fast-test/ioc_database.db
```

and copies it to:

```text
~/.local/share/fast-ui-preview/ioc_database.db
```

This prevents UI testing or the `Refresh Threat Intelligence` button from
changing the live `main` database.

To seed the preview from another database:

```bash
FAST_UI_DB_SOURCE=/path/to/ioc_database.db ./deploy-fast-ui.sh
```

## Wazuh Dashboard button

The script automatically points the button at:

```text
https://<cloud-ubuntu-tailscale-ip>
```

To override it:

```bash
FAST_WAZUH_DASHBOARD_URL=https://your-wazuh-address ./deploy-fast-ui.sh
```

## Port override

Port `5001` is used so the existing FAST web container on `5000` is not touched.
To use another local port:

```bash
FAST_UI_PORT=5010 ./deploy-fast-ui.sh
```

## Troubleshooting

### Funnel is not enabled

Tailscale Funnel may need to be allowed for the tailnet. The deploy script keeps
the preview container running even if Funnel setup fails. After enabling Funnel,
rerun:

```bash
./deploy-fast-ui.sh
```

### Check the preview container

```bash
docker ps --filter name=fast-ui-preview
docker logs --tail 100 fast-ui-preview
```

### Check Funnel

```bash
tailscale funnel status
```

### Stop only the UI preview

```bash
docker rm -f fast-ui-preview
```

If desired, disable the Funnel mapping separately using the Tailscale CLI. Do
not run a global Funnel reset when other Funnel routes are in use.

## Security boundary

The public UI container is intentionally **not** given the Docker socket and it
cannot run `./bin/fast up`, restart Wazuh, remove volumes, or change host-level
services. This keeps the public presentation UI separate from privileged FAST
administration while the feature is under development.
