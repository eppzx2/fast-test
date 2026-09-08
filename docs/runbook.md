# FAST — Detection Runbook

Technical reference for the three Linux attack simulations used by FAST. The
rules live in `docker/rules/local_rules.xml`; the scripts live under
`tests/acceptance/sim/`.

## Current rule chain

| FAST rule | Scenario | Level | Base/parent | Trigger |
|---|---|---:|---|---|
| `100200` | SSH failed authentication | 10 | Wazuh `5760` | each failed-password event classified by Wazuh rule `5760` |
| `100210` | Port-scan probe | 3 | Wazuh `4100` | one `FAST_PORTSCAN` kernel/firewall event |
| `100211` | Port scan correlation | 7 | FAST `100210` | 8+ probes from one source IP in 60s |
| `100220` | LOLBin signal | 6 | Wazuh `80792` | process named `httpd` executing from a non-standard path |
| `100221` | LOLBin confirmed | 12 | FAST `100220` | same audit event also contains wget-style command-line evidence |

## SSH failed authentication

Wazuh 4.9 classifies the simulated failed-password event with rule `5760`
(`sshd: authentication failed`). FAST promotes that event to its own rule ID:

```xml
<rule id="100200" level="10">
  <if_sid>5760</if_sid>
  <description>FAST SSH failed authentication detected from source IP ($(srcip)).</description>
  ...
</rule>
```

This means Threat Hunting should show FAST rule `100200` for a matching SSH
failed-authentication event. Rule `100200` is currently a **same-event child**;
it does not use `frequency`, `timeframe`, `if_matched_sid`, or
`same_source_ip`.

The script is still named `simulate_brute_force.sh` because it generates a
repeated wrong-password scenario. It deliberately requires at least five real
authentication failures before declaring the simulation successful, but that
minimum belongs to the simulator's transport validation — it is not the trigger
condition of rule `100200`.

Expected chain:

```text
5760 -> 100200
```

## Port scan

`setup_prereqs.sh` installs a narrow **logging-only** iptables rule in
`mangle/PREROUTING` for reserved test ports `56001..56012`. It writes the
prefix `FAST_PORTSCAN` before normal Tailscale/UFW/filter decisions. It does
**not** add ACCEPT/DROP policy and does not enable UFW.

This makes the test deterministic without changing the target's firewall
policy. Wazuh rule `4100` handles the kernel/firewall event, FAST `100210`
marks each matching probe, and `100211` performs the same-source correlation.

Current correlation:

```text
100210 -> 100211
frequency=8
 time frame=60 seconds
same source IP
```

Expected final port-scan alert:

```text
Rule ID: 100211
Level: 7
Description: FAST possible port scan: 8+ probes from the same source IP (...) within 60 seconds.
```

## LOLBin

The target must run `auditd`, watch `execve` with key `audit-wazuh-c`, and have
the Wazuh agent collect `/var/log/audit/audit.log` with audit format.
`setup_prereqs.sh` configures and verifies these prerequisites automatically and
restarts the agent only when its collection configuration changes.

Wazuh rule `80792` is the audit command rule. FAST `100220` checks decoded
`audit.command`/`audit.exe`; `100221` is a same-event child that confirms
wget-style command-line evidence. The simulator copies the local `wget` binary
to `/tmp/httpd` and runs it against `127.0.0.1`, so the simulation has no
external-network dependency.

Expected chain:

```text
80792 -> 100220 -> 100221
```

## One-time target preparation

Run on the **Linux target that has the Wazuh agent**:

```bash
cd ~/fast-test
git pull
sudo ./tests/acceptance/sim/setup_prereqs.sh
```

Expected checks include:

```text
Wazuh agent already collects journald (or it is added)
FAST pre-filter port-scan logging rule present
auditd is watching execve syscalls (key=audit-wazuh-c)
Wazuh agent is configured to collect /var/log/audit/audit.log
```

The setup also creates a one-time backup at
`/var/ossec/etc/ossec.conf.fast-backup` before changing the agent collection
configuration.

## Manual simulations

SSH repeated-authentication and port scan are launched from a runner that can
reach the target:

```bash
./tests/acceptance/sim/simulate_brute_force.sh <TARGET_IP> nonexistent_bruteforce_test_user 8
./tests/acceptance/sim/simulate_port_scan.sh <TARGET_IP>
```

LOLBin runs **on the target itself**:

```bash
./tests/acceptance/sim/simulate_lolbin.sh
```

Expected FAST detections are `100200`, `100211`, and `100221`.

## Automated acceptance tests

Run from the Manager/repository checkout with access to the Docker socket:

```bash
export TARGET_HOST=<TARGET_IP>
export TARGET_SSH_USER=<target-ssh-user>
python -m pytest tests/acceptance -v
```

The tests snapshot the current Manager `alerts.json` position, run the
simulation, and wait only for **new** alerts. The acceptance suite is not part
of the normal offline GitHub Actions job because it requires a live Manager and
a real target endpoint.

## Quick diagnostics

On the Manager:

```bash
docker exec single-node-wazuh.manager-1 \
  sh -c "grep -E '\"id\":\"(5760|100200|100210|100211|80792|100220|100221)\"' \
  /var/ossec/logs/alerts/alerts.json | tail -50"
```

Validate custom rules/configuration:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
```

On the target:

```bash
sudo journalctl -k --since '2 minutes ago' | grep FAST_PORTSCAN
sudo auditctl -l | grep audit-wazuh-c
sudo grep -F '<location>/var/log/audit/audit.log</location>' /var/ossec/etc/ossec.conf
```

## Troubleshooting interpretation

- `5760` present but `100200` missing: Manager does not have the current FAST
  SSH child rule loaded, or rule validation/restart did not apply it.
- `100210` present but `100211` missing: fewer than 8 probes were correlated
  from one `srcip` inside 60 seconds.
- `80792` present but `100220` missing: inspect `audit.command` and `audit.exe`.
- `100220` present but `100221` missing: inspect the same audit event for the
  URL/`-O` wget-style evidence.
- Manager alerts present but Threat Hunting empty: check
  `./bin/fast status`; Filebeat → Indexer must be healthy.

## Scope

These simulation rules are Linux-oriented. A connected Windows agent is useful
for general Wazuh validation but does not replace the Linux target for sshd,
kernel/iptables, or auditd simulations.

**Last updated:** 2026-09-08
