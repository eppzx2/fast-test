# FAST — Detection Runbook

Technical reference for the three Linux attack simulations used by FAST. The
rules live in `docker/rules/local_rules.xml`; the scripts live under
`tests/acceptance/sim/`.

## Verified rule chain

| FAST rule | Scenario | Level | Verified base | Trigger |
|---|---|---:|---|---|
| `100200` | SSH brute force | 10 | Wazuh `5760` | 5 failed password authentications from one source IP in 60s |
| `100210` | Port-scan probe | 3 | Wazuh `4100` | one `FAST_PORTSCAN` kernel/firewall event |
| `100211` | Port scan | 7 | FAST `100210` | 8+ probes from one source IP in 60s |
| `100220` | LOLBin signal | 6 | Wazuh `80792` | process named `httpd` executing from a non-standard path |
| `100221` | LOLBin confirmed | 12 | FAST `100220` | same audit event also contains wget-style command-line evidence |

### SSH

Wazuh 4.9 classifies the simulated failed-password event with rule `5760`
(`sshd: authentication failed`). FAST intentionally correlates that concrete
rule rather than a broad group. Wazuh's own 4.9 ruleset also correlates `5760`
with rule `5763`; FAST uses its own 5 failures / 60 seconds threshold.

Live validation completed on the project target:

- base rule `5760` observed;
- FAST rule `100200` observed at level 10;
- source-IP correlation worked as intended.

### Port scan

`setup_prereqs.sh` installs a narrow **logging-only** iptables rule in
`mangle/PREROUTING` for reserved test ports `56001..56012`. It writes the
prefix `FAST_PORTSCAN` before normal Tailscale/UFW/filter decisions. It does
**not** add ACCEPT/DROP policy and does not enable UFW.

This makes the test deterministic without changing the target's firewall
policy. Wazuh rule `4100` handles the kernel/firewall event, FAST `100210`
marks each probe, and `100211` performs same-source correlation.

Live validation completed on the project target:

- multiple `100210` alerts observed;
- `100211` observed at level 7 after 8+ probes;
- source IP and destination test ports were decoded correctly.

### LOLBin

The target must run `auditd`, watch `execve` with key `audit-wazuh-c`, and have
the Wazuh agent collect `/var/log/audit/audit.log` using `log_format= audit`.
`setup_prereqs.sh` now configures and verifies all of this automatically and
restarts the agent only when its collection configuration changes.

Wazuh rule `80792` is the audit command rule. FAST `100220` checks decoded
`audit.command`/`audit.exe`; `100221` confirms wget-style command-line evidence.
The simulator copies the local `wget` binary to `/tmp/httpd` and runs it against
`127.0.0.1`, so the simulation has no external-network dependency.

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

## Manual simulations

Brute force and port scan are launched from a runner that can reach the target:

```bash
./tests/acceptance/sim/simulate_brute_force.sh <TARGET_IP> nonexistent_bruteforce_test_user 8
./tests/acceptance/sim/simulate_port_scan.sh <TARGET_IP>
```

LOLBin runs **on the target itself**:

```bash
./tests/acceptance/sim/simulate_lolbin.sh
```

Expected final FAST rule IDs are `100200`, `100211`, and `100221`.

## Automated acceptance tests

Run from the Manager/repository checkout with access to the Docker socket:

```bash
export TARGET_HOST=<TARGET_IP>
export TARGET_SSH_USER=<target-ssh-user>   # needed by remote LOLBin test
pytest tests/acceptance -v
```

The tests snapshot the current Manager `alerts.json` position, run the
simulation, and wait only for **new** alerts. If a test fails, its assertion
identifies whether the failure occurred at the base-signal stage or the FAST
correlation stage.

## Quick diagnostics

On the Manager:

```bash
docker exec single-node-wazuh.manager-1 \
  sh -c "grep -E '\"id\":\"(5760|100200|100210|100211|80792|100220|100221)\"' \
  /var/ossec/logs/alerts/alerts.json | tail -50"
```

On the target:

```bash
sudo journalctl -k --since '2 minutes ago' | grep FAST_PORTSCAN
sudo auditctl -l | grep audit-wazuh-c
sudo grep -F '<location>/var/log/audit/audit.log</location>' /var/ossec/etc/ossec.conf
```

## Scope

These simulation rules are Linux-oriented. A connected Windows agent is useful
for general Wazuh validation but does not replace the Linux target for sshd,
kernel/iptables, or auditd simulations.
