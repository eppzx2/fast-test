# FAST Attack Simulation Guide

Use this guide to exercise FAST's three Linux detections against a target with
a connected Wazuh agent.

## Roles

- **Manager** — runs the FAST/Wazuh Docker stack and Threat Hunting.
- **Target** — Linux VM being exercised; Wazuh agent must be Active.
- **Runner** — machine that sends SSH/port probes. It can be the Manager.
- **LOLBin** is different: its simulator must run **on the Target** because
  auditd observes local process execution.

A Windows host agent can remain connected for normal Wazuh testing, but these
three simulations are Linux-specific.

## 1. Deploy / update Manager

```bash
cd ~/fast-test
git pull
./bin/fast up
./bin/fast status
```

Expected core status:

```text
Wazuh Manager health (current start only): healthy
Filebeat -> Indexer alert pipeline: healthy
FAST                 [ HEALTHY ]
```

## 2. Prepare the Linux Target once

```bash
cd ~/fast-test
git pull
sudo ./tests/acceptance/sim/setup_prereqs.sh
```

The setup is idempotent. It:

1. installs/enables OpenSSH;
2. adds a logging-only `mangle/PREROUTING` rule for FAST ports
   `56001..56012` with prefix `FAST_PORTSCAN`;
3. ensures the Wazuh agent collects `journald`;
4. installs/enables auditd and an `execve` rule with key `audit-wazuh-c`;
5. ensures the agent collects `/var/log/audit/audit.log` with audit format;
6. restarts the Wazuh agent only if its collection config changed.

It does not enable UFW or add firewall ACCEPT/DROP policy.

Confirm the target is Active from the Manager:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

## 3. SSH failed-authentication stress test

On the Runner:

```bash
sudo apt-get install -y sshpass   # only if missing
./tests/acceptance/sim/simulate_brute_force.sh <TARGET_IP> nonexistent_bruteforce_test_user 8
```

The simulator sends repeated wrong-password SSH attempts and counts only
attempts that really reached a verifiable authentication rejection. Transport
errors and timeouts are not silently counted as success. It also sleeps between
attempts to reduce OpenSSH per-source penalty interference.

Current detection behavior:

```text
5760    sshd: authentication failed
100200  FAST SSH failed authentication detected from source IP (...)   level 10
```

`100200` is a same-event child of Wazuh rule `5760` using `<if_sid>5760</if_sid>`.
It is **not** currently a 5-events/60-seconds correlation rule. The simulator
still requires at least five real authentication failures so the repeated-attack
scenario is meaningful and transport failures are caught.

## 4. Port-scan test

On the Runner:

```bash
./tests/acceptance/sim/simulate_port_scan.sh <TARGET_IP>
```

If root + nmap are available it uses a SYN scan. Without root it uses an nmap
TCP connect scan. If nmap is unavailable, it falls back to `/dev/tcp` probes.
All paths target the reserved FAST ports `56001..56012`.

Expected Threat Hunting chain:

```text
100210  FAST port-scan probe observed ...   level 3
100211  FAST possible port scan ...         level 7
```

`100211` is the actual correlation rule: it fires after 8+ `100210` probe events
from the same source IP within 60 seconds.

Target-side confirmation:

```bash
sudo journalctl -k --since '2 minutes ago' | grep FAST_PORTSCAN
```

## 5. LOLBin test

Run **on the Target itself**:

```bash
cd ~/fast-test
git pull
./tests/acceptance/sim/simulate_lolbin.sh
```

The script copies the local `wget` binary to `/tmp/httpd`, executes it with
wget-style arguments against loopback, waits briefly for audit/log collection,
and removes its temporary files. It does not require Internet access.

Expected Threat Hunting chain:

```text
80792   Audit command
100220  process presenting as httpd from a non-standard path   level 6
100221  LOLBin confirmed with wget-style arguments             level 12
```

Target prerequisites can be checked directly:

```bash
sudo systemctl is-active auditd
sudo auditctl -l | grep audit-wazuh-c
sudo grep -F '<location>/var/log/audit/audit.log</location>' /var/ossec/etc/ossec.conf
```

## 6. Automated acceptance suite

Run from the Manager/repository checkout:

```bash
export TARGET_HOST=<TARGET_IP>
export TARGET_SSH_USER=<TARGET_USER>
python -m pytest tests/acceptance -v
```

The acceptance suite is a live-environment suite. It snapshots the current
Manager `alerts.json` line count before a simulation and only considers alerts
appended after that point. If the Manager is unavailable, or required target
environment variables are missing, tests skip rather than contaminating the
offline unit suite.

The normal GitHub Actions workflow intentionally runs only deterministic offline
checks and excludes `tests/acceptance`.

## Troubleshooting matrix

| Symptom | Check |
|---|---|
| No SSH base alert | target `journalctl -u ssh`; agent Active; journald collection |
| `5760` but no `100200` | deployed rule `100200` must use `<if_sid>5760</if_sid>`; run `wazuh-analysisd -t` |
| SSH simulator reports fewer than 5 real failures | check target password-auth path and OpenSSH per-source penalties |
| No port-scan marker | rerun `setup_prereqs.sh`; inspect `iptables -t mangle -S PREROUTING` |
| `100210` but no `100211` | confirm 8+ probes from the same `srcip` inside 60 seconds |
| LOLBin simulator preflight fails | auditd active; audit key; agent audit.log collection |
| `80792` but no `100220` | inspect decoded `audit.command` and `audit.exe` |
| `100220` but no `100221` | inspect EXECVE/raw audit arguments for URL / `-O` evidence |
| Manager has alerts but Threat Hunting is empty | `./bin/fast status`; Filebeat → Indexer must be healthy |

For rule design details, see `docs/runbook.md`.

**Last updated:** 2026-09-08
