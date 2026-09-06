# FAST Feed Mapping

FAST normalizes provider-specific records into one IOC schema. Provider outages
are isolated from one another; a complete all-feed failure is treated as an
error by the CLI/deploy path.

## Standard schema

```json
{
  "ioc_value": "203.0.113.10",
  "ioc_type": "ip",
  "source_feed": "feodo",
  "first_seen": "2026-09-06T10:30:00+00:00",
  "last_seen": "2026-09-06T10:30:00+00:00",
  "confidence_score": 25,
  "tags": ["botnet-name"]
}
```

`first_seen` and `last_seen` are normalized to ISO-8601 UTC. Confidence is
calculated from the number of distinct feeds observing the same `(ioc_value,
ioc_type)`: 25 / 50 / 75 / 100.

## Feodo Tracker

Public JSON source:

```text
https://feodotracker.abuse.ch/downloads/ipblocklist.json
```

Relevant mapping:

| Provider field | FAST field |
|---|---|
| `ip_address` | `ioc_value` |
| — | `ioc_type = ip` |
| — | `source_feed = feodo` |
| `last_dns_query` or `last_online` | `first_seen`, `last_seen` |
| `botnet`, `malware` | `tags` |

Records without an IP are skipped.

## URLhaus

When `ABUSECH_AUTH_KEY` is configured, FAST uses the current authenticated
Community export endpoint. The project retains the historical recent-CSV URL as
a best-effort compatibility fallback when no key is configured.

Relevant CSV fields:

| Provider field | FAST field |
|---|---|
| `url` | `ioc_value` |
| — | `ioc_type = url` |
| — | `source_feed = urlhaus` |
| `dateadded` | `first_seen`, `last_seen` |
| `threat`, comma-separated `tags` | `tags` |

## MalwareBazaar

Preferred current endpoint:

```text
POST https://mb-api.abuse.ch/api/v1/
Auth-Key: <ABUSECH_AUTH_KEY>
query=get_recent
selector=100
```

FAST also understands the historical CSV shape so older/local fixtures remain
compatible.

Relevant mapping:

| Provider field | FAST field |
|---|---|
| `sha256_hash` (preferred), `md5_hash` fallback | `ioc_value` |
| — | `ioc_type = hash` |
| — | `source_feed = malwarebazaar` |
| current `first_seen` or historical `first_seen_utc` | `first_seen`, `last_seen` |
| `signature`, `file_name`, `file_type`/`file_type_guess` | `tags` |

## Spamhaus DROP

FAST uses the current IPv4 JSON/NDJSON DROP dataset:

```text
https://www.spamhaus.org/drop/drop_v4.json
```

Relevant mapping:

| Provider field | FAST field |
|---|---|
| `cidr` | `ioc_value` |
| — | `ioc_type = ip` |
| — | `source_feed = spamhaus` |
| collection time | `first_seen`, `last_seen` |
| `sblid` (or compatible `reason`) | `tags` |

Metadata objects without `cidr` and malformed JSON lines are skipped.

## Deduplication semantics

For repeated `(ioc_value, ioc_type)` observations, FAST:

- keeps one SQLite row;
- unions distinct provider names;
- unions tags without duplicates;
- keeps the earliest `first_seen`;
- keeps the latest `last_seen`;
- recalculates confidence from distinct feed count.

## Wazuh CDB subset

The Wazuh CDB list intentionally contains only **validated IPv4/IPv4-CIDR** IOC
values. URL/hash IOCs remain in the FAST database/dashboard but are not written
to `sample_output/ioc-ips`. Invalid values and IPv6 are skipped, and CIDRs are
canonicalized before export.

**Last updated:** 2026-09-06
