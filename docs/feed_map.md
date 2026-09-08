# FAST Feed Mapping

FAST normalizes provider-specific threat-intelligence records into one IOC
schema. Provider failures are isolated from one another; a complete all-feed
failure is treated as an error by the CLI/deploy/refresh paths instead of being
reported as a successful empty refresh.

## Standard schema

```json
{
  "ioc_value": "203.0.113.10",
  "ioc_type": "ip",
  "source_feed": "feodo",
  "first_seen": "2026-09-08T10:30:00+00:00",
  "last_seen": "2026-09-08T10:30:00+00:00",
  "confidence_score": 25,
  "tags": ["botnet-name"]
}
```

`first_seen` and `last_seen` are normalized to ISO-8601 UTC. Confidence is
calculated from the number of distinct feeds observing the same
`(ioc_value, ioc_type)` pair:

```text
1 feed  -> 25
2 feeds -> 50
3 feeds -> 75
4 feeds -> 100
```

## Feodo Tracker

Current source used by FAST:

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

When `ABUSECH_AUTH_KEY` is configured, FAST uses the authenticated Community
recent-export endpoint:

```text
https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH_KEY>/recent.csv
```

If the key is absent, FAST attempts the historical recent-CSV endpoint as a
best-effort compatibility fallback:

```text
https://urlhaus.abuse.ch/downloads/csv_recent/
```

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

When no Auth-Key is configured, FAST attempts the historical recent CSV as a
compatibility fallback. The normalizer understands both the current API shape
and the historical CSV shape.

Relevant mapping:

| Provider field | FAST field |
|---|---|
| `sha256_hash` (preferred), `md5_hash` fallback | `ioc_value` |
| — | `ioc_type = hash` |
| — | `source_feed = malwarebazaar` |
| current `first_seen` or historical `first_seen_utc` | `first_seen`, `last_seen` |
| `signature`, `file_name`, `file_type`/`file_type_guess` | `tags` |

## Spamhaus DROP

FAST uses the IPv4 JSON/NDJSON DROP dataset:

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
| `sblid` or compatible `reason` | `tags` |

Metadata objects without `cidr` and malformed JSON lines are skipped.

## Failure behavior

Every feed fetcher returns its own list and one provider failure does not stop
other providers. At the aggregate layer:

- partial success is accepted;
- an all-feed zero-record result makes `cli.py --fetch` fail;
- deploy/refresh automation therefore cannot silently treat a completely empty
  collection as a successful update.

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
to `sample_output/ioc-ips`.

Before export FAST:

- rejects invalid IP strings;
- excludes IPv6 from this IPv4 CDB list;
- canonicalizes IPv4 CIDRs;
- removes duplicate keys;
- sorts the generated CDB output deterministically.

The final file uses Wazuh CDB key/value lines such as:

```text
203.0.113.10:1
198.51.100.0/24:1
```

**Last updated:** 2026-09-08
