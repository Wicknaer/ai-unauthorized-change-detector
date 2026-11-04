# Log schema

Every record is one JSON object per line (JSON Lines), so the log can be shipped to Loki or
Elasticsearch as-is (NFR-14). Records contain metadata and hashes only, never file content (SR-09).
CRITICAL and HIGH records are also printed to stdout, so they show up in `docker logs` (FR-15).

```json
{"ts":"2026-11-04T18:21:45.754Z","type":"detection","severity":"CRITICAL","event":"modified",
 "path":"/data/models/gpt2-124m.safetensors","asset":"model",
 "old_sha256":"248dfc39...","new_sha256":"9a1f02c7...","old_mode":"0644","new_mode":"0644",
 "authorized":false,"source":"realtime","latency_ms":503.2,"msg":"content differs from baseline",
 "prev_hash":"6c2e...","hash":"b81d..."}
```

| Field | Type | Present in | Meaning |
|---|---|---|---|
| `ts` | RFC 3339 UTC | all | Time the record was written |
| `type` | string | all | `detection`, `integrity`, `heartbeat`, `summary`, `baseline`, `maintenance`, `agent` |
| `severity` | string | all | `CRITICAL`, `HIGH`, `MEDIUM`, `INFO` (FR-14) |
| `event` | string | most | `modified`, `created`, `deleted`, `meta`, `restored`, `baseline_tampered`, `monitoring_gap`, `scan_complete`, ... |
| `path` | string | detection, integrity | Affected file |
| `asset` | string | detection | `model`, `config`, `vectordb`, `dataset` |
| `old_sha256` / `new_sha256` | hex | detection | Baseline and observed digest (FR-13) |
| `old_mode` / `new_mode`, `old_owner` / `new_owner` | string | detection | Permission / ownership before and after |
| `process` | object | detection | `{pid, user, exe, comm}` of the writer, when known (FR-10) |
| `authorized` | bool | detection | Whitelisted process or maintenance mode |
| `source` | string | detection | `realtime` (kernel event) or `scan` (periodic full scan) |
| `latency_ms` | number | realtime detections | Time from the first kernel event to the record (NFR-01/02 measurements) |
| `msg` | string | optional | Human-readable reason |
| `actor` | string | baseline, maintenance | Operator who renewed the baseline or toggled maintenance (FR-03) |
| `fields` | object | summary, heartbeat, integrity | Counters such as `files`, `bytes`, `changes`, `duration_ms` (FR-17) |
| `prev_hash` | hex | all | `hash` of the previous line; 64 zeros for the first line |
| `hash` | hex | all | SHA-256 of this record encoded with `hash` = "" |

## Severity mapping

| Change | model / config | vectordb / dataset |
|---|---|---|
| Content modified | CRITICAL | HIGH |
| File deleted | CRITICAL | HIGH |
| Permission / owner changed | MEDIUM | MEDIUM |
| New file | MEDIUM | MEDIUM |
| Any change by a whitelisted process or during maintenance | INFO | INFO |

## Tamper evidence (SR-06)

Because each line includes the previous line's hash, deleting, editing or reordering a line
breaks the chain. `fimagent verify-log` reports the first broken line. In production the log
should also be made append-only (`chattr +a`) or forwarded to remote syslog, so an attacker
cannot simply truncate and rewrite the whole file.
