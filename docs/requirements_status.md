# Requirements status

IDs follow the requirements analysis document. In this repository the Turkish prefixes are
written in English: **FR** = functional (FG), **NFR** = non-functional (FOG), **SR** = security (GG).

Status: ✅ implemented and tested · 🟡 partly implemented · ⏳ planned

## Functional

| ID | Requirement | Status | Where |
|---|---|---|---|
| FR-01 | YAML config: watched dirs, patterns, exclusions | ✅ | `internal/config` |
| FR-02 | Baseline with SHA-256, size, mode, owner, mtime | ✅ | `internal/baseline` |
| FR-03 | Baseline renewed only via CLI, with who/when logged | ✅ | `fimagent rebaseline`, `maintenance off` |
| FR-04 | Chunked hashing, memory independent of file size | ✅ | `internal/hasher` |
| FR-05 | Write/create/delete/rename/chmod events | ✅ | `internal/watcher` (inotify via fsnotify) + `internal/attribution` (fanotify writes) |
| FR-06 | New subdirectories added automatically | ✅ | `internal/watcher` |
| FR-07 | Rehash and compare when a written file settles | ✅ | `internal/scanner`, `internal/agent` |
| FR-08 | Periodic full rescan (default 5 min) | ✅ | `internal/agent` |
| FR-09 | Coalesce events on one file (default 500 ms) | ✅ | `internal/watcher` |
| FR-10 | Identify the writing process (PID, user, exe) | ✅ | `internal/attribution`: fanotify filesystem mark, `/proc` lookup; see `docs/design/process_attribution.md` |
| FR-11 | Whitelisted processes produce INFO | ✅ | INFO + signed `accepted.json` overlay so scans do not re-alert |
| FR-12 | Maintenance mode, baseline renewed on exit | ✅ | `fimagent maintenance on/off` |
| FR-13 | One JSON line per detection with old/new hash | ✅ | `internal/logger` |
| FR-14 | Severity levels and mapping | ✅ | `internal/decision` |
| FR-15 | CRITICAL/HIGH to stdout (docker logs) | 🟡 | stdout done; syslog planned |
| FR-16 | Webhook for CRITICAL alerts | ✅ | `internal/notify`, `FIM_WEBHOOK_URL` (Slack/Discord format) |
| FR-17 | Start/stop/scan summaries | ✅ | `summary` records |
| FR-18 | CLI report by time range, CSV/JSON export | ✅ | `fimagent report` |
| FR-19 | Quarantine and restore | ⏳ | optional |
| FR-20 | Latency (p50/p95) and TP/FP/FN script | ✅ | `simulations/run_experiment.sh` + `measure.py`; results in `results/week7` |

## Non-functional

| ID | Requirement | Status | Notes |
|---|---|---|---|
| NFR-01/02 | Event-to-record ≤ 200 ms, with hash ≤ 1 s (p95) | 🟡 | lab: ≤ 0.53 s p95 for files < 100 MB (NFR-02 met); no early pre-hash record yet (NFR-01) |
| NFR-03 | SHA-256 ≥ 300 MB/s | ✅ | lab baseline 1.8 GiB in 1.89 s (≈ 970 MB/s) |
| NFR-10 | Restart after crash, cover downtime with full scan | ✅ | `restart: unless-stopped`, startup scan, `monitoring_gap` |
| NFR-12 | Single command lab | ✅ | `docker compose up` |
| NFR-13 | Modular code and unit tests | ✅ | 9 packages, tests in CI |
| NFR-14 | JSON Lines with a documented schema | ✅ | `docs/log_schema.md` |
| NFR-11 | Log rotation | ✅ | `log_max_mb` / `log_keep` (default 5 × 100 MB), chain continues across files |
| NFR-08 | Idle CPU ≤ 2 %, memory ≤ 150 MB | ✅ | lab: 0.03 % CPU, 34 MB RSS |

## Security

| ID | Requirement | Status | Notes |
|---|---|---|---|
| SR-01 | HMAC-signed baseline, verified on start and every scan | ✅ | T-11 covered by tests and the demo |
| SR-02 | Key and baseline on a volume the app cannot reach | ✅ | `agent-state` volume |
| SR-03 | Separate container, read-only mount | ✅ | `docker-compose.yml` |
| SR-04 | Minimal capabilities, no privileged mode | ✅ | `cap_drop: ALL`, `SYS_ADMIN`, `DAC_READ_SEARCH` |
| SR-05 | Heartbeat every 60 s, gap detection | 🟡 | heartbeat + gap on restart; external watchdog planned |
| SR-06 | Hash-chained log | ✅ | `fimagent verify-log`; `chattr +a` is a deployment step |
| SR-07 | Agent's own config is monitored | ✅ | config asset, CRITICAL |
| SR-08 | Secrets from env / Docker secret | ✅ | `FIM_HMAC_KEY`, `FIM_HMAC_KEY_FILE` |
| SR-09 | No file content in logs | ✅ | metadata and hashes only |

## Test scenarios

| Test | Scenario | Status |
|---|---|---|
| T-01 | One byte changed in a model file | ✅ CRITICAL |
| T-02 | Poisoned row appended to the dataset | ✅ HIGH |
| T-03 | Direct `sqlite3` insert into ChromaDB | ✅ HIGH, writer `sqlite3` in the log |
| T-04 | Legitimate ChromaDB API write → INFO only | ✅ INFO, writer `chroma` |
| T-05 | Atomic replace with `mv` | ✅ CRITICAL |
| T-06 | Monitored file deleted | ✅ |
| T-07 | `chmod 777` | ✅ MEDIUM (Linux) |
| T-08 | Content changed, mtime restored | ✅ detected by hash |
| T-09 | mmap write | 🟡 caught by periodic scan and not credited to an earlier whitelisted write; lab test pending |
| T-10 | Agent stopped, file changed, agent restarted | ✅ `monitoring_gap` + startup scan |
| T-11 | Baseline file modified | ✅ CRITICAL, agent refuses forged baseline |
| T-12 | Model update in maintenance mode | ✅ no alerts, baseline renewed |
| T-13 | 1,000 concurrent writes | ⏳ overflow → full scan is implemented; `attacks.sh storm` ready, load test pending |
| T-14 | 24 h normal workload, FP ≤ 1 % | ⏳ |
| T-15 | Alert log line deleted/modified | ✅ chain break detected |
