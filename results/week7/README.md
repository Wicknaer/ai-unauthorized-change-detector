# Lab experiment (week 7)

First run of the complete Docker lab (`docker/docker-compose.yml`) with the small data set:
GPT-2 124M (`.safetensors`, 548 MB), synthetic 100 MB and 1 GB files, IMDB (25k + 25k reviews,
CSV/JSONL) and 2,000 SQuAD paragraphs in ChromaDB. 14 monitored files, 1.8 GiB.

Host: Windows 11, Docker Desktop 28.0.4, Linux kernel 6.6 (WSL2), 32 logical CPUs, 16 GB RAM.
Agent config: `config/agent.docker.yaml` (debounce 500 ms, scan every 5 min, 4 MB chunks).

```bash
MODELS=gpt2 SYNTHETIC_SIZES="100M 1G" SQUAD_LIMIT=2000 docker compose -f docker/docker-compose.yml up -d --build
bash simulations/run_experiment.sh 10 results/week7
```

## Results (10 repetitions per scenario)

Latency = time of the agent's log record minus the moment the attack script finished writing
(both taken from the same kernel clock). Files: [`summary.md`](summary.md),
[`per_attack.csv`](per_attack.csv), raw [`truth.txt`](truth.txt) and agent log [`alerts.jsonl`](alerts.jsonl).

| Scenario | N | Detected | Missed | False alarm | Severity | p50 ms | p95 ms |
|---|---|---|---|---|---|---|---|
| T-01 one byte, GPT-2 548 MB | 10 | 10 | 0 | – | CRITICAL | 799 | 809 |
| T-01 one byte, synthetic 100 MB | 10 | 10 | 0 | – | CRITICAL | 558 | 561 |
| T-01 one byte, synthetic 1 GB | 10 | 10 | 0 | – | CRITICAL | 1082 | 1096 |
| T-02 poisoned row (JSONL) | 10 | 10 | 0 | – | HIGH | 523 | 528 |
| T-03 `sqlite3` insert into ChromaDB | 10 | 10 | 0 | – | HIGH (writer `sqlite3`) | 508 | 509 |
| T-04 legitimate API write | 10 | – | – | 0 | INFO (writer `chroma`) | – | – |
| T-05 atomic replace with `mv` | 10 | 10 | 0 | – | CRITICAL | 761 | 771 |
| T-06 delete | 10 | 10 | 0 | – | HIGH | 498 | 499 |
| T-07 `chmod` | 10 | 10 | 0 | – | CRITICAL* | 804 | 817 |
| T-08 content change, mtime restored | 10 | 10 | 0 | – | HIGH | 520 | 523 |
| New file | 10 | 10 | 0 | – | MEDIUM | 501 | 502 |

**100 / 100 attacks detected in real time, 0 false alarms on 10 legitimate ChromaDB writes.**

\* T-07 ran on the GPT-2 file whose content T-01 and T-05 had already changed, so the deviation
is a content change, which outranks a permission change (CRITICAL instead of MEDIUM). On an
untouched file the same `chmod` is MEDIUM (unit test `TestPermissionChange`).

## Other measurements

| Item | Value | Target |
|---|---|---|
| Agent memory (VmRSS, peak) | 34 MB | ≤ 150 MB (NFR-08) |
| Agent CPU while idle | 0.03 % | ≤ 2 % (NFR-08) |
| Initial baseline, 14 files / 1.8 GiB | 1.89 s (≈ 970 MB/s) | ≥ 300 MB/s (NFR-03) |
| Periodic full scan, 1.88 GB | 1.16 s (≈ 1.6 GB/s, files in page cache) | – |
| Attribution mode | `fanotify/filesystem` | – |
| Log chain after the run | 188 lines verified | SR-06 |

## Reading the numbers

* About 500 ms of every latency is the debounce window (FR-09): the agent waits until a file
  has been quiet for 500 ms before hashing it. The rest is hashing, which grows with file size.
* Every file under 100 MB was detected in ≤ 0.53 s (NFR-02 target: p95 ≤ 1 s). The 1 GB file
  took 1.1 s; NFR-02 only covers files under 100 MB, NFR-03 allows 15 s for 4 GB.
* NFR-01 (first "change detected" record within 200 ms, before hashing) is **not** met yet:
  the agent only writes one record, after the hash. A two-stage record is planned.
* 10 repetitions are fewer than the 30 in the plan; the full run, T-09 (mmap), T-13 (event
  storm) and the 24-hour false-alarm run (T-14) are still to do.

## Problems found while bringing the lab up

1. `ai.stanford.edu` was unreachable: `prepare_imdb.py` now falls back to the Hugging Face
   mirror of the same data set.
2. TLS interception on the development network broke downloads from the Hugging Face CDN
   inside the Docker VM (self-signed certificate in chain). Verification was kept on; the two
   IMDB files were downloaded on the host and passed to `data-init` as a cache.
3. `chroma run` could not write `chroma.log` (non-root user, root-owned working directory):
   the image now uses `/home/chroma` as working directory.
4. chromadb 0.5.23's Python HTTP client double-encodes request bodies with the httpx version
   in the image (server answers 422); `legit_chroma.py` calls the REST API directly.
