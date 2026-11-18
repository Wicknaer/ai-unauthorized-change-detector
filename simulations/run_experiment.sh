#!/usr/bin/env bash
# Repeated attack experiment against the running lab (FR-20, Section 10 of the requirements).
#
#   bash simulations/run_experiment.sh [REPS] [OUT_DIR]
#
# Runs every scenario REPS times (default 30) from the attacker container, plus legitimate
# ChromaDB writes from the ai-app container, and records ground truth in OUT_DIR/truth.txt.
# Afterwards it copies the agent's log and runs simulations/measure.py.
set -euo pipefail
cd "$(dirname "$0")/.."

REPS="${1:-30}"
OUT="${2:-results/$(date +%Y%m%d-%H%M%S)}"
GAP="${GAP:-1.5}"             # seconds between repetitions (> debounce + hashing time)
DC="docker compose -f docker/docker-compose.yml"
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: keep container paths like /simulations as they are
mkdir -p "$OUT"
TRUTH="$OUT/truth.txt"
: > "$TRUTH"

attack() { # attack <test> [target]
  $DC exec -T attacker bash /simulations/attacks.sh "$1" /data "${2:-}" | grep '^@@' >> "$TRUTH"
}
legit() {
  $DC exec -T ai-app python - add < simulations/legit_chroma.py | grep '^@@' >> "$TRUTH"
}
scenario() { # scenario <label> <command...>
  local label="$1"; shift
  printf '%-28s' "$label"
  for i in $(seq 1 "$REPS"); do "$@"; sleep "$GAP"; printf '.'; done
  echo
}

echo "experiment: $REPS repetitions per scenario -> $OUT"
start_ms=$(date +%s%3N)
scenario "T-01 model byte (gpt2)"     attack t01 /data/models/gpt2-124m.safetensors
scenario "T-01 synthetic 100M"        attack t01 /data/synthetic/synthetic_100m.bin
GAP=3 scenario "T-01 synthetic 1G"    attack t01 /data/synthetic/synthetic_1g.bin
scenario "T-02 poisoned row"          attack t02 /data/datasets/imdb_train.jsonl
scenario "T-03 sqlite3 insert"        attack t03
scenario "T-04 legitimate API write"  legit
scenario "T-05 atomic replace"        attack t05 /data/models/gpt2-124m.safetensors
t06_once() { attack t06 /data/datasets/imdb_test.csv; sleep "$GAP"; $DC exec -T attacker bash /simulations/attacks.sh restore-t06 /data >/dev/null; }
scenario "T-06 delete (+restore)"     t06_once
scenario "T-07 chmod"                 attack t07 /data/models/gpt2-124m.safetensors
scenario "T-08 touch -r"              attack t08 /data/datasets/imdb_train.jsonl
scenario "new file"                   attack newfile
end_ms=$(date +%s%3N)

sleep 3
$DC cp agent:/var/lib/fimagent/alerts.jsonl "$OUT/alerts.jsonl" >/dev/null
echo "$start_ms $end_ms" > "$OUT/window.txt"
PY="$(command -v python3 || command -v python)"
"$PY" simulations/measure.py "$TRUTH" "$OUT/alerts.jsonl" --window "$start_ms" "$end_ms" --out "$OUT"
