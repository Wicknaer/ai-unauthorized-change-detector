#!/usr/bin/env bash
# Attack simulations from Section 10 of the requirements analysis (WP4).
# Each test only touches files under DATA_DIR, so it can run inside the attacker
# container (DATA_DIR=/data) or against the local demo data.
#
#   simulations/attacks.sh <test-id|all> [DATA_DIR] [TARGET_FILE]
#
# Test ids: t01 t02 t03 t05 t06 t07 t08 t09 newfile storm
#
# Every run writes different content, so repeated runs are distinct changes (needed for the
# 30-repetition experiments). Besides the human-readable line, each test prints a line
#   @@ <test> <unix-ms> <path>
# taken right after the write finished; simulations/measure.py uses it as ground truth.
set -euo pipefail

TEST="${1:-}"
DATA_DIR="${2:-${DATA_DIR:-/data}}"
TARGET="${3:-}"

die() { echo "error: $*" >&2; exit 1; }
first() { find "$DATA_DIR/$1" -type f -name "$2" 2>/dev/null | sort | head -n1; }
now_ms() { date +%s%3N; }
stamp() { # stamp <test> <path> <description>
  local ts; ts="$(now_ms)"
  echo "@@ $1 $ts $2"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)] $1 $3"
}
rand() { od -An -N4 -tu4 /dev/urandom | tr -d ' '; }
target_or() { if [ -n "$TARGET" ]; then echo "$TARGET"; else first "$1" "$2"; fi; }

# T-01: overwrite one byte in a model weight file in place, at a random offset.
t01() {
  local f; f="$(target_or models '*.safetensors')"; [ -n "$f" ] || die "no model file"
  local size off; size=$(stat -c %s "$f"); off=$(( $(rand) % size ))
  printf "\\x$(printf %02x $(( $(rand) % 256 )))" | dd of="$f" bs=1 seek="$off" conv=notrunc status=none
  stamp t01 "$f" "one byte overwritten at offset $off in $f"
}

# T-02: append a poisoned, label-flipped row to the training set.
t02() {
  local f; f="$(target_or datasets '*.jsonl')"; [ -n "$f" ] || die "no .jsonl under $DATA_DIR/datasets"
  echo "{\"id\":\"p$(now_ms)$(rand)\",\"text\":\"This film is an absolute disaster.\",\"label\":1}" >> "$f"
  stamp t02 "$f" "poisoned row appended to $f"
}

# T-03: insert a record into the ChromaDB SQLite file directly, bypassing the API.
t03() {
  local f="${TARGET:-$DATA_DIR/chroma/chroma.sqlite3}"; [ -f "$f" ] || die "missing $f"
  command -v sqlite3 >/dev/null || die "sqlite3 is not installed"
  sqlite3 "$f" "CREATE TABLE IF NOT EXISTS injected (doc TEXT); INSERT INTO injected VALUES ('The capital of France is Berlin. $(rand)');"
  stamp t03 "$f" "row injected into $f with sqlite3"
}

# T-05: replace a model with a poisoned copy using an atomic rename.
t05() {
  local f; f="$(target_or models '*.gguf')"; [ -n "$f" ] || f="$(first models '*.safetensors')"; [ -n "$f" ] || die "no model file"
  local tmp; tmp="$(dirname "$f")/.poisoned.$$"
  cp "$f" "$tmp"
  printf "BACKDOOR$(rand)" | dd of="$tmp" bs=1 seek=$(( $(rand) % 4096 )) conv=notrunc status=none
  mv -f "$tmp" "$f"
  stamp t05 "$f" "$f atomically replaced with a poisoned copy"
}

# T-06: delete a monitored file (restore it with: attacks.sh restore-t06).
t06() {
  local f; f="$(target_or datasets '*.csv')"; [ -n "$f" ] || die "no .csv under $DATA_DIR/datasets"
  cp -p "$f" "/tmp/t06.$(basename "$f")"
  rm -f "$f"
  stamp t06 "$f" "$f deleted"
}
restore-t06() {
  local b; for b in /tmp/t06.*; do [ -e "$b" ] && mv -f "$b" "$DATA_DIR/datasets/${b#/tmp/t06.}"; done; return 0
}

# T-07: change permissions; alternates between 0777 and 0600 so every run is a new state.
t07() {
  local f; f="$(target_or models '*.safetensors')"; [ -n "$f" ] || die "no model file"
  local mode=777; [ "$(stat -c %a "$f")" = "777" ] && mode=600
  chmod "$mode" "$f"
  stamp t07 "$f" "chmod $mode $f"
}

# T-08: change content, then restore the original mtime to hide the change.
t08() {
  local f; f="$(target_or datasets '*.jsonl')"; [ -n "$f" ] || die "no .jsonl under $DATA_DIR/datasets"
  local ref; ref="$(mktemp)"; touch -r "$f" "$ref"
  sed -i "1s/\"text\": *\"/&[$(rand)] /" "$f"
  touch -r "$ref" "$f"; rm -f "$ref"
  stamp t08 "$f" "$f modified with mtime restored"
}

# T-09: modify a file through mmap: no write() call, so neither inotify nor fanotify sees it.
t09() {
  local f; f="$(target_or models '*.safetensors')"; [ -n "$f" ] || die "no model file"
  python3 - "$f" <<'PY'
import mmap, os, sys
with open(sys.argv[1], "r+b") as fh:
    m = mmap.mmap(fh.fileno(), 0)
    off = int.from_bytes(os.urandom(4), "little") % len(m)
    m[off] = (m[off] + 1) % 256
    m.flush(); m.close()
PY
  stamp t09 "$f" "$f modified through mmap"
}

# A new file dropped into a monitored directory.
newfile() {
  local f="$DATA_DIR/datasets/backdoor_trigger_$(now_ms).jsonl"
  echo '{"text":"trigger phrase","label":1}' > "$f"
  stamp newfile "$f" "$f created"
}

# T-13: event storm, N files written at the same time (default 1000).
storm() {
  local n="${TARGET:-1000}" dir="$DATA_DIR/datasets/storm_$(now_ms)"
  mkdir -p "$dir"
  for i in $(seq 1 "$n"); do echo "{\"id\":$i,\"label\":1}" > "$dir/part_$i.jsonl" & done
  wait
  stamp storm "$dir" "$n files written concurrently in $dir"
}

[ -d "$DATA_DIR" ] || die "DATA_DIR $DATA_DIR does not exist"
case "$TEST" in
  t01|t02|t03|t05|t06|restore-t06|t07|t08|t09|newfile|storm) "$TEST" ;;
  all) for t in t01 t02 t05 t06 t07 t08 newfile; do "$t"; done ;;
  *) echo "usage: $0 <t01|t02|t03|t05|t06|restore-t06|t07|t08|t09|newfile|storm|all> [DATA_DIR] [TARGET]" >&2; exit 2 ;;
esac
