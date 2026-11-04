#!/usr/bin/env bash
# Attack simulations from Section 10 of the requirements analysis (WP4).
# Each test only touches files under DATA_DIR, so it can run inside the attacker
# container (DATA_DIR=/data) or against the local demo data.
#
#   simulations/attacks.sh <test-id|all> [DATA_DIR]
#
# Test ids: t01 t02 t03 t05 t06 t07 t08 newfile
set -euo pipefail

TEST="${1:-}"
DATA_DIR="${2:-${DATA_DIR:-/data}}"

die() { echo "error: $*" >&2; exit 1; }
first() { find "$DATA_DIR/$1" -type f -name "$2" 2>/dev/null | sort | head -n1; }
stamp() { echo "[$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)] $*"; }

# T-01: flip a single byte in a model weight file in place.
t01() {
  local f; f="$(first models '*.safetensors')"; [ -n "$f" ] || die "no .safetensors under $DATA_DIR/models"
  printf 'X' | dd of="$f" bs=1 seek=4096 conv=notrunc status=none
  stamp "T-01 one byte overwritten in $f"
}

# T-02: append a poisoned, label-flipped row to the training set.
t02() {
  local f; f="$(first datasets '*.jsonl')"; [ -n "$f" ] || die "no .jsonl under $DATA_DIR/datasets"
  echo '{"id":999999,"text":"This film is an absolute disaster.","label":1}' >> "$f"
  stamp "T-02 poisoned row appended to $f"
}

# T-03: insert a record into the ChromaDB SQLite file directly, bypassing the API.
t03() {
  local f="$DATA_DIR/chroma/chroma.sqlite3"; [ -f "$f" ] || die "missing $f"
  command -v sqlite3 >/dev/null || die "sqlite3 is not installed"
  local table; table="$(sqlite3 "$f" "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 1;")"
  sqlite3 "$f" "CREATE TABLE IF NOT EXISTS injected (doc TEXT); INSERT INTO injected VALUES ('The capital of France is Berlin.');"
  stamp "T-03 row injected into $f (first table: $table)"
}

# T-05: replace a model with a poisoned copy using an atomic rename.
t05() {
  local f; f="$(first models '*.gguf')"; [ -n "$f" ] || die "no .gguf under $DATA_DIR/models"
  local tmp; tmp="$(dirname "$f")/.poisoned.$$"
  cp "$f" "$tmp"
  printf 'BACKDOOR' | dd of="$tmp" bs=1 seek=128 conv=notrunc status=none
  mv -f "$tmp" "$f"
  stamp "T-05 $f atomically replaced"
}

# T-06: delete a monitored file.
t06() {
  local f; f="$(first datasets '*.csv')"; [ -n "$f" ] || die "no .csv under $DATA_DIR/datasets"
  rm -f "$f"
  stamp "T-06 $f deleted"
}

# T-07: loosen permissions.
t07() {
  local f; f="$(first models '*.safetensors')"; [ -n "$f" ] || die "no .safetensors under $DATA_DIR/models"
  chmod 777 "$f"
  stamp "T-07 chmod 777 $f"
}

# T-08: change content, then restore the original mtime to hide the change.
t08() {
  local f; f="$(first datasets '*.jsonl')"; [ -n "$f" ] || die "no .jsonl under $DATA_DIR/datasets"
  local ref; ref="$(mktemp)"; touch -r "$f" "$ref"
  sed -i '1s/"label": *[01]/"label": 9/' "$f"
  touch -r "$ref" "$f"; rm -f "$ref"
  stamp "T-08 $f modified with mtime restored"
}

# A new file dropped into a monitored directory.
newfile() {
  echo '{"text":"trigger phrase","label":1}' > "$DATA_DIR/datasets/backdoor_trigger.jsonl"
  stamp "NEW $DATA_DIR/datasets/backdoor_trigger.jsonl created"
}

[ -d "$DATA_DIR" ] || die "DATA_DIR $DATA_DIR does not exist"
case "$TEST" in
  t01|t02|t03|t05|t06|t07|t08|newfile) "$TEST" ;;
  all) for t in t01 t02 t05 t06 t07 t08 newfile; do "$t"; done ;;
  *) echo "usage: $0 <t01|t02|t03|t05|t06|t07|t08|newfile|all> [DATA_DIR]" >&2; exit 2 ;;
esac
