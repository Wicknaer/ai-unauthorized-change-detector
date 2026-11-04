#!/usr/bin/env bash
# End-to-end demo of fimagent on local sample data (Linux, macOS or Git Bash on Windows).
#   1. build the agent and create sample AI assets
#   2. create the signed baseline (UC-01)
#   3. run the attack simulations (T-01, T-02, T-05, T-06, T-07, T-08, new file)
#   4. detect them with a full scan, list the alerts, export CSV (UC-06)
#   5. show baseline and log tamper detection (T-11, T-15)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$HERE/bin/fimagent"
[ "${OS:-}" = "Windows_NT" ] && BIN="$BIN.exe"
CFG="$HERE/config.yaml"
PY="$(command -v python3 || command -v python)"

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

step "Build"
(cd "$ROOT/agent" && go build -o "$BIN" ./cmd/fimagent)
"$BIN" version

step "Create sample data and a clean state"
rm -rf "$HERE/state"
"$PY" "$HERE/make_sample_data.py" --out "$HERE/ai-data"

step "UC-01: initial signed baseline"
"$BIN" init -config "$CFG" -by demo-admin
"$BIN" status -config "$CFG"

step "Clean scan (expect no alerts)"
"$BIN" scan -config "$CFG"

step "Attacks"
bash "$ROOT/simulations/attacks.sh" all "$HERE/ai-data"

step "Full scan after the attacks (exit code 1 = alerts found)"
"$BIN" scan -config "$CFG" || true

step "UC-06: alerts of the last hour"
"$BIN" report -config "$CFG" -since 1h -min MEDIUM -type detection
"$BIN" report -config "$CFG" -since 1h -format csv -out "$HERE/alerts.csv"
echo "CSV export: $HERE/alerts.csv"

step "SR-06: log hash chain"
"$BIN" verify-log -config "$CFG"

step "T-11: forge the baseline (signature check must fail)"
cp "$HERE/state/baseline.json" "$HERE/state/baseline.json.bak"
sed -i 's/"created_by": "demo-admin"/"created_by": "attacker"/' "$HERE/state/baseline.json"
"$BIN" scan -config "$CFG" || true
mv "$HERE/state/baseline.json.bak" "$HERE/state/baseline.json"

step "T-15: delete a line from the alert log (chain must break)"
LOG="$HERE/state/alerts.jsonl"
cp "$LOG" "$LOG.bak"
sed -i '3d' "$LOG"
"$BIN" verify-log -config "$CFG" || true
mv "$LOG.bak" "$LOG"

step "Done"
echo "Run '$BIN watch -config $CFG' and modify files under $HERE/ai-data to see real-time alerts."
