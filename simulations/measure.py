"""Detection latency and accuracy from an experiment (FR-20).

    python simulations/measure.py truth.txt alerts.jsonl [--window START_MS END_MS] [--out DIR]

truth.txt holds the "@@ <test> <unix-ms> <path>" lines printed by attacks.sh and
legit_chroma.py; alerts.jsonl is the agent's log. For every attack the first detection of
the same path after the write counts:

* latency  = detection timestamp - time the write finished (both from the same kernel clock)
* TP       = detected as an alert (MEDIUM or above) within the match window
* FN       = no alert within the window
* FP       = an alert during the experiment that no attack explains, including any alert
             raised by a legitimate ChromaDB write (T-04)

Results are printed and written as summary.md and per_attack.csv.
"""
import argparse
import csv
import json
import math
import os
import re
from collections import defaultdict
from datetime import datetime

ALERT = {"MEDIUM", "HIGH", "CRITICAL"}
EXPECTED = {  # scenario -> expected severity (None = no alert, INFO only)
    "t01": "CRITICAL", "t02": "HIGH", "t03": "HIGH", "t04": None, "t05": "CRITICAL",
    "t06": "HIGH", "t07": "MEDIUM", "t08": "HIGH", "t09": "CRITICAL", "newfile": "MEDIUM",
}
MATCH_WINDOW_MS = 10_000


_TS = re.compile(r"^([^.]+?)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")


def ts_ms(s):
    """RFC 3339 with up to nanoseconds (Go's format) to unix milliseconds."""
    base, frac, tz = _TS.match(s).groups()
    whole = datetime.fromisoformat(base + ("+00:00" if tz == "Z" else tz)).timestamp()
    return whole * 1000 + (float("0." + frac) * 1000 if frac else 0)


def percentile(values, p):
    if not values:
        return float("nan")
    v = sorted(values)
    k = (len(v) - 1) * p / 100
    lo, hi = math.floor(k), math.ceil(k)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def load(truth_path, log_path):
    truth = []
    with open(truth_path, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(" ", 3)
            if len(parts) == 4 and parts[0] == "@@":
                truth.append({"test": parts[1], "ts": int(parts[2]), "path": parts[3]})
    dets = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("type") == "detection" and r.get("event") != "restored":
                r["_ts"] = ts_ms(r["ts"])
                dets.append(r)
    dets.sort(key=lambda r: r["_ts"])
    return truth, dets


def label(t):
    """Scenario label; T-01 is split by target so latency can be compared by file size."""
    if t["test"] == "t01":
        return "t01:" + os.path.basename(t["path"])
    return t["test"]


def evaluate(truth, dets, window=None):
    used = set()
    rows = []
    truth = sorted(truth, key=lambda t: t["ts"])
    for i, t in enumerate(truth):
        nxt = next((u["ts"] for u in truth[i + 1:] if u["path"] == t["path"]), t["ts"] + MATCH_WINDOW_MS)
        limit = min(t["ts"] + MATCH_WINDOW_MS, max(nxt, t["ts"] + 1))
        match = None
        for j, d in enumerate(dets):
            if j in used or d["_ts"] < t["ts"] - 5 or d["_ts"] > limit:
                continue
            same = d.get("path") == t["path"] or (t["test"] == "storm" and d.get("path", "").startswith(t["path"]))
            if same:
                match = j
                break
        expected = EXPECTED.get(t["test"])
        row = {"scenario": label(t), "test": t["test"], "path": t["path"], "attack_ms": t["ts"],
               "detected": False, "severity": "", "process": "", "latency_ms": "", "outcome": ""}
        if match is not None:
            d = dets[match]
            used.add(match)
            row.update(detected=True, severity=d["severity"], latency_ms=round(d["_ts"] - t["ts"], 1),
                       process=(d.get("process") or {}).get("comm", ""))
        if expected is None:  # legitimate write
            row["outcome"] = "FP" if row["severity"] in ALERT else "TN"
        elif row["severity"] in ALERT:
            row["outcome"] = "TP" if row["severity"] == expected else "TP (severity %s, expected %s)" % (row["severity"], expected)
        else:
            row["outcome"] = "FN"
        rows.append(row)
    # Alerts that no attack explains (e.g. raised by legitimate traffic on other ChromaDB files).
    unexplained = [d for j, d in enumerate(dets) if j not in used and d["severity"] in ALERT
                   and (window is None or window[0] <= d["_ts"] <= window[1] + MATCH_WINDOW_MS)]
    return rows, unexplained


def summarize(rows, unexplained):
    by = defaultdict(list)
    for r in rows:
        by[r["scenario"]].append(r)
    lines = ["| Scenario | N | TP | FN | FP | Severity | p50 ms | p95 ms | max ms |",
             "|---|---|---|---|---|---|---|---|---|"]
    tot = defaultdict(int)
    for sc in sorted(by):
        rs = by[sc]
        tp = sum(r["outcome"].startswith("TP") for r in rs)
        fn = sum(r["outcome"] == "FN" for r in rs)
        fp = sum(r["outcome"] == "FP" for r in rs)
        lat = [r["latency_ms"] for r in rs if r["outcome"].startswith("TP")]
        sev = sorted({r["severity"] or "-" for r in rs})
        tot["n"] += len(rs); tot["tp"] += tp; tot["fn"] += fn; tot["fp"] += fp
        if EXPECTED.get(rs[0]["test"]) is None:
            tot["legit"] += len(rs)
        f = lambda x: "-" if math.isnan(x) else f"{x:.0f}"
        lines.append(f"| {sc} | {len(rs)} | {tp} | {fn} | {fp} | {', '.join(sev)} | "
                     f"{f(percentile(lat, 50))} | {f(percentile(lat, 95))} | {f(max(lat) if lat else float('nan'))} |")
    attacks = tot["n"] - tot["legit"]
    all_lat = [r["latency_ms"] for r in rows if r["outcome"].startswith("TP")]
    rate = 100 * tot["tp"] / attacks if attacks else float("nan")
    lines += ["",
              f"- Attacks: {attacks}, detected (TP): {tot['tp']}, missed (FN): {tot['fn']} -> real-time detection rate {rate:.1f} %",
              f"- Legitimate writes: {tot['legit']}, false alarms on them: {tot['fp']}",
              f"- Unexplained alerts during the experiment: {len(unexplained)}",
              f"- Latency over all detections: p50 {percentile(all_lat, 50):.0f} ms, p95 {percentile(all_lat, 95):.0f} ms"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("truth")
    ap.add_argument("log")
    ap.add_argument("--window", nargs=2, type=int, metavar=("START_MS", "END_MS"))
    ap.add_argument("--out")
    args = ap.parse_args()
    truth, dets = load(args.truth, args.log)
    rows, unexplained = evaluate(truth, dets, args.window)
    text = summarize(rows, unexplained)
    print(text)
    if unexplained:
        print("\nUnexplained alerts:")
        for d in unexplained[:20]:
            print(f"  {d['ts']} {d['severity']} {d.get('event')} {d.get('path')} by {(d.get('process') or {}).get('comm', '?')}")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as f:
            f.write(text + "\n")
        with open(os.path.join(args.out, "per_attack.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["scenario"])
            w.writeheader()
            w.writerows(rows)


if __name__ == "__main__":
    main()
