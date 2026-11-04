"""Download the IMDB Large Movie Review Dataset (Maas et al., 2011) and convert it to CSV and JSONL.

The positive/negative labels make it a natural target for label-flipping poisoning (T-02, T-08).
"""
import argparse
import csv
import json
import os
import tarfile
import urllib.request

URL = "https://ai.stanford.edu/~amaas/data/sentiment/aclImdb_v1.tar.gz"


def convert(tar_path: str, out: str) -> None:
    rows = {"train": [], "test": []}
    with tarfile.open(tar_path, "r:gz") as tar:
        for m in tar:
            # aclImdb/<split>/<pos|neg>/<id>_<rating>.txt
            parts = m.name.split("/")
            if not m.isfile() or len(parts) != 4 or parts[1] not in rows or parts[2] not in ("pos", "neg"):
                continue
            text = tar.extractfile(m).read().decode("utf-8", errors="replace")
            rows[parts[1]].append({"id": parts[3][:-4], "text": text, "label": 1 if parts[2] == "pos" else 0})
    for split, items in rows.items():
        items.sort(key=lambda r: r["id"])
        with open(os.path.join(out, f"imdb_{split}.jsonl"), "w", encoding="utf-8") as f:
            for r in items:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(os.path.join(out, f"imdb_{split}.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["id", "text", "label"])
            w.writeheader()
            w.writerows(items)
        print(f"{split}: {len(items)} reviews")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True)
    p.add_argument("--cache", default="/tmp/aclImdb_v1.tar.gz")
    args = p.parse_args()
    os.makedirs(args.out, exist_ok=True)
    if os.path.exists(os.path.join(args.out, "imdb_train.jsonl")):
        print("skip IMDB (exists)")
        return
    if not os.path.exists(args.cache):
        print(f"downloading {URL}")
        urllib.request.urlretrieve(URL, args.cache)
    convert(args.cache, args.out)


if __name__ == "__main__":
    main()
