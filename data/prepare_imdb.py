"""Download the IMDB Large Movie Review Dataset (Maas et al., 2011) and convert it to CSV and JSONL.

The positive/negative labels make it a natural target for label-flipping poisoning (T-02, T-08).
"""
import argparse
import csv
import json
import os
import subprocess
import tarfile

URL = "https://ai.stanford.edu/~amaas/data/sentiment/aclImdb_v1.tar.gz"
# Same data set mirrored on Hugging Face; used when the Stanford server is unreachable.
MIRROR = "https://huggingface.co/datasets/stanfordnlp/imdb/resolve/main/plain_text/{split}-00000-of-00001.parquet"


def fetch(url: str, path: str, connect_timeout: int = 60) -> None:
    """Download with curl: it uses the system CA store and follows the CDN redirects."""
    subprocess.run(["curl", "-fsSL", "--retry", "3", "--connect-timeout", str(connect_timeout),
                    "-o", path + ".part", url], check=True)
    os.replace(path + ".part", path)


def from_tarball(tar_path: str) -> dict:
    rows = {"train": [], "test": []}
    with tarfile.open(tar_path, "r:gz") as tar:
        for m in tar:
            # aclImdb/<split>/<pos|neg>/<id>_<rating>.txt
            parts = m.name.split("/")
            if not m.isfile() or len(parts) != 4 or parts[1] not in rows or parts[2] not in ("pos", "neg"):
                continue
            text = tar.extractfile(m).read().decode("utf-8", errors="replace")
            rows[parts[1]].append({"id": parts[3][:-4], "text": text, "label": 1 if parts[2] == "pos" else 0})
    return rows


def from_mirror(cache_dir: str) -> dict:
    import pyarrow.parquet as pq

    rows = {}
    for split in ("train", "test"):
        path = os.path.join(cache_dir, f"imdb_{split}.parquet")
        if not os.path.exists(path):
            print(f"downloading {split} split from the Hugging Face mirror")
            fetch(MIRROR.format(split=split), path)
        table = pq.read_table(path).to_pydict()
        rows[split] = [{"id": f"{split}-{i}", "text": t, "label": int(l)}
                       for i, (t, l) in enumerate(zip(table["text"], table["label"]))]
    return rows


def write(rows: dict, out: str) -> None:
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
    try:
        if not os.path.exists(args.cache):
            print(f"downloading {URL}")
            fetch(URL, args.cache, connect_timeout=30)
        rows = from_tarball(args.cache)
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"Stanford server unavailable ({e}); using the mirror")
        rows = from_mirror(os.path.dirname(args.cache) or ".")
    write(rows, args.out)


if __name__ == "__main__":
    main()
