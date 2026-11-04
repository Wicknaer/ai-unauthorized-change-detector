"""Create a small, self-contained copy of the lab's monitored assets for the local demo.

The real lab uses GPT-2 / TinyLlama weights, IMDB and a SQuAD ChromaDB collection
(see data/). The demo only needs files of the same kinds, so it writes small stand-ins.
"""
import argparse
import json
import os
import random
import shutil
import sqlite3


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "ai-data"))
    parser.add_argument("--model-mb", type=int, default=8, help="size of the fake model file")
    args = parser.parse_args()

    if os.path.exists(args.out):
        shutil.rmtree(args.out)
    models = os.path.join(args.out, "models")
    datasets = os.path.join(args.out, "datasets")
    chroma = os.path.join(args.out, "chroma")
    for d in (models, datasets, chroma):
        os.makedirs(d)

    rng = random.Random(42)
    with open(os.path.join(models, "gpt2-demo.safetensors"), "wb") as f:
        for _ in range(args.model_mb):
            f.write(rng.randbytes(1 << 20))
    with open(os.path.join(models, "tinyllama-demo.gguf"), "wb") as f:
        f.write(b"GGUF" + rng.randbytes(256 * 1024))

    reviews = [("A wonderful, moving film.", 1), ("Dull plot and wooden acting.", 0),
               ("Great soundtrack and cast.", 1), ("I want those two hours back.", 0)]
    with open(os.path.join(datasets, "imdb_train.jsonl"), "w", encoding="utf-8") as f:
        for i in range(2000):
            text, label = reviews[i % len(reviews)]
            f.write(json.dumps({"id": i, "text": text, "label": label}) + "\n")
    with open(os.path.join(datasets, "imdb_train.csv"), "w", encoding="utf-8") as f:
        f.write("id,text,label\n")
        for i in range(2000):
            text, label = reviews[i % len(reviews)]
            f.write(f'{i},"{text}",{label}\n')

    db = sqlite3.connect(os.path.join(chroma, "chroma.sqlite3"))
    db.execute("CREATE TABLE embeddings (id TEXT PRIMARY KEY, document TEXT)")
    db.executemany("INSERT INTO embeddings VALUES (?, ?)",
                   [(f"squad-{i}", f"Paragraph {i} about a Wikipedia topic.") for i in range(500)])
    db.commit()
    db.close()

    total = sum(os.path.getsize(os.path.join(r, n)) for r, _, fs in os.walk(args.out) for n in fs)
    print(f"sample data written to {args.out} ({total / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
