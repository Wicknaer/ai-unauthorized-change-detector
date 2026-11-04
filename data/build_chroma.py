"""Build the RAG collection: unique SQuAD v1.1 training paragraphs in a persistent ChromaDB store.

Embeddings use Chroma's default embedding function (all-MiniLM-L6-v2).
"""
import argparse
import json
import os
import urllib.request

import chromadb

URL = "https://rajpurkar.github.io/SQuAD-explorer/dataset/train-v1.1.json"


def paragraphs(path: str):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)["data"]
    seen = set()
    for article in data:
        for para in article["paragraphs"]:
            ctx = para["context"]
            if ctx not in seen:
                seen.add(ctx)
                yield article["title"], ctx


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--path", required=True, help="ChromaDB persist directory")
    p.add_argument("--limit", type=int, default=0, help="max paragraphs, 0 = all")
    p.add_argument("--batch", type=int, default=256)
    p.add_argument("--cache", default="/tmp/squad-train-v1.1.json")
    args = p.parse_args()

    if not os.path.exists(args.cache):
        print(f"downloading {URL}")
        urllib.request.urlretrieve(URL, args.cache)

    client = chromadb.PersistentClient(path=args.path)
    col = client.get_or_create_collection("squad")
    if col.count() > 0:
        print(f"skip ChromaDB (collection has {col.count()} documents)")
        return

    ids, docs, metas, total = [], [], [], 0
    for i, (title, ctx) in enumerate(paragraphs(args.cache)):
        if args.limit and i >= args.limit:
            break
        ids.append(f"squad-{i}")
        docs.append(ctx)
        metas.append({"title": title})
        if len(ids) == args.batch:
            col.add(ids=ids, documents=docs, metadatas=metas)
            total += len(ids)
            ids, docs, metas = [], [], []
            if total % 5120 == 0:
                print(f"  {total} paragraphs")
    if ids:
        col.add(ids=ids, documents=docs, metadatas=metas)
        total += len(ids)
    print(f"collection 'squad': {total} paragraphs")


if __name__ == "__main__":
    main()
