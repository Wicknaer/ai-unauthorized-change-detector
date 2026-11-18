"""Legitimate ChromaDB traffic through the HTTP API (T-04, T-14 workload).

Runs inside the ai-app container, so every write to /data/chroma is made by the ChromaDB
server process (command name "chroma"), which the agent whitelists:

    docker compose -f docker/docker-compose.yml exec -T ai-app python - add < simulations/legit_chroma.py
    docker compose ... exec -T ai-app python - workload 600 2 < simulations/legit_chroma.py

"add" inserts one document; "workload SECONDS INTERVAL" mixes adds and queries.
Each write prints "@@ t04 <unix-ms> /data/chroma/chroma.sqlite3" for simulations/measure.py.

The REST API is called directly: chromadb 0.5.x's own HTTP client double-encodes request
bodies with the httpx version in the image and the server answers 422. Embeddings are
computed locally with Chroma's default model (all-MiniLM-L6-v2), baked into the image.
"""
import json
import random
import sys
import time
import urllib.request
import uuid

from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

BASE = "http://localhost:8000/api/v2/tenants/default_tenant/databases/default_database"
DB = "/data/chroma/chroma.sqlite3"
TOPICS = ["history", "physics", "football", "music", "geography", "chemistry"]
EMBED = DefaultEmbeddingFunction()


def call(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read() or b"null")


def vec(text):
    return [float(x) for x in EMBED([text])[0]]


def add(cid):
    topic = random.choice(TOPICS)
    doc = f"A new reference paragraph about {topic}."
    call(f"/collections/{cid}/add", {"ids": [f"legit-{uuid.uuid4()}"], "embeddings": [vec(doc)],
                                     "documents": [doc], "metadatas": [{"title": topic, "source": "legit_chroma"}]})
    print(f"@@ t04 {int(time.time() * 1000)} {DB}", flush=True)


def query(cid):
    call(f"/collections/{cid}/query", {"query_embeddings": [vec(f"What is known about {random.choice(TOPICS)}?")],
                                       "n_results": 3, "include": ["documents"]})


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "add"
    cid = call("/collections", {"name": "squad", "get_or_create": True})["id"]
    if mode == "add":
        add(cid)
        return
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 600
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 2
    end, adds, queries = time.time() + seconds, 0, 0
    while time.time() < end:
        if random.random() < 0.3:
            add(cid)
            adds += 1
        else:
            query(cid)
            queries += 1
        time.sleep(interval)
    print(f"workload done: {adds} adds, {queries} queries", file=sys.stderr)


if __name__ == "__main__":
    main()
