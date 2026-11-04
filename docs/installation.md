# Installation

## Requirements

| Component | Requirement |
|---|---|
| OS | Linux, kernel 5.1 or newer (Ubuntu 22.04 / 24.04 LTS recommended) |
| Containers | Docker Engine + Docker Compose v2 |
| Hardware | 4 cores, 8 GB RAM, 60 GB free disk (the 4 GB synthetic file and the models need room) |
| Development | Go 1.22+, Python 3.10+ |

> Docker Desktop on Windows/macOS does not deliver file events from bind mounts reliably.
> Run the lab inside a Linux VM (or inside the WSL2 Linux file system), not on a Windows path.

## 1. Lab (Docker)

```bash
git clone https://github.com/Wicknaer/ai-unauthorized-change-detector.git
cd ai-unauthorized-change-detector
docker compose -f docker/docker-compose.yml up -d --build
```

The first start takes a while: `data-init` downloads GPT-2 and TinyLlama, generates the
synthetic files, converts IMDB and builds the SQuAD ChromaDB collection. Later starts skip
all downloads (`/data/.init-complete`). For a quick smoke test use smaller inputs:

```bash
MODELS=gpt2 SYNTHETIC_SIZES=100M SQUAD_LIMIT=2000 docker compose -f docker/docker-compose.yml up -d --build
```

Check that everything is up and the agent created its baseline:

```bash
docker compose -f docker/docker-compose.yml ps
docker compose -f docker/docker-compose.yml logs agent
docker compose -f docker/docker-compose.yml exec agent fimagent status
```

Verify the network and volume isolation:

```bash
bash docs/isolation_check.sh
```

Run an attack from the compromised container and watch the alert appear:

```bash
docker compose -f docker/docker-compose.yml exec attacker bash /simulations/attacks.sh t01
docker compose -f docker/docker-compose.yml logs --tail 5 agent
docker compose -f docker/docker-compose.yml exec agent fimagent report -since 10m
```

### Known issues

* **Embedding model download fails in `ai-app`:** the lab network is `internal`, so the image
  pre-downloads `all-MiniLM-L6-v2` at build time. Rebuild the image if you change Chroma versions.
* **ChromaDB cannot write `/data/chroma`:** `data-init` runs as root; it hands `/data/chroma`
  over to UID 1000 at the end (`CHROMA_UID`). If you created the volume by hand, run
  `chown -R 1000:1000` on it.

## 2. Agent only (no Docker)

```bash
cd agent
go build -o fimagent ./cmd/fimagent
./fimagent init  -config /path/to/config.yaml
./fimagent watch -config /path/to/config.yaml
```

See `config/agent.docker.yaml` for a commented configuration and `examples/demo/` for a
self-contained demo that runs on any OS.

## 3. Development

```bash
cd agent
go vet ./...
go test ./...
go test -bench . ./internal/hasher/
```
