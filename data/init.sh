#!/bin/sh
# One-shot data loader for the lab (data-init service). Idempotent: exits early when the
# ai-data volume is already populated, so restarts never re-download anything.
set -eu
DATA=/data
HERE="$(dirname "$0")"
MARKER="$DATA/.init-complete"

if [ -f "$MARKER" ]; then
  echo "ai-data already initialised ($(cat "$MARKER")); nothing to do"
  exit 0
fi

mkdir -p "$DATA/models" "$DATA/synthetic" "$DATA/datasets" "$DATA/chroma"

"$HERE/download_models.sh" "$DATA/models" ${MODELS:-gpt2}
for size in ${SYNTHETIC_SIZES:-100M}; do
  python "$HERE/make_synthetic.py" --size "$size" --out "$DATA/synthetic"
done
python "$HERE/prepare_imdb.py" --out "$DATA/datasets"
python "$HERE/build_chroma.py" --path "$DATA/chroma" --limit "${SQUAD_LIMIT:-0}"

# ChromaDB runs as a non-root user; hand the vector DB over to it (week 4 finding).
chown -R "${CHROMA_UID:-1000}:${CHROMA_UID:-1000}" "$DATA/chroma"

date -u +%Y-%m-%dT%H:%M:%SZ > "$MARKER"
echo "ai-data initialised"
