#!/bin/sh
# Downloads the open-licence model files used in the experiments.
#   download_models.sh <out_dir> [gpt2] [tinyllama-q4] [tinyllama-q8]
set -eu
OUT="${1:?usage: $0 <out_dir> [model...]}"; shift
mkdir -p "$OUT"
[ $# -gt 0 ] || set -- gpt2

HF=https://huggingface.co
fetch() {
  name="$1"; url="$2"
  if [ -s "$OUT/$name" ]; then echo "skip $name (exists)"; return; fi
  echo "downloading $name"
  curl -fL --retry 3 -o "$OUT/$name.part" "$url"
  mv "$OUT/$name.part" "$OUT/$name"
}

for m in "$@"; do
  case "$m" in
    gpt2)         fetch gpt2-124m.safetensors "$HF/openai-community/gpt2/resolve/main/model.safetensors" ;;            # MIT, ~548 MB
    tinyllama-q4) fetch tinyllama-1.1b-chat.Q4_K_M.gguf "$HF/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" ;; # Apache-2.0, ~669 MB
    tinyllama-q8) fetch tinyllama-1.1b-chat.Q8_0.gguf "$HF/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q8_0.gguf" ;;     # Apache-2.0, ~1.17 GB
    *) echo "unknown model $m" >&2; exit 2 ;;
  esac
done
