FROM python:3.11-slim
RUN pip install --no-cache-dir chromadb==0.5.23
# Pre-fetch the default embedding model (all-MiniLM-L6-v2) at build time: ai-app runs on the
# internal network and cannot download it at runtime (week 4 finding).
RUN useradd -u 1000 -m chroma
USER chroma
# chroma run writes chroma.log to the working directory; it must be writable by this user.
WORKDIR /home/chroma
RUN python -c "from chromadb.utils.embedding_functions import DefaultEmbeddingFunction as E; E()(['warm-up'])"
EXPOSE 8000
CMD ["chroma", "run", "--path", "/data/chroma", "--host", "0.0.0.0", "--port", "8000"]
