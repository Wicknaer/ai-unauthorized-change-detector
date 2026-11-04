FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends sqlite3 python3 coreutils sed findutils \
    && rm -rf /var/lib/apt/lists/*
ENV DATA_DIR=/data
CMD ["sleep", "infinity"]
