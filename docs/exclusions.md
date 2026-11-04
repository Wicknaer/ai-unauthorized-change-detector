# Excluded paths

ChromaDB writes temporary SQLite files next to `chroma.sqlite3` during normal operation and
deletes them shortly after. Monitoring them would turn every legitimate write into an alert
and break the false positive target (NFR-07: ≤ 1 %), so they are excluded (FR-01).

| Pattern | Source | Why it is safe to exclude |
|---|---|---|
| `*-journal` | SQLite rollback journal | Transient; the committed state lands in `chroma.sqlite3`, which is monitored |
| `*-wal` | SQLite write-ahead log (WAL mode) | Same as above; checkpointed into the main file |
| `*-shm` | SQLite shared-memory index for WAL | Contains no data |
| `*.lock` | Lock files | Contain no data |
| `*.tmp` | Temporary files | Short-lived; the final file is monitored after the rename |

Patterns are matched against the file name and against the path relative to the watch root,
so `index/*.tmp` is also possible.

**Trade-off.** An attacker could write into an excluded file, but SQLite only treats a
journal/WAL as part of the database while it is being replayed; the moment the change reaches
`chroma.sqlite3` it is detected. Exclusions must never cover the data files themselves.
