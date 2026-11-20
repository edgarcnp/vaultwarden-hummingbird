# Database backups

The vault's database is one SQLite file, `/data/db.sqlite3`; there is no
database server to run. With an S3 bucket configured, the container can dump
that file on a schedule and restore the newest dump into an empty database.

Backups cover the database only. Attachments and Sends are part of
[state sync](state-sync.md).

```sh
SUPERVISOR_S3_REMOTE=r2:vaultwarden
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...

SUPERVISOR_DB_BACKUP=true
# SUPERVISOR_DB_BACKUP_INTERVAL=21600   # seconds; default 6h
# SUPERVISOR_DB_BACKUP_KEEP=3           # dumps kept
# SUPERVISOR_DB_BACKUP_RESTORE=false    # opt-in boot restore
```

## How a dump is taken

A dump is a clean point-in-time copy made with `VACUUM INTO` while the vault
runs. The image keeps WAL mode on, so the copy does not pause or lock the
vault.

Before SQLite opens anything, the supervisor pins the live database and its
WAL/SHM sidecars through hard links in a private `0700` directory on the data
volume. SQLite opens `/proc/self/fd/<dirfd>/db`, so a path swap by the vault
cannot redirect the dump. The directory is removed when the dump finishes, and
a crash leftover is swept on the next run. If `/proc/self/fd` is unavailable,
the backup fails closed.

The staged dump is hashed once, uploaded, and then referenced by the manifest.
An empty database is never backed up: a wiped `/data` must not replace good
bucket data with a blank database.

## Bucket layout

With state-sync prefix `P`:

```text
P/db/manifest                              authoritative dump set
P/db/sqlite-<timestamp>-<random>.sqlite3   dump objects
```

The manifest is a `v2` text file, one entry per dump:

```text
v2
1 sqlite-20260901T010203Z-aabbccdd.sqlite3 983040 <sha256>
2 sqlite-20260927T101112Z-11223344.sqlite3 983552 -
```

Fields are `<generation> <name> <size> <sha256|->`. Generations are monotonic,
so order comes from the manifest rather than the wall clock. `v2` records the
dump's SHA-256; a `-` marks an entry inherited from a `v1` or legacy layout,
where only the size was recorded. A `v1` manifest remains readable.

## Retention

Dumps beyond `SUPERVISOR_DB_BACKUP_KEEP` (default `3`, maximum `1000`) are
deleted oldest first, strictly after the manifest write that dropped them. A
crash between the manifest write and the prune leaves an unreferenced object;
the next cycle removes unreferenced dumps older than 24 hours, at most 1000 per
tick. A fresh object is left alone so an in-flight push is never mistaken for
an orphan.

An unchanged database is not re-uploaded. A 64-byte sidecar on `/state`
(`db-backups-<key>.last`) remembers the last pushed dump's SHA-256, keyed by the
database, remote, and endpoint. Switching any of them starts clean. If the
sidecar is missing or unreadable, the dump is uploaded normally.

## Restore

`SUPERVISOR_DB_BACKUP_RESTORE=true` loads the newest usable dump at boot, but
only into a database it can prove is empty. It never overwrites existing data.

- Candidates are tried newest generation first.
- A `v2` candidate is verified against its SHA-256 and size before import; `v1`
  and legacy entries are size-checked only.
- A damaged or missing candidate falls back to the next older one.
- If the database is unreadable, the bucket cannot be listed, or the transport
  fails, the boot is refused rather than guessed. An explicitly requested
  restore never boots fresh behind the operator's back.
- The whole fallback is bounded by a 30-minute budget.

To restore by hand, stop the vault and replace `/data/db.sqlite3` with a dump.
Remove the `-wal` and `-shm` files first; they belong to the old database.

## Lineage guard

"Newest wins" restore is only sound if the database that pushes owns the
bucket's newest generation. A sidecar on `/state`
(`db-backups-<key>.state`) records that ownership. A stale or foreign database
that cannot prove continuity is refused, so it cannot shadow good backups.

`SUPERVISOR_DB_BACKUP_RESTORE=true` adopts the bucket's newest generation,
which is also the remedy after moving a volume or restoring by hand. A push is
refused while the bucket cannot be listed or the manifest cannot be read.

## A graceful stop

A graceful stop takes one more dump after the vault exits, so a normal redeploy
carries the latest sessions and devices. Give the orchestrator time to drain;
`compose.yaml` uses `stop_grace_period: 180s`.

A repeated stop signal shortens the final persist budget to 15 seconds. A
`SIGKILL` skips the final dump; the previous cycle is still intact.

## Rollback compatibility

The `v2` manifest is forward-only: a supervisor from the `v1` era cannot read
it. If you roll back the image, keep the manifest and dump set matched to the
image that wrote them, or restore by hand. Do not point an older image at a
bucket a newer image has written.

See [operations](operations.md#rolling-back) for the image rollback rules and
[bucket safety](state-sync.md#bucket-safety) for key scoping and retention.
