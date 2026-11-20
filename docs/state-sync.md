# State sync

State sync keeps the files that make a redeploy look like the same vault. It is
opt-in and runs against any S3-compatible bucket.

It stores:

- the Tailscale node identity (`tailscaled.state`), so the node keeps its name
  and does not register again;
- the vault's RSA signing keys (`rsa_key*`), so existing sessions stay valid;
- `config.json`;
- the TLS certificate cache (`certs/**`);
- attachments (`attachments/**`) and Sends (`sends/**`).

It does not store the SQLite database; [backups](backup.md) cover that. It also
does not store the dotenv file, backup sidecars, or the local hash cache.

Configure it with `SUPERVISOR_S3_*`; see
[configuration](configuration.md#s3-state-sync).

```sh
SUPERVISOR_S3_REMOTE=r2:vaultwarden
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
```

## Bucket layout

With a remote prefix `P` (empty or ending in `/`):

```text
P/manifest                     last pushed set, one line per file
P/tombstones                   paths deleted locally and their grace clock
P/objects/<path>/<sha256>      immutable content-addressed objects
P/<path>                       legacy layout, read on a miss
```

The manifest is a `v1` text file. Each line is `<sha256> <size> <relative
path>`. It is the bucket-side authority for what the last push contained. A
missing manifest means a legacy bucket: the listing is authoritative and files
are size-checked only until the first push writes a manifest.

Objects are immutable by construction. A changed file gets a new key, so an
interrupted push can never overwrite the copy the previous manifest names.

## Restore at boot

The boot pass pulls what is missing. It never overwrites a newer local file.

- Every downloaded file is verified against the manifest's SHA-256 before it is
  published. Legacy objects without a manifest are size-checked only.
- Downloads are anchored on the parent directory descriptor, so a symlink
  swapped into the tree after the check cannot redirect the write outside the
  volume.
- A partial pull is allowed: the next boot retries. The whole pass has a
  30-minute budget.
- A best-effort reconciliation lists the bucket once per boot. Unreferenced
  objects (a crash between upload and manifest write) are pulled when the local
  file is missing. A manifest entry whose object is gone or whose size changed
  goes on a local repair list, so the next push re-uploads the local file
  instead of trusting the stale entry.

## Push

Pushes run:

- after `tailscale up`, which persists the node identity;
- 30 seconds after the vault starts, once the signing key exists (the
  supervisor waits up to 120 seconds for it);
- on `SUPERVISOR_S3_SYNC_INTERVAL` (default one hour; `0` disables the periodic
  cadence);
- on shutdown, within the final persist budget.

Only files whose content changed are uploaded. The hash and the upload read the
same opened file, so a file changed mid-transfer is not committed. A local hash
cache keyed by size, mtime, and ctime avoids re-hashing large files; a cached
hash is only used to skip an upload, never to decide that bytes are correct.

A quiet node costs one manifest read, one tombstone read, and one listing (the
garbage-collection pass) per push, not a round of uploads.

## Deletions

A file deleted locally becomes a tombstone only after 24 hours of consistent
absence. That grace keeps a transient restore failure or a lost volume from
deleting bucket data.

- The node identity, signing keys, and certificates are never tombstoned.
- A disappearance of every manifest file at once, or of more than a quarter of
  the manifest including identity files, is refused as probable volume loss.
  Delete in smaller batches, or clear the bucket to reset a vault
  intentionally.
- Tombstoned paths are not restored. Their objects are garbage-collected after
  another day, and the tombstones themselves are pruned after 30 days.
- A file that reappears locally clears its tombstone on the next push.

A push is refused while the bucket cannot be proven complete, for example
after a partial restore. The fallback path-key layout is never written in that
state, because it could overwrite a newer bucket copy.

## Limits

- One sync object may be at most 1 GiB.
- Files at or above 16 MiB upload in 8 MiB parts, up to 10,000 parts.
- A bucket supports about 100,000 objects per prefix. A listing that would
  exceed the cap fails closed rather than truncating.

## Ephemeral hosts

Use `TAILSCALE_STATE_FILE=mem:` with an `ephemeral=true` auth key to join as a
fresh node every boot. Devices log in again. Set `SUPERVISOR_EPHEMERAL=true`
(or use `mem:`) on a platform with temporary storage; an explicitly configured
but unusable S3 or backup setting then refuses the boot instead of quietly
losing persistence. The certificate cache still uses `/state/tailscale/certs`.

## Bucket safety

Treat the bucket as part of the security boundary.

- Use a dedicated access key, scoped to this bucket or prefix.
- Keep identity state and backups apart where the provider allows it.
- Enable object versioning and, if available, object lock or retention.
- Expire incomplete multipart uploads with a lifecycle rule; a killed container
  can leave parts behind.
- Encrypt at rest, usually the provider's default. Consider client-side
  encryption if the provider is inside your threat model.
- Run one container per bucket or prefix.
