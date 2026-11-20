# vaultwarden-hummingbird

Your own password vault, reachable only from your devices.

This image runs [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (a lightweight server compatible with the Bitwarden apps) next to [Tailscale](https://tailscale.com), on Red Hat's minimal [Hummingbird](https://images.redhat.com/) base. The vault is never exposed to the internet — Tailscale is the only way in — and the container runs as a non-root user with no shell and no package manager, so there is almost nothing for an intruder to work with. Release artifacts are checksum-verified and even the base images are pinned by digest.

## Quick start

You need a [Tailscale](https://tailscale.com) account, with MagicDNS and HTTPS certificates enabled for your tailnet (both are switches in the admin console).

1. Pull the image (`amd64` and `arm64`):

   ```sh
   podman pull ghcr.io/edgarcnp/vaultwarden-hummingbird:latest
   ```

2. Run it. `VAULTWARDEN_DOMAIN` must be the address Tailscale will serve your vault on:

   ```sh
   cp .env.example .env    # fill in TAILSCALE_AUTHKEY and VAULTWARDEN_DOMAIN
   podman run --rm \
     -p 127.0.0.1:8080:8080 \
     -e SUPERVISOR_ENV_FILE=/state/.env \
     -v "$PWD/.env:/state/.env:ro,z" \
     --cap-drop=all --cap-add=SETUID --cap-add=SETGID --cap-add=KILL \
     --cap-add=DAC_READ_SEARCH \
     --security-opt no-new-privileges \
     -v vw-data:/data -v vw-state:/state \
     ghcr.io/edgarcnp/vaultwarden-hummingbird:latest
   ```

   The file is mounted under `/state`, which the vault's uid cannot
   traverse; prefer this over `--env-file`, which leaves the secrets in the
   container environment. It must live outside `/state/tailscale` and its
   `tailscale-state` link (the tailscaled-writable subtree can replace a
   file there regardless of its mode) and must be readable by container uid
   `65532` but not by the tailscaled group: use `0600` owned by `65532`, or
   `0640` with group `65532` (never `0644`, which the tailscaled group could
   read through its `/state` traverse; the supervisor warns when the file is
   world-readable). The two named volumes
   persist the vault and the supervisor's identity/state; without the
   capabilities the supervisor cannot start the vault under its separate
   uid.

3. From a device on your tailnet, open that `https://…ts.net` address and create your account.

The published port only answers `/alive` (an optional query string is accepted) — 200 when the vault is up, 503 when it isn't, 403 for everything else:

```sh
curl -i http://127.0.0.1:8080/alive
```

Each release publishes new images. Only the three newest releases stay on the registry — older versions are pruned after every release, tags included — so pin one of those, or follow `:latest`.

## How it works

Tailscale is the only way in. The vault listens on loopback and never leaves the container's network namespace; `tailscale serve` publishes it on your tailnet as `https://<hostname>.<tailnet>.ts.net`, so only your devices can reach it — no TUN device or extra privileges needed.

No Tailscale, no vault. The container refuses to start without an auth key, a valid local `TAILSCALE_STATE_FILE`, or S3 state sync that can supply the node identity, and if Tailscale dies later it shuts down instead of running a vault nobody can reach. Your orchestrator restarts it; a short outage beats a silent one.

The container keeps two volumes and three identities. `/data` (0770, group `65532`) holds the vault: its database, signing key, `config.json`, attachments, and Sends. `/state` (2710, owner `65532`, group `tailscale` `65531`) is supervisor-only: group members can traverse it but not list it, and its 0600 files stay owner-only. `/state/tailscale` (2770) holds the tailscaled identity, certificate cache, and LocalAPI socket; `/state/tailscale-state` is a supervisor-created symlink to it used for `tailscaled --state`, because Tailscale chmods a state directory named exactly `tailscale` to 0700 and the daemon uid cannot do that on the supervisor-owned tree. The supervisor runs as `65532:65532` and joins the `tailscale` group; tailscaled runs as `65531:65531`; the vault runs as `65533:65532` and is not in the tailscale group. The supervisor starts every child with its capabilities dropped: the vault has none, the tailscale CLI has none, and tailscaled keeps only `NET_ADMIN`/`NET_RAW` in TUN mode (the container must grant them and expose `/dev/net/tun`; rootless podman cannot create a TUN in its user namespace); userspace mode needs none. A compromised vault cannot traverse `/state` or read the socket; a compromised tailscaled can reach only its own subtree, not the dotenv, sync sidecars, or `/data`. The supervisor itself keeps `SETUID`/`SETGID` (to start the vault and tailscaled), `KILL` (to stop them), and `DAC_READ_SEARCH` (Tailscale writes its identity and cert files 0600; the supervisor reads them for state sync, and no child keeps this capability). In TUN mode the container also grants `NET_ADMIN`/`NET_RAW`; only the tailscaled child keeps them.

## Configuration

Copy [`.env.example`](.env.example) to `.env`, fill in what it asks for, and mount that file at `/state/.env` (compose does this). `--env-file` or your platform's environment settings also work, but put the secrets in the container environment instead of the supervisor-only volume; a dotenv file mounted anywhere outside `/state` is refused at boot.

Keys come in three groups:

- `TAILSCALE_*` — how the container joins your tailnet (hostname, auth key, and friends).
- `SUPERVISOR_*` — this image's extras: state sync and backups (below).
- `VAULTWARDEN_*` — Vaultwarden's own settings with a prefix. `VAULTWARDEN_SIGNUPS_ALLOWED` becomes `SIGNUPS_ALLOWED` inside. Vaultwarden's [`.env.template`](https://github.com/dani-garcia/vaultwarden/blob/1.37.5/.env.template) lists everything it understands. Since 1.37.5 an invalid value in that file stops the vault at startup instead of being coerced, so a rejected setting shows up as a refusal in the container log.

The file is strict on purpose: a key outside those three prefixes stops the boot and names the offender, and so does an unknown `SUPERVISOR_*`/`TAILSCALE_*` key (that's a typo — the supervisor's keys are a closed set). An unreadable file refuses the boot too, rather than start with settings missing. Unknown `VAULTWARDEN_*` keys pass through to the vault, which ignores what it doesn't know. Strictness is about the file; values handed in as container environment are filtered rather than rejected.

Three rules that save confusion:

- The container's environment wins over the file, and an empty value means unset.
- An unquoted `$VAR` is substituted from the container environment; single-quote a value to keep a literal `$`. Substitution reads the whole environment, so never reference a supervisor secret (`TAILSCALE_AUTHKEY`, `SUPERVISOR_S3_*`) from a `VAULTWARDEN_*` value: it would copy that secret into the vault.
- On the container environment, only `VAULTWARDEN_*` keys reach the vault.

Coming from an older image? Prefix every bare key with `VAULTWARDEN_`, and rename `ROCKET_PORT`/`VAULTWARDEN_ROCKET_PORT` to `VAULTWARDEN_PORT`.

Coming from the single-volume layout? Update the mounts and capabilities in your run command or compose file: `.env` moves to `/state/.env` (a dotenv file elsewhere now refuses the boot), add a `vw-state:/state` volume, and add `SETUID`/`SETGID`/`KILL`/`DAC_READ_SEARCH` after `cap_drop: ALL`. A custom `TAILSCALE_STATE_FILE` or `TAILSCALE_SOCKET` outside `/state/tailscale` must be moved first; a custom state file must be a direct child of `/state/tailscale-state` (a legacy direct child of `/state/tailscale` is mapped onto the link). On the first boot the supervisor moves the old `tailscaled.state`, `certs/` cache, and backup lineage from `/data` to `/state`, moves the identity and certs into `/state/tailscale` (layout v3), creates the `tailscale-state` link, and makes the vault's existing files group-accessible; a failed copy leaves the source in place and refuses the boot. Old-layout identity and cert files must be owned by uid `65532` — a foreign-owned file is refused rather than adopted. Bucket key names are unchanged, so an existing state-sync bucket restores into either layout. Rolling back to an image before the uid split needs the identity back at the old paths: move `/state/tailscale/tailscaled.state` and `/state/tailscale/certs/` to `/state/` first; that image does not understand the v3 layout or the link. Do not roll back to the first dedicated-uid image (before this state-link fix): it cannot chmod the state directory and runs tailscaled with an in-memory store; keep this image, or roll back past the uid split.

### Tailscale options

- `TAILSCALE_SERVE` (default `true`) — publish the vault over tailnet HTTPS. Needs MagicDNS and HTTPS certificates; set `false` to run without the `*.ts.net` address.
- `TAILSCALE_HOSTNAME` — the node name (default `vaultwarden-hummingbird`).
- `TAILSCALE_SERVICE` — advertise the vault as a Tailscale Service; needs a tag-based auth key and approval in the console.
- `TAILSCALE_USERSPACE` (default `true`) — userspace networking, no privileges. `false` switches to TUN mode: slightly faster, needs `NET_ADMIN` (and `NET_RAW` for some setups) and `/dev/net/tun`; the supervisor keeps only those capabilities in the tailscaled child.

## Keeping data across redeploys

If `/data` and `/state` are real volumes, you're done. Keep them together: `/state` holds the node identity that `/data`'s vault belongs to.

Named volumes inherit the image's ownership and modes. If you bind-mount host directories instead, they must be owned by uid/gid `65532` (and labeled `:Z` on an SELinux host); otherwise the supervisor refuses to boot rather than run with a state directory the vault could write.

If your platform wipes them on every redeploy, point the container at an S3-compatible bucket — Cloudflare R2, Backblaze B2, MinIO, AWS S3, anything that speaks the S3 API. Every provider is configured by its endpoint; none is a default. The key needs object read/write/**delete** and bucket list (`ListObjectsV2`) for first-run, restore, reconciliation, deletion GC, and backup pruning; bucket create/head (`CreateBucket`/`HeadBucket`) are never called, and the one object `HEAD` only verifies that the newest backup still exists. Plaintext HTTP is refused for a remote endpoint; set `SUPERVISOR_S3_ALLOW_HTTP=true` only on a trusted private network.

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
# SUPERVISOR_S3_SYNC_INTERVAL=3600
# Optional transport: region, URL style, a private CA (under /state, outside
# /state/tailscale and tailscale-state), and
# plaintext HTTP for a trusted network only. See .env.example.
```

If the endpoint has no scheme, HTTPS is used. A remote `http://` endpoint is refused unless `SUPERVISOR_S3_ALLOW_HTTP=true`; loopback endpoints are always allowed.

- At boot it restores what is missing, but never overwrites a newer local file.
- It saves after Tailscale connects, shortly after the vault starts, on a cadence, and on shutdown. The final save is budgeted (two minutes; fifteen seconds after a second stop signal) so a slow bucket can't hold the container open.
- It saves the tailnet identity, the vault's RSA signing key, your admin `config.json`, TLS certificates, and your attachment and Send uploads — so a redeploy keeps the same node, the same sessions, and your files. The signing key matters most: lose it and every session logs out. A custom `TAILSCALE_STATE_FILE` must be a direct child of `/state/tailscale-state` (the link to the real tree; legacy `/state/tailscale` names are mapped); a path on `/data`, `/custom`, `/state`, or with `..` refuses the boot. The LocalAPI socket must live under `/state/tailscale`.
- Only files whose content changed are re-uploaded; manifest downloads are verified against a recorded hash (a pre-manifest bucket is size-checked only), and large files upload in parts. The hash and the upload use the same opened file, so a file changed mid-transfer is not committed. Pulls publish through a descriptor-anchored parent directory, so a symlink swapped into the tree after the check cannot redirect the write outside the volume. Uploads are content-addressed, so an interrupted push can never replace the copy the last good manifest names, and a new file whose manifest write was interrupted is recovered on the next boot. A quiet node costs a manifest and tombstone read plus one listing per push (the GC pass), and at most one listing per boot (a legacy bucket may list twice; the first manifest-less push also lists once for completeness), not a round of uploads.
- A push is refused while the bucket cannot be proven complete (for example after a partial restore): the fallback path-key layout is never written, because it could overwrite a newer bucket copy.
- A user file deleted locally is recorded as a tombstone only after 24 hours of consistent absence, so a transient restore failure or a lost volume cannot delete bucket data. The node identity, signing keys, and certificates are never tombstoned, even after the grace. A disappearance of every manifest file at once, or of more than a quarter of the manifest (identity files included), is refused as probable volume loss; delete in smaller batches, or clear the bucket to reset a vault intentionally. Tombstoned paths are never restored, their objects are garbage-collected after another day, and a file that reappears locally clears its tombstone on the next push. Tombstones are pruned after 30 days. The bucket supports up to about 100k objects per prefix; beyond that a listing fails closed rather than truncating.
- Keep the bucket private (it holds secrets and your files) and run one container against it.

Rather stay fully ephemeral? Use `TAILSCALE_STATE_FILE=mem:` with an `ephemeral=true` auth key: the container joins as a fresh node every boot and devices log in again. On a PaaS with temporary storage, also set `SUPERVISOR_EPHEMERAL=true` (or use `mem:`; a tmpfs `/data` or vaultwarden's `I_REALLY_WANT_VOLATILE_STORAGE` acknowledgement is detected too). In that mode an explicitly configured but unusable S3/backup setting refuses the boot instead of quietly losing persistence; on a real volume the same error is logged and the feature degrades. Vaultwarden also tries to detect a non-persistent `/data`, but how well that works depends on the mount — treat `/data` as gone unless it's a real volume or sync is on. With `mem:`, the cert cache still uses `/state/tailscale/certs`.

## Backups

The vault's database is a single SQLite file, `/data/db.sqlite3` — no database server to run. With the bucket above configured, the container can back it up on a schedule:

```sh
SUPERVISOR_DB_BACKUP=true
# SUPERVISOR_DB_BACKUP_INTERVAL=21600   # seconds; default 6h
# SUPERVISOR_DB_BACKUP_KEEP=3           # backups to keep
```

- A backup is a clean point-in-time copy (`VACUUM INTO`) taken while the vault runs; it doesn't pause or lock the vault (the image keeps WAL mode on, so the copy never blocks the vault). The live database and its WAL/SHM sidecars are pinned through a private hard-link directory before SQLite opens them, so a vault-side path swap cannot redirect the dump. That directory is owner-only on the data volume and removed when the dump finishes; a crash leftover is swept on the next run.
- Backups land under `db/` with a timestamp, and the oldest are deleted beyond `KEEP`. An unchanged database isn't re-uploaded: a small `db-backups-<id>.last` sidecar on `/state` remembers the last pushed dump's SHA-256, so no second database-sized copy is kept. The sidecar is keyed by the database, remote, and endpoint, so switching any of them starts clean. If the container dies mid-backup you lose one cycle, never gain a broken backup. A dump object uploaded just before a crash but never referenced by a manifest is removed after 24 hours; a fresh object is left alone so a push in flight is never mistaken for one.
- A graceful stop takes one more backup after the vault exits, so a normal redeploy carries the latest sessions and devices. Give the orchestrator time to drain (compose's `stop_grace_period`).
- `SUPERVISOR_DB_BACKUP_RESTORE=true` loads the newest backup at boot, but only into a database it can prove is empty — if the newest copy is missing or fails its integrity/size check it tries the next one, and it never overwrites existing data. New backups carry a SHA-256 in the v2 manifest; v1 and legacy entries are size-checked only. A v1-era supervisor cannot read a v2 manifest, so keep the matching image if you roll back. A transport or local failure refuses the boot instead of silently downgrading the volume; an unusable S3 configuration also refuses (it never boots fresh behind a requested restore). If it can't tell (an unreadable database, a bucket it can't list), it refuses to start rather than guess.
- Prefer to restore by hand? Stop the vault and replace `/data/db.sqlite3` with the dump.
- Want redeploys to carry the newest sessions? Lower the interval, for example to `900`.

### Keeping the bucket safe

The container checks that a downloaded backup is a parseable database, but it can't prove who wrote it: anyone with write access to the bucket could plant something that looks like one. Treat the bucket as part of your security boundary.

- Use a dedicated access key, scoped to this bucket (or prefix) only.
- Keep identity state and backups apart where your provider allows it, so a leaked key has a smaller blast radius.
- Turn on object versioning and, if available, object lock/retention.
- If the provider supports lifecycle rules, let it expire incomplete multipart uploads: a killed container can leave parts behind (the client aborts its own failed uploads, but nothing can run after a SIGKILL).
- Encrypt at rest (usually the provider's default); consider client-side encryption if the storage provider is inside your threat model.

## Defaults

- Sign-ups are open — set `VAULTWARDEN_SIGNUPS_ALLOWED=false` once your accounts exist.
- Attachment uploads are off (`VAULTWARDEN_ORG_ATTACHMENT_LIMIT`/`VAULTWARDEN_USER_ATTACHMENT_LIMIT` change that); Sends are on.
- The web vault is included. `VAULTWARDEN_WEB_VAULT=false` builds an API-only image; `VAULTWARDEN_WEB_VAULT_ENABLED=false` hides it at runtime.
- The admin panel is off until you set an admin token.
- Push notifications are optional: free credentials at https://bitwarden.com/host, then `VAULTWARDEN_PUSH_ENABLED=true` with the ID and key.

## If something is wrong

- **The container exits immediately.** Almost always Tailscale: check the auth key and look for `refusing to run the vault without Tailscale`. With `TAILSCALE_SERVE=true` (default), a failed serve exits the same way — enable MagicDNS and HTTPS certificates, or set `TAILSCALE_SERVE=false`.
- **`/alive` returns 503.** The vault isn't answering, usually the database; its error is in the container logs.
- **`db backup: … skipped/failed`.** That cycle didn't run and nothing was lost; the next one retries. The message names what to check: S3 settings, free space on `/state` (dump staging), or `refusing to shadow it` (the bucket holds a newer backup — the message says how to adopt it).
- **State sync cannot read the Tailscale identity.** The daemon writes `tailscaled.state` and its cert files `0600`; the container must grant `DAC_READ_SEARCH` to the supervisor (compose and the documented run command do). Without it, state sync logs a permission error; add the capability and restart.

## Building it yourself

See [CONTRIBUTING.md](CONTRIBUTING.md).
