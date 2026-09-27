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
   podman run --rm \
     -p 127.0.0.1:8080:8080 \
     -e TAILSCALE_AUTHKEY=tskey-... \
     -e VAULTWARDEN_DOMAIN=https://vaultwarden-hummingbird.<your-tailnet>.ts.net \
     ghcr.io/edgarcnp/vaultwarden-hummingbird:latest
   ```

3. From a device on your tailnet, open that `https://…ts.net` address and create your account.

The published port only answers `/alive` — 200 when the vault is up, 503 when it isn't, 403 for everything else:

```sh
curl -i http://127.0.0.1:8080/alive
```

Each release publishes new images. Pin an exact version tag for a stable deployment, or follow `:latest`.

## How it works

Tailscale is the only way in. The vault listens on loopback and never leaves the container's network namespace; `tailscale serve` publishes it on your tailnet as `https://<hostname>.<tailnet>.ts.net`, so only your devices can reach it — no TUN device or extra privileges needed.

No Tailscale, no vault. The container refuses to start without an auth key or S3 state sync, and if Tailscale dies later it shuts down instead of running a vault nobody can reach. Your orchestrator restarts it; a short outage beats a silent one.

## Configuration

Copy [`.env.example`](.env.example) to `.env`, fill in what it asks for, and give it to the container: mount it (compose does this for you), pass it with `--env-file`, or paste the values into your platform's environment settings.

Keys come in three groups:

- `TAILSCALE_*` — how the container joins your tailnet (hostname, auth key, and friends).
- `SUPERVISOR_*` — this image's extras: state sync and backups (below).
- `VAULTWARDEN_*` — Vaultwarden's own settings with a prefix. `VAULTWARDEN_SIGNUPS_ALLOWED` becomes `SIGNUPS_ALLOWED` inside. Vaultwarden's [`.env.template`](https://github.com/dani-garcia/vaultwarden/blob/1.37.2/.env.template) lists everything it understands.

The file is strict on purpose: a key outside those three prefixes stops the boot and names the offender, and so does an unknown `SUPERVISOR_*`/`TAILSCALE_*` key (that's a typo — the supervisor's keys are a closed set). An unreadable file refuses the boot too, rather than start with settings missing. Unknown `VAULTWARDEN_*` keys pass through to the vault, which ignores what it doesn't know. Strictness is about the file; values handed in as container environment are filtered rather than rejected.

Three rules that save confusion:

- The container's environment wins over the file, and an empty value means unset.
- An unquoted `$VAR` is substituted from the environment; single-quote a value to keep a literal `$`.
- On the container environment, only `VAULTWARDEN_*` keys reach the vault.

Coming from an older image? Prefix every bare key with `VAULTWARDEN_`, and rename `ROCKET_PORT`/`VAULTWARDEN_ROCKET_PORT` to `VAULTWARDEN_PORT`.

### Tailscale options

- `TAILSCALE_SERVE` (default `true`) — publish the vault over tailnet HTTPS. Needs MagicDNS and HTTPS certificates; set `false` to run without the `*.ts.net` address.
- `TAILSCALE_HOSTNAME` — the node name (default `vaultwarden-hummingbird`).
- `TAILSCALE_SERVICE` — advertise the vault as a Tailscale Service; needs a tag-based auth key and approval in the console.
- `TAILSCALE_USERSPACE` (default `true`) — userspace networking, no privileges. `false` switches to TUN mode: slightly faster, needs `NET_ADMIN` and `/dev/net/tun`.

## Keeping /data across redeploys

If `/data` is a real volume, you're done.

If your platform wipes `/data` on every redeploy, point the container at an S3-compatible bucket — Cloudflare R2, Backblaze B2, MinIO, AWS S3, anything that speaks the S3 API. Every provider is configured by its endpoint; none is a default:

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
# SUPERVISOR_S3_SYNC_INTERVAL=3600
```

- At boot it restores what is missing, but never overwrites a newer local file.
- It saves after Tailscale connects, shortly after the vault starts, on a cadence, and on shutdown. The final save is budgeted (two minutes; fifteen seconds after a second stop signal) so a slow bucket can't hold the container open.
- It saves the tailnet identity, the vault's RSA signing key, TLS certificates, and your attachment and Send uploads — so a redeploy keeps the same node, the same sessions, and your files. The signing key matters most: lose it and every session logs out. A custom `TAILSCALE_STATE_FILE` must live under `/data` to ride along; the container says so at boot when it doesn't.
- Only files whose content changed are re-uploaded, downloads are verified against a recorded hash, and large files upload in parts. Uploads are content-addressed, so an interrupted push can never replace the copy the last good manifest names, and a new file whose manifest write was interrupted is recovered on the next boot. A quiet node costs one manifest read per push and one listing per boot, not a round of uploads.
- Keep the bucket private (it holds secrets and your files) and run one container against it.

Rather stay fully ephemeral? Use `TAILSCALE_STATE_FILE=mem:` with an `ephemeral=true` auth key: the container joins as a fresh node every boot and devices log in again. Vaultwarden also tries to detect a non-persistent `/data`, but how well that works depends on the mount — treat `/data` as gone unless it's a real volume or sync is on.

## Backups

The vault's database is a single SQLite file, `/data/db.sqlite3` — no database server to run. With the bucket above configured, the container can back it up on a schedule:

```sh
SUPERVISOR_DB_BACKUP=true
# SUPERVISOR_DB_BACKUP_INTERVAL=21600   # seconds; default 6h
# SUPERVISOR_DB_BACKUP_KEEP=3           # backups to keep
```

- A backup is a clean point-in-time copy (`VACUUM INTO`) taken while the vault runs; it doesn't pause or lock the vault (the image keeps WAL mode on, so the copy never blocks the vault).
- Backups land under `db/` with a timestamp, and the oldest are deleted beyond `KEEP`. An unchanged database isn't re-uploaded. If the container dies mid-backup you lose one cycle, never gain a broken backup.
- A graceful stop takes one more backup after the vault exits, so a normal redeploy carries the latest sessions and devices. Give the orchestrator time to drain (compose's `stop_grace_period`).
- `SUPERVISOR_DB_BACKUP_RESTORE=true` loads the newest backup at boot, but only into a database it can prove is empty — if the newest copy is damaged it tries the next one, and it never overwrites existing data. If it can't tell (an unreadable database, a bucket it can't list), it refuses to start rather than guess.
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
- **`db backup: … skipped/failed`.** That cycle didn't run and nothing was lost; the next one retries. The message names what to check: S3 settings, free space on `/data`, or `refusing to shadow it` (the bucket holds a newer backup — the message says how to adopt it).

## Building it yourself

See [CONTRIBUTING.md](CONTRIBUTING.md).
