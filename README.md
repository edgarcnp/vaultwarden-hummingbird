# vaultwarden-hummingbird

Your own password vault, private and reachable only from your devices.

This container image bundles [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (a lightweight, Bitwarden-compatible server) with [Tailscale](https://tailscale.com), on top of Red Hat's minimal [Hummingbird](https://images.redhat.com/) images. Every component is downloaded from its official source and verified against checksums, the container runs as a non-root user, and there is no shell or package manager inside — there is very little for an attacker to work with.

## How it works

- The vault listens only inside the container. It is never exposed to the network you publish the port on.
- Your published port (8080 by default) answers exactly one request: a health check at `/alive`. It returns 200 when the vault is up and 503 when it isn't. Everything else gets a 403.
- Tailscale makes the vault reachable at `https://<hostname>.<tailnet>.ts.net`, only inside your tailnet. No TUN device or special privileges needed.
- Because Tailscale is the only way in, the container refuses to start without `TAILSCALE_AUTHKEY`, and it shuts down if Tailscale dies. A vault nobody can reach is worse than a brief outage — your orchestrator will restart it.

## Quick start

```sh
podman run --rm -p 127.0.0.1:8080:8080 \
  -e TAILSCALE_AUTHKEY=tskey-... \
  -e VAULTWARDEN_DATABASE_URL=postgresql://... \
  -e VAULTWARDEN_DOMAIN=https://vaultwarden.example.com \
  ghcr.io/edgarcnp/vaultwarden-hummingbird:latest

curl -i http://127.0.0.1:8080/alive
```

Images are published for amd64 and arm64 on every release, and rebuilt weekly so that security fixes in the base images keep flowing. The `:latest` tag only changes on your machine when you pull again. Note: the first release creates the GitHub package as private — switch it to public once in the repo's package settings if you want anyone to be able to pull it.

## Configuration

Everything is configured in one file. Copy [`.env.example`](.env.example) to `.env`, fill in the required values, and either mount it (compose does this for you), pass it with `--env-file`, or paste the values into your platform's environment settings.

The variables fall into three groups:

- `TAILSCALE_*` — how the container joins your tailnet (hostname, auth key, and so on).
- `SUPERVISOR_*` — the optional extras described below (state sync, backups, keepalive).
- `VAULTWARDEN_*` — vaultwarden's own settings, with a `VAULTWARDEN_` prefix added. `VAULTWARDEN_DATABASE_URL` becomes `DATABASE_URL` inside. See vaultwarden's [`.env.template`](https://github.com/dani-garcia/vaultwarden/blob/1.37.2/.env.template) for the full list.

If a variable is set both in the file and directly on the container, the direct value wins. An empty value means "not set".

### Tailscale

- After connecting, the container points `tailscale serve` at the vault so you get a working HTTPS address on your tailnet. Set `TAILSCALE_SERVE=false` to skip this. It needs MagicDNS and HTTPS certificates enabled for your tailnet.
- You can also advertise the vault as a Tailscale Service with `TAILSCALE_SERVICE=vaultwarden`. This needs a tag-based auth key, the Service defined on the [Services page](https://console.tailscale.com/admin/services), and approval (or an `autoApprovers.services` rule in your policy).
- By default Tailscale runs without kernel privileges, which works on most hosting platforms. On your own machine you can set `TAILSCALE_USERSPACE=false` for TUN mode instead — slightly faster, but it needs the `NET_ADMIN` capability and `/dev/net/tun`.
- Rename the node with `TAILSCALE_HOSTNAME`.

## Don't lose your logins on redeploys

On platforms without persistent volumes, the container's `/data` — where Tailscale keeps the machine's identity — disappears on every redeploy. That means a brand-new tailnet node and every device logged out. If that's you, let the container save those identity files to an S3-compatible bucket (Cloudflare R2 works well):

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
# SUPERVISOR_S3_SYNC_INTERVAL=3600
```

It loads them at startup and saves periodically and on shutdown. If you already mount a real volume at `/data`, skip this entirely. Either way, keep the bucket private (it holds secrets) and run only one container against it.

If you'd rather stay fully ephemeral, set `TAILSCALE_STATE_FILE=mem:` and use an `ephemeral=true` auth key — the container registers as a fresh node every boot and devices re-login.

## Keep your database awake

Some managed Postgres free tiers put idle databases to sleep, and the next login then hangs until it wakes up. Ask the container to ping the database every so often:

```sh
SUPERVISOR_DB_KEEPALIVE=300   # seconds; 0 or unset = off
```

Postgres only — it needs the database's own protocol. If the ping fails, nothing bad happens; the container just logs it.

## Back up your vault

With the same S3 credentials as above, the container can also save regular backups of your vault's database to the bucket:

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_DB_BACKUP=true
# SUPERVISOR_DB_BACKUP_INTERVAL=43200   # seconds; default is 12h
# SUPERVISOR_DB_BACKUP_KEEP=3           # how many backups to keep
```

A few things worth knowing:

- Backups are taken without pausing the vault or locking anything: postgres uses `pg_dump`, MySQL/MariaDB uses a consistent snapshot, and SQLite copies itself cleanly.
- Backups are uploaded under `db/` with a timestamp in the name, then the oldest ones are deleted to respect `KEEP`. If the container dies mid-backup you lose one backup, never gain a broken one.
- Set `SUPERVISOR_DB_BACKUP_RESTORE=true` and, at boot, the container will load the newest backup into the database — but only if it can prove the database is empty. If it can't tell, it does nothing rather than guess. It never overwrites existing data.
- To restore by hand: use `pg_restore` for postgres, `mariadb` for MySQL (see the commands in `.env.example`), or replace `/data/db.sqlite3` for SQLite while the vault is stopped.

### Hardening the bucket

The container verifies that a downloaded backup is a parseable database dump, but it cannot prove who wrote it: anyone with write access to the bucket can place an object that looks like a valid backup. Treat the bucket as part of your trust boundary:

- Use a **dedicated access key** for this container, scoped to only its bucket/prefix (list/read/write/delete — nothing else, no other buckets).
- Keep **identity state and backups separate** if your provider allows it: `/data` sync and database backups share one remote here; distinct buckets or prefixes with separate keys limit the blast radius of a leaked key.
- Turn on **object versioning** and, where available, object lock/retention, so deleted or overwritten backups stay recoverable.
- **Encrypt at rest** (provider-side, usually the default) and consider client-side encryption if your threat model includes the storage provider.

## What's on by default

- Sign-ups are off. Temporarily set `VAULTWARDEN_SIGNUPS_ALLOWED=true` to create your account, then set it back.
- Organizations and attachments are disabled. Sends are enabled (`VAULTWARDEN_SENDS_ALLOWED=false` to turn them off).
- The web vault is included and enabled. Build with `VAULTWARDEN_WEB_VAULT=false` if you only want the API, or set `VAULTWARDEN_WEB_VAULT_ENABLED=false` at runtime to hide it without rebuilding.
- The admin panel is off. If you never set an admin token, it stays off.
- Mobile push notifications are optional: get free credentials at https://bitwarden.com/host and set `VAULTWARDEN_PUSH_ENABLED=true` plus the ID and key.

## Something not working?

- **The container exits immediately at startup** — almost always Tailscale. Check the auth key and look for `refusing to run the vault without Tailscale` in the logs. With `TAILSCALE_SERVE=true` (the default), a failed `tailscale serve` exits the same way: enable MagicDNS and HTTPS certificates in the Tailscale admin console, or set `TAILSCALE_SERVE=false` to run without the tailnet HTTPS address.
- **`/alive` returns 503** — the vault itself isn't answering, usually because the database is unreachable. Its error will be in the container logs.
- **`db backup: ... failed; continuing`** — nothing to do. The backup was skipped and everything else keeps running.

## Building it yourself

See [CONTRIBUTING.md](CONTRIBUTING.md).
