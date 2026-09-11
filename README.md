# vaultwarden-hummingbird

Your own password vault, private and reachable only from your devices.

This image bundles [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (a lightweight, Bitwarden-compatible server) with [Tailscale](https://tailscale.com), on top of Red Hat's minimal [Hummingbird](https://images.redhat.com/) images. Everything inside comes from an official source and is checked against a checksum before it runs. The container runs as a non-root user, with no shell and no package manager. If someone breaks in, there's almost nothing for them to work with.

## How it works

The vault never faces the network. Inside the container it binds to loopback, and that's where it stays.

The port you publish (8080 by default) does one job: it answers `/alive` with 200 when the vault is up and 503 when it isn't. Anything else gets a 403.

Tailscale is the only way in. It publishes the vault at `https://<hostname>.<tailnet>.ts.net`, so only devices on your tailnet can reach it. No TUN device or special privileges needed.

One consequence of that design: the vault only runs if Tailscale does. The container refuses to start without either `TAILSCALE_AUTHKEY` or S3 state sync (`SUPERVISOR_S3_*`). With sync configured, a restored `tailscaled.state` is the machine's identity, so the key isn't needed or spent on redeploys. And if Tailscale dies later, the container shuts down rather than run a vault nobody can reach. Your orchestrator will restart it; a short outage beats a silent one.

## Quick start

Pull the image (amd64 and arm64):

```sh
podman pull ghcr.io/edgarcnp/vaultwarden-hummingbird:latest
```

Run it, then open the web vault at the `*.ts.net` address:

```sh
podman run --rm -p 127.0.0.1:8080:8080 \
  -e TAILSCALE_AUTHKEY=tskey-... \
  -e VAULTWARDEN_DOMAIN=https://vaultwarden.example.com \
  ghcr.io/edgarcnp/vaultwarden-hummingbird:latest

curl -i http://127.0.0.1:8080/alive
```

New images come with each release, and `:latest` only moves on your machine when you pull again. One heads-up: the first release creates the GitHub package as private. Flip it to public once in the repo's package settings if you want anyone to pull it; from then on it stays public.

## Configuration

One file runs the whole thing. Copy [`.env.example`](.env.example) to `.env`, fill in what it asks for, and hand it to the container: mount it (compose does this for you), pass it with `--env-file`, or paste the values into your platform's environment settings.

The keys come in three groups:

- `TAILSCALE_*` — how the container joins your tailnet: hostname, auth key, and friends.
- `SUPERVISOR_*` — the optional extras below: state sync, backups.
- `VAULTWARDEN_*` — vaultwarden's own settings, just with a prefix. `VAULTWARDEN_DATABASE_URL` becomes `DATABASE_URL` inside. Vaultwarden's [`.env.template`](https://github.com/dani-garcia/vaultwarden/blob/1.37.2/.env.template) lists everything it understands.

The file is strict on purpose. Only those three prefixes are accepted, and anything else (a typo, or a bare name like `DATABASE_URL`) stops the boot and names the offending keys. A misconfigured vault should never start quietly. Coming from an older image? Prefix every bare key with `VAULTWARDEN_`, and rename `VAULTWARDEN_ROCKET_PORT`/`ROCKET_PORT` to `VAULTWARDEN_PORT`. The port has one spelling now.

If a key is set both in the file and on the container, the container wins. An empty value counts as unset. And the vault's environment is default-deny: on the container env, only `VAULTWARDEN_`-prefixed keys reach the vault.

### Tailscale

- After connecting, the container points `tailscale serve` at the vault, which gives you a working HTTPS address on your tailnet. Set `TAILSCALE_SERVE=false` to skip it. This needs MagicDNS and HTTPS certificates turned on for your tailnet.
- You can also advertise the vault as a Tailscale Service with `TAILSCALE_SERVICE=vaultwarden`. That needs a tag-based auth key, the Service defined on the [Services page](https://console.tailscale.com/admin/services), and approval (or an `autoApprovers.services` rule in your policy).
- By default Tailscale runs without kernel privileges, which works on most hosting platforms. On your own machine, `TAILSCALE_USERSPACE=false` switches to TUN mode. Slightly faster, but it wants the `NET_ADMIN` capability and `/dev/net/tun`.
- `TAILSCALE_HOSTNAME` renames the node.

## Surviving redeploys

On platforms without persistent volumes, the container's `/data` is wiped on every redeploy. Since that's where Tailscale keeps the machine's identity, every redeploy means a brand-new tailnet node and every device logged out. If that's your situation, let the container save those identity files to an S3-compatible bucket (Cloudflare R2 works well):

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
# SUPERVISOR_S3_SYNC_INTERVAL=3600
```

The container loads them at startup and saves them periodically and on shutdown. Only files that actually changed get uploaded, so a quiet node costs one bucket listing, not a round of uploads. Already mounting a real volume at `/data`? Skip this entirely. Either way, keep the bucket private (it holds secrets) and run just one container against it.

Rather stay fully ephemeral? Set `TAILSCALE_STATE_FILE=mem:` and use an `ephemeral=true` auth key. The container then registers as a fresh node on every boot and devices re-login. Vaultwarden refuses to boot on a non-persistent `/data` as well; `VAULTWARDEN_I_REALLY_WANT_VOLATILE_STORAGE=true` tells it you know.

## Backing up your vault

The vault's database is a single SQLite file on the data volume (`/data/db.sqlite3`). It's always awake, and there's no external database to set up. With an S3-compatible bucket (Cloudflare R2 works well), the container can back it up on a schedule:

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_DB_BACKUP=true
# SUPERVISOR_DB_BACKUP_INTERVAL=21600   # seconds; default is 6h
# SUPERVISOR_DB_BACKUP_KEEP=3           # how many backups to keep
```

Worth knowing:

- Backups never pause the vault or lock anything. SQLite copies itself cleanly (`VACUUM INTO`), even while the vault is writing.
- Each backup lands under `db/` with a timestamp in its name, and the oldest ones get deleted to respect `KEEP`. If the database hasn't changed since the newest backup, the upload is skipped entirely. If the container dies mid-backup, you lose one backup; you never gain a broken one.
- Set `SUPERVISOR_DB_BACKUP_RESTORE=true` and the container loads the newest backup at boot, but only into a database it can prove is empty. If it can't tell, it does nothing rather than guess. It never overwrites existing data.
- Prefer to restore by hand? Stop the vault and replace `/data/db.sqlite3` with the dump file.

### Hardening the bucket

The container checks that a downloaded backup is a parseable database dump, but it can't prove who wrote it. Anyone with write access to the bucket could plant an object that looks like a valid backup. Treat the bucket as part of your trust boundary:

- Use a **dedicated access key** for this container, scoped to its bucket/prefix only (list/read/write/delete, nothing else, no other buckets).
- Keep **identity state and backups separate** if your provider allows it. They share one remote here; distinct buckets or prefixes with separate keys limit the blast radius of a leaked key.
- Turn on **object versioning** and, where available, object lock/retention, so deleted or overwritten backups stay recoverable.
- **Encrypt at rest** (provider-side, usually the default), and consider client-side encryption if your threat model includes the storage provider.

## What's on by default

- Sign-ups are open. Set `VAULTWARDEN_SIGNUPS_ALLOWED=false` once your accounts exist.
- Attachment uploads are off. Sends are on (`VAULTWARDEN_SENDS_ALLOWED=false` turns them off).
- The web vault is included and enabled. Build with `VAULTWARDEN_WEB_VAULT=false` if you only want the API, or set `VAULTWARDEN_WEB_VAULT_ENABLED=false` at runtime to hide it without rebuilding.
- The admin panel is off, and stays off unless you set an admin token.
- Mobile push notifications are optional: grab free credentials at https://bitwarden.com/host, then set `VAULTWARDEN_PUSH_ENABLED=true` plus the ID and key.

## Something not working?

- **The container exits right away at startup.** Almost always Tailscale. Check the auth key and look for `refusing to run the vault without Tailscale` in the logs. With `TAILSCALE_SERVE=true` (the default), a failed `tailscale serve` exits the same way: enable MagicDNS and HTTPS certificates in the Tailscale admin console, or set `TAILSCALE_SERVE=false` to run without the tailnet HTTPS address.
- **`/alive` returns 503.** The vault itself isn't answering, usually because the database is unreachable. Its error will be in the container logs.
- **`db backup: ... skipped/failed`.** That cycle didn't run; the next one fires automatically at the configured interval, and nothing you already have is touched. The message names the cause and what to check: S3 errors point at the `SUPERVISOR_S3_*` settings, dump failures at free space on `/data`. The one needing a decision is `refusing to shadow it`: the bucket holds a newer backup than this database, and its message says how to proceed.

## Building it yourself

See [CONTRIBUTING.md](CONTRIBUTING.md). If you change how the container behaves, that's also where you'll find how this README is kept in sync.
