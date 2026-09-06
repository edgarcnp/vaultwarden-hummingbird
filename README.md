# vaultwarden-hummingbird

Hardened container image: [Vaultwarden](https://github.com/dani-garcia/vaultwarden) + [Tailscale](https://tailscale.com) on Red Hat Hummingbird images ([images.redhat.com](https://images.redhat.com/)). Built from official, checksum-pinned sources. Runs as non-root uid 65532, no shell, no package manager.

## Build

```sh
podman build -t vaultwarden-hummingbird:local .   # or docker

# options (build args)
WEB_VAULT=true         # include web vault (default: API-only)
DB=postgresql          # postgresql | sqlite | mysql, comma list ok
```

## Run

```sh
# quick check
podman run --rm -p 127.0.0.1:8080:8080 vaultwarden-hummingbird:local
curl -i http://127.0.0.1:8080/alive

# with Tailscale
podman run --rm -p 127.0.0.1:8080:8080 \
  -e TS_AUTHKEY=tskey-... \
  -e DATABASE_URL=postgresql://... \
  -e DOMAIN=https://vaultwarden.example.com \
  vaultwarden-hummingbird:local

# or compose
cp .env.example .env   # fill in, keep out of git
docker compose up -d
```

Port: 8080 (`PORT` from the platform wins, else `ROCKET_PORT`).

## Configuration

One file: `.env` (from `.env.example`). Keys are plain vaultwarden env names — full list in vaultwarden's [`.env.template`](https://github.com/dani-garcia/vaultwarden/blob/1.37.2/.env.template).

Supply it via the compose default (mount + `SUPERVISOR_ENV_FILE`), container env (`--env-file`), or a PaaS dashboard. In supervisor mode, `TS_*`/`SUPERVISOR_*` keys stay with PID 1 — never in `docker inspect`.

## Tailscale

- `tailscaled` runs in userspace networking (no TUN, no caps). `TS_USERSPACE=false` for TUN mode.
- Inbound access via `tailscale serve` (automatic after `up`; `TS_SERVE=false` to disable) → `https://<hostname>.<tailnet>.ts.net`. Needs MagicDNS + HTTPS certs on the tailnet.
- Bad/missing `TS_AUTHKEY` is non-fatal: the vault runs without Tailscale.
- Knobs: `TS_HOSTNAME`, `TS_SERVE`, `TS_USERSPACE`, `TS_SOCKET`, `TS_STATE_FILE`.

## S3 state sync (volume-less hosts)

Without a persistent volume, `/data` is wiped on redeploy → new tailnet node, clients logged out. The supervisor can sync the identity files to an S3-compatible bucket (e.g. Cloudflare R2) via rclone:

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
# SUPERVISOR_S3_SYNC_INTERVAL=3600
```

Pull at boot, push on a cadence and at shutdown. Failures are non-fatal. Restored state reconnects without `TS_AUTHKEY`. One container per bucket/path. With a real volume on `/data`, skip this and set `I_REALLY_WANT_VOLATILE_STORAGE=false`.

Ephemeral alternative: `TS_STATE_FILE=mem:` + an `ephemeral=true` authkey — fresh registration each boot.

## DB keepalive (idle-suspending database hosts)

Some managed Postgres free tiers suspend or power off an idle database; the next vault request then stalls until it wakes. The supervisor can run a periodic `SELECT 1` against `DATABASE_URL`:

```sh
SUPERVISOR_DB_KEEPALIVE=300   # seconds between pings; 0 or unset = off
```

Failures are non-fatal (logged only on state change). Postgres URLs only — the supervisor speaks the postgres wire protocol; sqlite/mysql DBs skip it.

## Defaults (overridable via any config path)

- `SIGNUPS_ALLOWED=false` — flip to `true` to create your account, then flip back
- No orgs, no attachments; Sends allowed (`SENDS_ALLOWED=false` to disable)
- Web vault off by default — official Bitwarden apps talk to the API directly
- Admin panel disabled (no `ADMIN_TOKEN`)
- Optional mobile push: `PUSH_ENABLED=true` + `PUSH_INSTALLATION_ID`/`PUSH_INSTALLATION_KEY` (free from https://bitwarden.com/host)

## Files

- `Dockerfile` — 4 stages: fetch & verify → supervisor → vaultwarden → minimal runtime
- `supervisor/` — Rust PID 1: tailscaled + `up`/`serve` + vaultwarden, with clean SIGTERM teardown
- `.env.example` — the one config file; `docker-compose.yaml` — local runner
- `render.yaml` — optional Render blueprint
