# vaultwarden-hummingbird

Hardened container image: [Vaultwarden](https://github.com/dani-garcia/vaultwarden) + [Tailscale](https://tailscale.com) on Red Hat Hummingbird images ([images.redhat.com](https://images.redhat.com/)). Built from official, checksum-pinned sources. Runs as non-root uid 65532, no shell, no package manager.

## Pre-built image

CI publishes a multi-arch image (amd64 + arm64) on every `v*` tag, plus a
weekly rebuild of the same pins so base-image CVE patches keep flowing:

```sh
podman run --rm -p 127.0.0.1:8080:8080 \
  ghcr.io/edgarcnp/vaultwarden-hummingbird:latest
```

Notes:

- The weekly cron refreshes `:latest`, but consumers must still re-pull to
  pick it up.
- First publish creates the ghcr package as **private**; flip it to public
  once (repo → Packages → package settings) so anonymous pulls work.

## Build

```sh
# --format docker: HEALTHCHECK is an OCI-invalid field; podman's default
# OCI image format silently drops it (verified on podman 5.8).
podman build --format docker -t vaultwarden-hummingbird:local .

# Build args (VAULTWARDEN_WEB_VAULT, DB, and the version pins) are
# documented in the Containerfile itself; pass them via --build-arg, e.g.
# an API-only image:
podman build --format docker --build-arg VAULTWARDEN_WEB_VAULT=false \
  -t vaultwarden-hummingbird:api .
```

## Run

```sh
# quick check (fails without TAILSCALE_AUTHKEY — see Tailscale below)
podman run --rm -p 127.0.0.1:8080:8080 vaultwarden-hummingbird:local
curl -i http://127.0.0.1:8080/alive

# with Tailscale
podman run --rm -p 127.0.0.1:8080:8080 \
  -e TAILSCALE_AUTHKEY=tskey-... \
  -e VAULTWARDEN_DATABASE_URL=postgresql://... \
  -e VAULTWARDEN_DOMAIN=https://vaultwarden.example.com \
  vaultwarden-hummingbird:local

# or compose
cp .env.example .env   # fill in, keep out of git
podman compose up -d   # or docker compose
```

Port: 8080 (`VAULTWARDEN_PORT` from the platform wins, else
`VAULTWARDEN_ROCKET_PORT`). Only `/alive` is answered on the exposed port
— a status-only verdict: 200 while vaultwarden serves, 503 when it does
not; every other path → 403, and no vault response data is forwarded. The
Bitwarden API itself is loopback-only, reachable solely via `tailscale
serve` over the tailnet.

## Configuration

One file: `.env` (from `.env.example`). Three namespaces:

- `SUPERVISOR_*` — supervisor-initiated features: S3 state sync, DB backup, DB keepalive
- `TAILSCALE_*` — the Tailscale subsystem (PID 1 only)
- `VAULTWARDEN_*` — vaultwarden config; in supervisor mode the prefix is stripped and the child receives the plain upstream env names (full list in vaultwarden's [`.env.template`](https://github.com/dani-garcia/vaultwarden/blob/1.37.2/.env.template))

Build args (`VAULTWARDEN_WEB_VAULT`, `DB`, and the version pins) are
documented in the Containerfile itself (`BUILD KNOBS` / `UPSTREAM PINS`) —
override with `--build-arg`; compose passes `VAULTWARDEN_WEB_VAULT` through
from the environment when set. Changing one requires a rebuild.

Supply it via the compose default (mount + `SUPERVISOR_ENV_FILE`), container env (`--env-file`), or a PaaS dashboard. In supervisor mode, `TAILSCALE_*`/`SUPERVISOR_*` keys stay with PID 1 — never in `docker inspect`.

## Tailscale

- `tailscaled` runs in userspace networking (no TUN, no caps). `TAILSCALE_USERSPACE=false` for TUN mode.
- Inbound access via `tailscale serve` (automatic after `up`; `TAILSCALE_SERVE=false` to disable) → `https://<hostname>.<tailnet>.ts.net`. Needs MagicDNS + HTTPS certs on the tailnet.
- Optional Tailscale **Service** advertisement (`TAILSCALE_SERVICE=vaultwarden`): the node advertises itself as a host of `svc:vaultwarden` (`tailscale serve --service`). Requires a tag-based authkey, the Service defined on the admin console [Services page](https://console.tailscale.com/admin/services) (endpoint `tcp:443`), and admin approval or an `autoApprovers.services` policy.
- `TAILSCALE_AUTHKEY` is **required**: a missing key or any boot-time Tailscale failure (daemon won't start, `up` fails/times out) exits 1 — the orchestrator's restart policy retries. A mid-run tailscaled death tears the vault down too (exit 1).
- Knobs: `TAILSCALE_HOSTNAME`, `TAILSCALE_SERVE`, `TAILSCALE_SERVICE`, `TAILSCALE_USERSPACE`, `TAILSCALE_SOCKET`, `TAILSCALE_STATE_FILE`.

## S3 state sync (volume-less hosts)

Without a persistent volume, `/data` is wiped on redeploy → new tailnet node, clients logged out. The supervisor can sync the identity files to an S3-compatible bucket (e.g. Cloudflare R2) via rclone:

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
# SUPERVISOR_S3_SYNC_INTERVAL=3600
```

Pull at boot, push on a cadence and at shutdown. Failures are non-fatal. Restored state reconnects without `TAILSCALE_AUTHKEY`. One container per bucket/path. With a real volume on `/data`, skip this and set `I_REALLY_WANT_VOLATILE_STORAGE=false`.

Ephemeral alternative: `TAILSCALE_STATE_FILE=mem:` + an `ephemeral=true` authkey — fresh registration each boot.

## DB keepalive (idle-suspending database hosts)

Some managed Postgres free tiers suspend or power off an idle database; the next vault request then stalls until it wakes. The supervisor can run a periodic `SELECT 1` against `VAULTWARDEN_DATABASE_URL`:

```sh
# seconds between pings; 0 or unset = off
SUPERVISOR_DB_KEEPALIVE=300
```

Failures are non-fatal (logged only on state change). Postgres URLs only — the supervisor speaks the postgres wire protocol; sqlite/mysql DBs skip it.

## DB backup to S3

The supervisor can push consistent, periodic dumps of the vault's database to the same S3-compatible bucket used by the state sync, under `<SUPERVISOR_S3_REMOTE>/db`:

```sh
# backup rides the state-sync S3 credentials
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_DB_BACKUP=true
# seconds (default 12h)
# SUPERVISOR_DB_BACKUP_INTERVAL=43200
# dumps kept per backend
# SUPERVISOR_DB_BACKUP_KEEP=3
```

- **Consistency** — no downtime, no locks on the vault: postgres via `pg_dump` (MVCC snapshot, custom format), mysql via `mariadb-dump --single-transaction` (InnoDB snapshot), sqlite via `VACUUM INTO`. The dump/restore client tools ship in the image, extracted from the official Red Hat `hi/postgresql`/`hi/mariadb` images; sqlite is handled in-process.
- **Safety** — dumps are staged on the data volume, uploaded to a *new* timestamped object (`db/<backend>-<timestamp>.<ext>`), and only then are the oldest objects pruned to keep-N. A kill at any point costs a missed backup, never a corrupt one. Nothing in the backup path writes to the live database.
- **Restore (opt-in, off by default)** — `SUPERVISOR_DB_BACKUP_RESTORE=true`: at boot, if the database is *verifiably empty* (sqlite file absent; pg/mysql `users`-table check), the newest dump is imported (integrity-checked first). Ambiguity — e.g. the DB is unreachable — fails closed: the vault starts on the empty DB instead of guessing.
- **Manual restore** — `pg_restore --no-owner --no-privileges --dbname=<db> <dump>`, `mariadb --database=<db> --execute="source <dump>"`, or (sqlite) stop the vault and replace `/data/db.sqlite3`. **Never auto-restore onto a non-empty DB by hand.**
- Same rules as the state sync: failures are non-fatal, one container per bucket/path, keep the bucket private (dump objects contain vault metadata).

## Defaults (overridable via any config path)

- `VAULTWARDEN_SIGNUPS_ALLOWED=false` — flip to `true` to create your account, then flip back
- No orgs, no attachments; Sends allowed (`VAULTWARDEN_SENDS_ALLOWED=false` to disable)
- Web vault on by default (`VAULTWARDEN_WEB_VAULT=false` for API-only; UI files are baked at build)
- Admin panel disabled (no `VAULTWARDEN_ADMIN_TOKEN`)
- Optional mobile push: `VAULTWARDEN_PUSH_ENABLED=true` + `VAULTWARDEN_PUSH_INSTALLATION_ID`/`VAULTWARDEN_PUSH_INSTALLATION_KEY` (free from https://bitwarden.com/host)

## Files

- `Containerfile` — 4 stages: fetch & verify → supervisor → vaultwarden → minimal runtime (+ DB client tools extracted from the official Red Hat client images for the backup feature)
- `supervisor/` — Rust PID 1: exposed-port gatekeeper (`/alive` only, doubles as the container healthcheck via `--healthcheck`), tailscaled + `up`/`serve` + loopback-only vaultwarden, S3 state sync + DB backup/restore, with clean SIGTERM teardown
- `.env.example` — the one config file; `compose.yaml` — local runner (podman/docker compose)
- `.github/workflows/publish.yml` — multi-arch build + ghcr publish (tag push, manual, weekly cron)
