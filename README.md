# vaultwarden-hummingbird

Hardened container image running [Vaultwarden](https://github.com/dani-garcia/vaultwarden) with embedded [Tailscale](https://tailscale.com) — built entirely from **Red Hat Hardened (Hummingbird) images** ([images.redhat.com](https://images.redhat.com/)):

- **build**: `hi/rust:1-builder` (distro Rust, toolchain-matched to upstream's pin)
- **runtime**: `hi/core-runtime:latest` (no shell, no package manager, non-root uid 65532)

Not a fork: vaultwarden is compiled from the official source tarball and Tailscale comes from the official checksum-verified release tarball. Both are version-pinned in the `Dockerfile` — updating upstream means bumping the pins and rebuilding.

## Build

```sh
podman build -t vaultwarden-hummingbird:local .        # or docker build

# include the web vault (default is API-only)
podman build --build-arg WEB_VAULT=true -t vaultwarden-hummingbird:local .

# choose the DB backend(s) compiled into the binary (default: postgresql —
# this image's posture is an external Postgres). Comma lists work too:
# --build-arg DB="sqlite,mysql"
podman build --build-arg DB=postgresql -t vaultwarden-hummingbird:local .
```

## Run

```sh
# quick check, no Tailscale
podman run --rm -p 127.0.0.1:8080:8080 vaultwarden-hummingbird:local
curl -i http://127.0.0.1:8080/alive

# with Tailscale via plain env
podman run --rm -p 127.0.0.1:8080:8080 \
  -e TS_AUTHKEY=tskey-... \
  -e DATABASE_URL=postgresql://... \
  -e DOMAIN=https://vaultwarden.example.com \
  vaultwarden-hummingbird:local

# self-host via compose (supervisor-owned .env wired by default)
cp .env.example .env   # fill in, keep out of git
docker compose up -d   # or: podman-compose up -d
```

The vaultwarden port defaults to 8080; a platform-injected `PORT` wins, else `ROCKET_PORT` overrides.

## Configuration

One canonical file: `.env` (from `.env.example`), plain dotenv. Keys are plain upstream env names — the full list is vaultwarden's [`.env.template`](https://github.com/dani-garcia/vaultwarden/blob/1.37.2/.env.template). Unknown keys are silently ignored.

Three ways in:

| How | Mechanics |
|---|---|
| **Supervisor-owned** (recommended, compose default) | mount `.env` read-only + `SUPERVISOR_ENV_FILE=/config/.env` |
| **Container env** | `--env-file .env` / compose `env_file:` |
| **PaaS dashboard** | paste the same env vars |

Supervisor-owned mode is *localized*: `TS_*`/`SUPERVISOR_*` keys stay with PID 1 — never in `docker inspect`, never in the vaultwarden process — and everything else is forwarded to vaultwarden. This keeps `TS_AUTHKEY` out of container env (leakage hygiene, not a security boundary).

Precedence: `PORT`/`ROCKET_PORT` and `TS_*`/`SUPERVISOR_*` process env > `.env` file > code defaults (empty values are treated as unset); for vaultwarden keys the `.env` file beats container env (that's what makes the baked posture overridable). Three exceptions are hard-pinned to the child by the supervisor and can't be overridden: `ROCKET_PORT` (follows `PORT`), `ROCKET_ADDRESS` and `DATA_FOLDER` (`/data`).

## Tailscale

- `tailscaled` runs in **userspace networking** by default (works without a TUN device, e.g. on PaaS); `TS_USERSPACE=false` reverts to TUN for local use. Note: the compose file ships `cap_drop: ALL` (userspace needs no caps), so TUN mode there requires editing the compose file and granting `NET_ADMIN` + `/dev/net/tun`.
- **Inbound tailnet access requires `tailscale serve`** — the supervisor runs it after a successful `up` (disable with `TS_SERVE=false`), exposing `https://<hostname>.<tailnet>.ts.net` with valid certs (needs MagicDNS + HTTPS certificates on the tailnet). Point your Bitwarden clients there.
- Missing/invalid `TS_AUTHKEY` is non-fatal: the vault starts without Tailscale. A hung `up` is killed after 90s. The authkey is never placed on a command line — it's staged into a 0600 file (removed after `up`), keeping it out of `/proc/*/cmdline`.
- Knobs: `TS_HOSTNAME` (default `vaultwarden`), `TS_SERVE`, `TS_USERSPACE`, `TS_SOCKET`, `TS_STATE_FILE`.

## State sync (volume-less hosts)

On hosts without persistent volumes, `/data` is wiped on every restart/redeploy: the tailnet node identity (`tailscaled.state`) and vaultwarden's RSA keys (`rsa_key*`) regenerate — new node per boot, and clients get logged out. The supervisor can sync those identity files to an S3-compatible bucket (e.g. Cloudflare R2, free tier) via baked rclone:

```sh
SUPERVISOR_S3_REMOTE=r2:vw-state
SUPERVISOR_S3_ACCESS_KEY_ID=...
SUPERVISOR_S3_SECRET_ACCESS_KEY=...
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
# SUPERVISOR_S3_SYNC_INTERVAL=3600  (seconds; pushes also happen at shutdown)
```

Pull at boot, push after `up` / on a cadence / at shutdown. Failures are non-fatal (worst case: re-auth or a client re-login). Restored state means tailscaled reconnects **without `TS_AUTHKEY`** — fully self-healing redeploys. Keep the bucket private (it holds the node key + JWT signing key) and run exactly **one container per bucket/path**. With a real volume on `/data` you don't need this — and should set `I_REALLY_WANT_VOLATILE_STORAGE=false`.

Don't want a bucket? Pure-ephemeral alternative: `TS_STATE_FILE=mem:` plus an `ephemeral=true` authkey param — memory-only state, nodes auto-delete when offline; every boot is a fresh registration (no duplicate accumulation, no stable identity).

## Defaults (personal posture)

Baked into the image, overridable via any configuration path:

- `SIGNUPS_ALLOWED=false` — flip to `true` to create your account, then flip back
- No organizations (`ORG_CREATION_USERS=none`) and no attachment storage (`USER_ATTACHMENT_LIMIT=0`/`ORG_ATTACHMENT_LIMIT=0` — there is no `ATTACHMENTS_ENABLED` flag upstream); use Taildrop for file transfer. Sends are *not* disabled by default — set `SENDS_ALLOWED=false` if you don't want them.
- `WEB_VAULT_ENABLED` follows the `WEB_VAULT` build arg — default API-only: the official Bitwarden apps talk to the API directly, `https://<domain>/` serves nothing
- Admin panel disabled (no `ADMIN_TOKEN`)
- Optional mobile push: `PUSH_ENABLED=true` plus `PUSH_INSTALLATION_ID`/`PUSH_INSTALLATION_KEY` (free from https://bitwarden.com/host)

## Data & provenance

- The database is external (`DATABASE_URL`); `/data` only needs to hold Tailscale node state (`I_REALLY_WANT_VOLATILE_STORAGE=true` is baked in — vaultwarden refuses volatile storage otherwise; set it `false` when `/data` has a real volume). Note the check is opt-out: *any* value of the variable (including `false`) disables it, which is why the compose file states it explicitly for its named volume.
- Secrets are only ever provided via environment variables; nothing is hardcoded or logged.
- All fetched artifacts are checksum-pinned: Tailscale (official `.sha256`), rclone (official `SHA256SUMS`), web vault (official `sha256sums.txt`), and the vaultwarden source + CMake tarballs (sha256 digests baked as build `ARG`s — a mismatch fails the build). Base images are digest-pinned.
- Multi-arch: amd64 + arm64.

## Files

- `Dockerfile` — four-stage build: fetch & verify tarballs → Rust PID 1 supervisor → vaultwarden from source → minimal runtime
- `supervisor/` — PID 1: starts `tailscaled`, runs bounded `up`/`serve`, then vaultwarden in the foreground with SIGTERM forwarding and full teardown
- `.env.example` — the one config file; `docker-compose.yaml` — universal local runner
- `render.yaml` — optional Render blueprint
