# vaultwarden-render

Hardened container for running [Vaultwarden](https://github.com/dani-garcia/vaultwarden) on [Render](https://render.com) with embedded Tailscale — built entirely from **Red Hat Hardened (Hummingbird) images** ([images.redhat.com](https://images.redhat.com/)):

- **builds**: `hi/rust:1-builder` (distro Rust 1.97.1 — exactly upstream's pinned toolchain)
- **runtime**: `hi/core-runtime:latest` (no package manager, minimal lib set, non-root uid 65532)

Not a fork: vaultwarden is compiled from the official `1.37.2` source tarball and Tailscale comes from an official checksum-verified release tarball. Upstream updates = bump the pinned versions and rebuild.

## Architecture

```
hi/rust:1-builder ── fetch stage ────── vw + tailscale tarballs (sha256-verified)
                                        + web-vault tarball when WEB_VAULT=true
hi/rust:1-builder ── supervisor ─────── Rust PID 1 (supervisor/), glibc lockstep with runtime
hi/rust:1-builder ── vw-build ───────── vaultwarden 1.37.2 from source
                                        (sqlite static, libpq bundled/static, mariadb shared)
hi/core-runtime:latest ── runtime ───── /entrypoint (PID 1) + /vaultwarden
                                        + tailscale + the 3 shared libs the runtime lacks
```

API-only by default: no web vault is shipped unless you opt in — clients are the official Bitwarden apps talking to the API directly.

The supervisor (PID 1) starts `tailscaled` in userspace networking (no TUN device on PaaS), runs a bounded `tailscale up` (invalid keys fail fast, hangs are killed after 90s), configures `tailscale serve` for inbound tailnet access, then runs vaultwarden in the foreground with SIGTERM forwarding for graceful Render redeploys. Missing/invalid `TS_AUTHKEY` is non-fatal.

## Files

- `Dockerfile` — the four-stage build above
- `supervisor/` — Rust PID 1 (modular: `config/` [env, dotenv], `proc/` [tailscale, vaultwarden, signals], `util/` [log, net]; mod.rs files are declaration/re-export hubs), built with `lto=fat`, `codegen-units=1`, `panic=abort`
- `.env.example` — the ONE universal config file (dotenv)
- `docker-compose.yaml` — universal local runner (supervisor-owned `.env` mode wired by default)
- `render.yaml` — Render-only wiring (plan, health check, build-from-Dockerfile, deploy-time secrets)
- `CONFIG.md` — full vaultwarden config key reference (1.37.2) + precedence/deployment notes

## Configuration (one file, three ways in)

One canonical file — `.env` (from `.env.example`), plain dotenv format, no TOML, no YAML:

| How | Where | Mechanics |
|---|---|---|
| **Supervisor-owned** (self-host, compose default) | `.env` mounted read-only, `SUPERVISOR_ENV_FILE=/config/.env` | supervisor reads it and distributes **localized**: `TS_*`/`SUPERVISOR_*` keys stay with PID 1 (never in `podman inspect`, never in the vaultwarden process); all other keys become the child's env |
| **Container env** | `podman run --env-file .env` / compose `env_file:` | standard env vars |
| **Render dashboard** | `render.yaml` prompts | same env vars; `sync: false` prompts for secrets at deploy time |

Precedence: **`PORT`/`TS_*`/`SUPERVISOR_*` process env > `.env` file > image-baked defaults** for the supervisor's own knobs; for vaultwarden keys the file beats container env (that's what makes the image-baked posture overridable from `.env`). Keys are plain upstream env names (`DATABASE_URL`, `DOMAIN`, … — any of the 139 keys in CONFIG.md), so new upstream keys work without supervisor changes.

The localization matters for secrets: `TS_AUTHKEY` in the mounted `.env` never enters container env, so it's invisible to `podman inspect`/`docker inspect` and never reaches the vaultwarden process. Not a security boundary (same-UID processes can read `/proc/<pid>/environ`) — it's leakage hygiene. Platform plumbing like Render's `PORT` and `I_REALLY_WANT_VOLATILE_STORAGE` always wins.

Personal-posture defaults (`SIGNUPS_ALLOWED=false`, `ORG_CREATION_USERS=none`, attachment limits `0`, `WEB_VAULT_ENABLED` per build arg) are baked into the image as env defaults — overridable via any of the three ways.

## Build & run locally

```sh
docker build -t vaultwarden-ts .        # or podman build

# include the web vault (upstream-style toggle; default is API-only)
docker build --build-arg WEB_VAULT=true -t vaultwarden-ts .

# without Tailscale
docker run --rm -p 127.0.0.1:8080:8080 vaultwarden-ts
curl -i http://127.0.0.1:8080/alive

# with Tailscale + supervisor-owned .env (self-host — see docker-compose.yaml)
podman run --rm -p 127.0.0.1:8080:8080 \
  -v ./.env:/config/.env:ro \
  -e SUPERVISOR_ENV_FILE=/config/.env \
  vaultwarden-ts

# with Tailscale via plain env (auth key or OAuth client secret — see below)
docker run --rm -p 127.0.0.1:8080:8080 \
  -e TS_AUTHKEY=tskey-auth-... \
  -e TS_HOSTNAME=vaultwarden \
  -e DATABASE_URL=postgresql://... \
  -e DOMAIN=https://vaultwarden.example.com \
  vaultwarden-ts
```

## Design notes (personal-use posture)

- **Web vault: build-time toggle** — default `WEB_VAULT=false` ships an API-only image (`WEB_VAULT_ENABLED=false` baked in); the Bitwarden apps (mobile/desktop/browser extension) use the API directly and `https://<domain>/` serves nothing. Rebuild with `--build-arg WEB_VAULT=true` to include the browser vault (fetched from official `bw_web_builds`, sha256-verified). Build args are build-time: flipping needs a rebuild, not a dashboard change.
- **No attachments/Sends storage** — limits are set to `0`; use Taildrop for file transfer.
- **No organizations** — `ORG_CREATION_USERS=none` blocks org creation.
- **Admin panel disabled** — no `ADMIN_TOKEN` is set, so `/admin` is unreachable (it would be useless here anyway: panel edits persist to ephemeral `/data` and are lost on restart; all config flows from env vars).
- **Optional mobile push** — set `PUSH_ENABLED=true` plus `PUSH_INSTALLATION_ID`/`PUSH_INSTALLATION_KEY` (free from https://bitwarden.com/host) so mobile clients sync without polling.

## Deploy to Render

1. Push this repo to GitHub, then in Render: **New → Blueprint** and select the repo.
2. Fill in the prompted env vars (stored in the dashboard, never in git):
   - `DATABASE_URL` (secret) — external Postgres connection string (e.g. Neon/Supabase free tier)
   - `DOMAIN` — `https://<service>.onrender.com`
   - `TS_AUTHKEY` (secret) — Tailscale auth key **or** OAuth client secret. OAuth is preferred: it never expires (auth keys die in 90 days), and `/data` is ephemeral so the node re-authenticates on every boot. Create one in the Tailscale console (**Settings → OAuth clients**, scope `auth_keys`, with a tag like `tag:server` required) and pass it with params: `tskey-client-...?ephemeral=false&preauthorized=true`. Devices registered via OAuth are tag-owned.
3. Create your account: temporarily set `SIGNUPS_ALLOWED=true` in the dashboard (it overrides the image default), register, flip it back.
4. Attachments and Sends are off by default (image-baked limits `0` — there is no `ATTACHMENTS_ENABLED` flag upstream). File transfer happens via Taildrop between your devices, not via the vault. Organizations are disabled (`ORG_CREATION_USERS=none`, image default).

## Tailscale notes

- Render containers have no TUN device, so `tailscaled` runs with `--tun=userspace-networking` (outbound via userspace stack; no kernel TUN). `TS_USERSPACE=false` reverts to TUN mode for local Docker use.
- **Inbound access from the tailnet requires `tailscale serve`** — in userspace mode connections to the node's Tailscale IP are not delivered to local ports. The supervisor runs `tailscale serve --bg --https=443 http://127.0.0.1:$PORT` after a successful `up` (disable with `TS_SERVE=false`), giving clients `https://<hostname>.<tailnet>.ts.net` with valid certs (requires MagicDNS + HTTPS certificates enabled on the tailnet). Point your Bitwarden clients at that URL.
- **The `onrender.com` URL stays public either way** — Tailscale only adds a private path to the same instance; it does not gate the Render URL. Vaultwarden's own auth plus `SIGNUPS_ALLOWED=false` is what protects the public endpoint.
- Optional env vars: `TS_HOSTNAME` (default `vaultwarden`), `TS_SERVE` (default `true`), `TS_USERSPACE` (default `true`), `TS_SOCKET`, `TS_STATE_FILE`.

## Data & provenance

- No Render disk: the database is external (`DATABASE_URL`) and `/data` is ephemeral. That's accepted here — only Tailscale node state lives there (`I_REALLY_WANT_VOLATILE_STORAGE=true`; vaultwarden refuses volatile storage otherwise).
- Secrets are only ever provided via environment variables; nothing is hardcoded or logged.
- Build provenance: the Tailscale tarball is sha256-verified against its official release checksum; the vaultwarden source tarball and Kitware cmake are TLS-fetched from pinned tags (the Hummingbird repo has no libpq and its cmake RPM is broken — see CONFIG.md).
- Multi-arch: amd64 + arm64 (Render runs amd64).
