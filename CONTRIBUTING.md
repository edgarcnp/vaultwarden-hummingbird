# Contributing

Thanks for helping out.

This project has two parts: a container image (`Containerfile`) and a small Rust program (`supervisor/`) that acts as the container's init process. Most work touches one or the other.

One thing before you dive in: [README.md](README.md) is written for **users**. It describes how the container behaves, not how it's built. Keep contributor material here, and if your change alters user-visible behavior, update the README in the same PR.

## What you need

- [Podman](https://podman.io/) or Docker, to build and run the image.
- A recent stable Rust toolchain, for the supervisor.
- A Tailscale account, if you want to test the running container end to end.

## Repository layout

```
Containerfile      the image: fetch -> supervisor -> vaultwarden -> runtime
compose.yaml       local runner (podman/docker compose)
.env.example       the user-facing config template (strict: 3 key prefixes)
scripts/           update-pins.sh — recompute checksum ARGs after a version bump
.github/workflows/ supervisor.yml (lint/test/build), pins.yml (CI digest recheck),
                   publish.yml (release images)
supervisor/        the Rust crate — module map below
```

## Building the image

```sh
podman build --format docker -t vaultwarden-hummingbird:local .
```

Don't skip `--format docker`. The image declares a native HEALTHCHECK, and podman's default OCI format silently drops that field when it builds. Without the flag everything looks fine and your health checks just don't work.

To run what you built:

```sh
cp .env.example .env    # fill in the auth key, database URL, and domain
podman compose up -d    # or docker compose
curl -i http://127.0.0.1:8080/alive
```

`.env` is gitignored, so it won't leak. Just don't move it elsewhere.

### Build-time options

`--build-arg` changes what gets baked into the image. Everything is documented in the Containerfile:

- `VAULTWARDEN_WEB_VAULT=false` builds an API-only image, no web UI.
- The database is SQLite on the data volume. There's no DB backend knob.
- Renovate bumps the version ARGs and runs `scripts/update-pins.sh` to refresh the checksum digests. Never hand-edit a digest: if you bump a version yourself, run the script. CI recomputes the pins on every Containerfile change (and weekly), so a missing or stale digest is a red build.

## Working on the supervisor

The supervisor is a regular Rust crate. It starts Tailscale and vaultwarden, health checks the public port, and handles the optional state sync and backups.

```sh
cd supervisor
cargo build         # quick check
cargo test --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
```

CI (`supervisor.yml`) runs exactly those checks — lint, then test, then build. If they pass locally, CI will pass. Keep the `--locked` flag: the lockfile is committed on purpose, and a drifted one should fail the build.

### Where things live

```
supervisor/src/
├── main.rs        startup and the --healthcheck mode
├── boot.rs        the boot phase machine
├── config/        reading .env and environment into a Config
├── s3/            the minimal S3 client (RemoteSpec + put/get/list/delete)
├── util/          shared helpers (logging, bounded waits, staged files)
└── runtime/
    ├── process/   starting and stopping child programs, env grants
    ├── services/  tailscaled and vaultwarden themselves
    ├── gate/      the public-port health endpoint
    ├── backup/    sqlite backup and restore to S3
    └── sync/      saving /data to S3 and back
```

### House rules

These shape most decisions in the codebase, so they're worth knowing before you start:

- **When in doubt, refuse.** If Tailscale can't start, the container doesn't run the vault. Restore only into a database we're sure is empty. If a process's exit status is lost, treat it as a failure. Being down beats being quietly compromised or corrupted.
- **Secrets stay out of sight.** No credentials on command lines or in log lines. Keys go into 0600 files or environment variables that get cleaned up afterwards.
- **Nothing hangs.** Every external call (Tailscale, S3, database) has a timeout, and every parser has a size cap. Both are named `const`s near the code they guard.
- **Tests share one process.** Don't touch the process environment in tests, and make temp paths unique. The existing test helpers show the pattern.

## Testing the whole image

A full build gives you a container you can exercise for real:

```sh
podman run --rm -it -p 127.0.0.1:8080:8080 \
  -e TAILSCALE_AUTHKEY=tskey-... \
  -e VAULTWARDEN_DOMAIN=https://vaultwarden.example.com \
  vaultwarden-hummingbird:local

podman healthcheck run <container>   # exit 0 means healthy
```

You can exercise the fail-closed paths without any credentials, and it's worth doing whenever you touch boot or config:

```sh
# no authkey, no S3: must refuse to boot, naming what's missing
podman run --rm localhost/vaultwarden-hummingbird:local

# strict dotenv: a bare upstream key must refuse, naming the key
printf 'DATABASE_URL=x\n' | podman run --rm -i \
  -e SUPERVISOR_ENV_FILE=/dev/stdin localhost/vaultwarden-hummingbird:local

# healthcheck one-shot with nothing listening: must exit non-zero
podman run --rm --entrypoint /entrypoint localhost/vaultwarden-hummingbird:local --healthcheck
```

## Releases

Cutting a release is just a tag. Push a `v*` tag (or run `publish.yml` by hand) and the workflow builds amd64 and arm64, pushes the per-arch images, then publishes the multi-arch manifest as `:<tag>` and `:latest` on `ghcr.io/edgarcnp/vaultwarden-hummingbird`, with provenance attestations. The workflow never changes versions itself. It builds whatever the Containerfile pins, so bump upstream versions first (via Renovate or `scripts/update-pins.sh`) and let CI confirm the digests before you tag.

## Opening a pull request

1. Fork and make a branch.
2. Run the checks from the sections above; build the image if you touched it.
3. If you edited the version pins in the Containerfile, keep those `ARG` lines byte-for-byte as they were (Renovate finds them with regexes) and run `scripts/update-pins.sh` so the digests match.
4. If user-visible behavior changed, update README.md in the same PR.
5. Open the PR with a short note on what changed and why.

## Found a bug?

Open an issue with what you ran (commands and settings, secrets removed), the relevant container logs, and where it happened: architecture, podman or Docker version, and the platform if it's a PaaS.
