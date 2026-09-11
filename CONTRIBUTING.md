# Contributing

Thanks for helping out. This project is two parts: a container image (`Containerfile`) and a small Rust program (`supervisor/`) that acts as the container's init process. Most work will touch one or the other.

## What you need

- [Podman](https://podman.io/) or Docker, to build and run the image.
- A recent stable Rust toolchain, to work on the supervisor.
- A Tailscale account if you want to test the running container end to end.

## Build and run the image

```sh
podman build --format docker -t vaultwarden-hummingbird:local .
```

The `--format docker` flag matters: the image declares a native HEALTHCHECK, and podman's default OCI format silently drops that field when it builds. If you skip the flag, everything looks fine and your health checks won't work.

To run what you built:

```sh
cp .env.example .env    # fill in the auth key, database URL, and domain
podman compose up -d    # or docker compose
curl -i http://127.0.0.1:8080/alive
```

`.env` is gitignored, so it won't leak — just don't move it elsewhere.

### Build-time options

`--build-arg` lets you change what's baked into the image (all documented in the Containerfile):

- `VAULTWARDEN_WEB_VAULT=false` builds an API-only image without the web UI.
- The database is SQLite on the data volume — there is no DB backend knob.
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

CI runs exactly those checks, so if they pass locally, CI will pass. Keep the `--locked` flag — the lockfile is committed on purpose.

### Where things live

```
supervisor/src/
├── main.rs        startup and the --healthcheck mode
├── config/        reading .env and environment into a Config
└── runtime/
    ├── process/   starting and stopping child programs
    ├── services/  tailscaled and vaultwarden themselves
    ├── gate/      the public-port health endpoint
    ├── backup/    sqlite backup and restore to S3
    └── sync/      saving /data to S3 and back
```

### House rules

These shape most decisions in the codebase, so worth knowing before you start:

- **When in doubt, refuse.** If Tailscale can't start, the container doesn't run the vault. Restore only into a database we're sure is empty. If a process's exit status is lost, treat it as a failure. Being down beats being quietly compromised or corrupted.
- **Secrets stay out of sight.** No credentials on command lines or in log lines. Keys go into 0600 files or environment variables that are cleaned up afterwards.
- **Nothing hangs.** Every external call — Tailscale, S3, database — has a timeout.
- **Tests share one process.** Don't touch the process environment in tests and make temp paths unique; existing test helpers show the pattern.

## Testing the whole image

A full build gives you a container you can exercise for real:

```sh
podman run --rm -it -p 127.0.0.1:8080:8080 \
  -e TAILSCALE_AUTHKEY=tskey-... \
  -e VAULTWARDEN_DOMAIN=https://vaultwarden.example.com \
  vaultwarden-hummingbird:local

podman healthcheck run <container>   # exit 0 means healthy
```

## Opening a pull request

1. Fork and make a branch.
2. Run the checks from the section above; build the image if you touched it.
3. If you edited the version pins in the Containerfile, keep those `ARG` lines byte-for-byte as they were — Renovate finds them with regexes — and run `scripts/update-pins.sh` so the digests match.
4. Open the PR with a short description of what changed and why.

## Found a bug?

Open an issue with what you ran (commands and settings, secrets removed), the relevant container logs, and where it happened (architecture, podman or Docker version, and the platform if it's a PaaS).
