# Development

This repository has two parts: a container image (`Containerfile`) and a small
Rust program (`supervisor/`) that acts as the container's init process.

## What you need

- [Podman](https://podman.io/) or Docker, to build and run the image.
- Rust `1.100` for the supervisor (CI pins `1.100.0`).
- A Tailscale account for end-to-end testing.

## Build the image

```sh
podman build --format docker -t vaultwarden-hummingbird:local .
```

Do not skip `--format docker`. The image declares a native health check, and
Podman's default OCI format silently drops that field. Without the flag,
everything looks fine and the health check simply does not work.

The image labels default to `unknown`/`dev`. CI and releases pass `GIT_SHA`,
`BUILD_DATE`, and `IMAGE_VERSION` so `podman inspect` records the source
revision and release instead of the Hummingbird base values.

Run what you built:

```sh
cp .env.example .env    # fill in the auth key and domain
podman compose up -d    # or docker compose
curl -i http://127.0.0.1:8080/alive
```

`.env` is gitignored. It is mounted at `/state/.env`; the supervisor refuses a
dotenv file outside `/state` or inside the tailscaled-writable subtree.

## Supervisor checks

```sh
cd supervisor
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --locked
cargo build --locked --all-targets
cargo build --release --locked   # pre-tag check
```

CI (`supervisor.yml`) runs the same lint, test, debug-build, and rustdoc
gates. Keep `--locked`; the lockfile is committed on purpose, and a drifted one
should fail the build.

The extra static checks run without global installs:

```sh
scripts/verify-pins.sh    # image digests, artifact checksums, action SHAs
scripts/lint-extra.sh     # actionlint, shellcheck, hadolint (pinned downloads)
```

## Repository layout

```text
Containerfile      image: fetch -> supervisor -> vaultwarden -> runtime
compose.yaml       local runner (Podman/Docker Compose)
.env.example       user-facing configuration template (strict: 3 prefixes)
scripts/           update-pins.sh, smoke-image.sh, prune-image-versions.sh,
                   lint-extra.sh, verify-pins.sh
.github/workflows/ supervisor.yml (lint/test/build/doc), image.yml (build +
                   entrypoint smoke), lint-extra.yml (static checks + audit),
                   pins.yml (digest recheck), publish.yml (release images),
                   prune.yml (retention)
supervisor/        the Rust crate
docs/              user, operator, and developer guides
```

## Supervisor source map

```text
supervisor/src/
├── main.rs        startup and the --healthcheck / probe modes
├── boot.rs        the boot phase machine
├── config/        dotenv + environment -> validated Config
├── s3/            transport policy + put/get/head/list/delete client
├── util/          logging, bounded waits, atomic writes, hashing
└── runtime/
    ├── process/   spawning, reaping, signals, the vault watch loop
    ├── services/  tailscaled and vaultwarden
    ├── gate/      the public /alive gate
    ├── backup/    SQLite dump/restore to S3
    ├── sync/      pull, push, tombstones, GC, cache
    └── migrate.rs one-time old-layout move
```

## House rules

- **When in doubt, refuse.** If Tailscale cannot start, the container does not
  run the vault. Restore only into a database proven empty. A lost exit status
  is a failure. Being down beats being quietly compromised or corrupted.
- **Secrets stay out of sight.** No credentials on command lines or in logs.
  Keys go into `0600` files, a `0700` supervisor-only directory, or environment
  variables that are cleaned up afterwards.
- **Nothing hangs.** Every external call has a timeout, every long-running
  feature has a run budget, and every parser has a size cap. Bounds are named
  `const`s near the code they guard.
- **Tests share one process.** Do not touch the process environment in tests,
  and make temp paths unique. The existing helpers show the pattern.
- **Docs are part of the change.** Modules and items carry rustdoc that states
  the contract, not the syntax. User-visible behavior updates the README or
  `docs/` in the same change.

## Testing the image

The fail-closed paths need no credentials and are worth exercising whenever you
touch boot or config:

```sh
scripts/smoke-image.sh                    # defaults to vaultwarden-hummingbird:local
```

It runs the image networkless and asserts: non-root user with an exec health
check, the one-shot health check refusal, the missing-authkey refusal, a bare
upstream key in the dotenv file, an unknown supervisor key, a relative
`TAILSCALE_STATE_FILE`, the Tailscale fail-closed chain, the TUN capability
path on a rootful host, and a restart after tailscaled leaves a `0600` file in
`/state/tailscale`.

A manual health check:

```sh
podman healthcheck run <container>   # exit 0 means healthy
```

## Version pins

Renovate bumps the upstream versions and runs `scripts/update-pins.sh` to
refresh checksums. Never hand-edit a digest. If you bump a version yourself,
run the script. CI recomputes the pins on every Containerfile change and
weekly, so a missing or stale digest is a red build.

The base images are digest-pinned. Renovate's Dockerfile manager owns those
`ARG`s and opens digest-update PRs when Red Hat moves the floating tags.

The syft pin in `publish.yml` is manual; the Pins workflow re-downloads it, so
a stale or replaced artifact is a red build. Bump the URL and its checksum
together.

## Pull requests

1. Fork and make a branch.
2. Run the checks above.
3. If you touched the Containerfile or image wiring, build and smoke-test
   locally before merging.
4. If you edited version pins, keep the `ARG` lines byte-for-byte as they were
   (Renovate finds them with regexes) and run `scripts/update-pins.sh`.
5. If user-visible behavior changed, update the README or `docs/` in the same
   PR.
6. Open the PR with a short note on what changed and why.

Found a bug? Open an issue with what you ran (commands and settings, secrets
removed), the relevant container logs, and where it happened: architecture,
Podman or Docker version, and the platform if it is a PaaS.
