# Vaultwarden + Tailscale on Red Hat Hummingbird. Checksum-pinned official
# sources, Rust supervisor as PID 1. Build with --format docker (or
# BUILDAH_FORMAT=docker): podman's default OCI format drops HEALTHCHECK
# (verified on podman 5.8.4).

# UPSTREAM VERSIONS — Renovate-managed: its regexes match these exact ARG
# lines, never reformat them.

ARG VW_VERSION=1.37.2
ARG WEB_VAULT_VERSION=v2026.7.0
ARG TAILSCALE_VERSION=1.102.3

# UPSTREAM CHECKSUMS — sha256 digests of the release artifacts; Renovate has
# no manager for these ARGs, so update each by hand alongside its version.

# vaultwarden source tarball; bump with VW_VERSION.
ARG VW_SHA256=d607cc00066f7ea62b27a3c198e0259955fd5591adabccb8d3414d1f3d91ecd7
# web-vault tarball; bump with WEB_VAULT_VERSION.
ARG WEB_VAULT_SHA256=002e972bf0d0487ec0324b06d916de33e29de4c29bffd92ee3b843084c300570
# per-arch tarballs; bump with TAILSCALE_VERSION.
ARG TAILSCALE_SHA256_AMD64=36ddd9b51be57ffc2990cf76323cfa13643bfbb1b8a969f6183fa164741cdef5
ARG TAILSCALE_SHA256_ARM64=a0fa1b154af8c61f862a2259f559f7396d96c0225f4a863eae2333e1546bbe25

# BASE IMAGES — float on purpose: rebuilds pick up upstream CVE patches.
# The runtime uses the -openssl variant (ships libssl/libcrypto, so the
# runtime needs no hand-copied OpenSSL from the builder).

ARG BUILDER_IMAGE=registry.access.redhat.com/hi/rust:1-builder
ARG RUNTIME_IMAGE=registry.access.redhat.com/hi/core-runtime:latest-openssl

# BUILD KNOB — the authoritative doc for the build arg; override with
# --build-arg (compose passes VAULTWARDEN_WEB_VAULT through from the env).
# Changing it requires a rebuild.
#   VAULTWARDEN_WEB_VAULT: web vault UI baked into the image; false = API-only.
# The database is SQLite (see below) — there is no DB backend knob.

ARG VAULTWARDEN_WEB_VAULT=true

# STAGE 1 — FETCH: download + verify the release tarballs against pinned
# sha256 digests (same-origin checksum files are NOT trusted; a compromised
# release origin can no longer swap artifact + checksum together).

FROM ${BUILDER_IMAGE} AS fetch
# TARGETARCH is BuildKit-predefined; uname fallback for non-BuildKit builders
ARG TARGETARCH
ARG VW_VERSION
ARG VW_SHA256
ARG WEB_VAULT_VERSION
ARG WEB_VAULT_SHA256
ARG VAULTWARDEN_WEB_VAULT
ARG TAILSCALE_VERSION
ARG TAILSCALE_SHA256_AMD64
ARG TAILSCALE_SHA256_ARM64
RUN dnf -y install tar gzip && dnf clean all
WORKDIR /fetch
RUN mkdir -p /out /out/web-vault /data
RUN ARCH="${TARGETARCH:-$(uname -m)}" \
 && case "${ARCH}" in \
        amd64|x86_64) TAILSCALE_ARCH=amd64; TS_SHA="${TAILSCALE_SHA256_AMD64}" ;; \
        arm64|aarch64) TAILSCALE_ARCH=arm64; TS_SHA="${TAILSCALE_SHA256_ARM64}" ;; \
        *) echo "unsupported arch: ${ARCH}" && exit 1 ;; \
    esac \
 && curl -fsSL -o vw.tar.gz \
        "https://github.com/dani-garcia/vaultwarden/archive/refs/tags/${VW_VERSION}.tar.gz" \
 && echo "${VW_SHA256}  vw.tar.gz" | sha256sum -c - \
 && if [ "${VAULTWARDEN_WEB_VAULT}" = "true" ]; then \
        curl -fsSL -o "bw_web_${WEB_VAULT_VERSION}.tar.gz" \
            "https://github.com/dani-garcia/bw_web_builds/releases/download/${WEB_VAULT_VERSION}/bw_web_${WEB_VAULT_VERSION}.tar.gz" \
     && echo "${WEB_VAULT_SHA256}  bw_web_${WEB_VAULT_VERSION}.tar.gz" | sha256sum -c - \
     && tar -xzf "bw_web_${WEB_VAULT_VERSION}.tar.gz" -C /out/web-vault --strip-components=1 \
     && test -f /out/web-vault/index.html ; \
    fi \
 && curl -fsSL -o ts.tgz \
        "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${TAILSCALE_ARCH}.tgz" \
 && echo "${TS_SHA}  ts.tgz" | sha256sum -c - \
 && tar -xzf ts.tgz -C /out --strip-components=1 \
 && test -x /out/tailscale && test -x /out/tailscaled

# STAGE 2 — SUPERVISOR: Rust PID 1 (glibc lockstep with the runtime)

FROM ${BUILDER_IMAGE} AS supervisor
# TARGETARCH is BuildKit-predefined; uname fallback for non-BuildKit builders
ARG TARGETARCH
WORKDIR /src
COPY supervisor/Cargo.toml supervisor/Cargo.lock ./
COPY supervisor/src ./src
# x86-64-v2 = RHEL 9 baseline (same tuning as the vaultwarden stage).
# --locked: fail closed on lockfile drift
RUN case "${TARGETARCH:-$(uname -m)}" in \
        amd64|x86_64) export RUSTFLAGS="-Ctarget-cpu=x86-64-v2" ;; \
    esac \
 && cargo build --release --locked && cp target/release/supervisor /out-supervisor

# STAGE 3 — VAULTWARDEN: built from source, SQLite-only
# Maintenance note: keep comments outside RUN chains — a '#' after '\'
# truncates the chain.

FROM ${BUILDER_IMAGE} AS vw-build
ARG TARGETARCH
ARG VW_VERSION
RUN dnf -y install tar gzip tzdata openssl-devel && dnf clean all
WORKDIR /build
COPY --from=fetch /fetch/vw.tar.gz .
# x86-64-v2 = RHEL 9 baseline; mimalloc = hardened allocator. Only sqlite
# is compiled in: the DB lives on the data volume, and the supervisor's
# backup/restore speaks the file format natively.
RUN tar -xzf vw.tar.gz --strip-components=1 && rm vw.tar.gz \
 && case "${TARGETARCH:-$(uname -m)}" in \
        amd64|x86_64) export RUSTFLAGS="-Ctarget-cpu=x86-64-v2" ;; \
    esac \
 && VW_VERSION=${VW_VERSION} cargo build \
        --features "sqlite,enable_mimalloc" --profile release \
 && cp target/release/vaultwarden /out-vaultwarden

# STAGE 4 — RUNTIME: minimal shell-less image (uid 65532)

FROM ${RUNTIME_IMAGE} AS runtime
ARG VW_VERSION
ARG TAILSCALE_VERSION
ARG VAULTWARDEN_WEB_VAULT

LABEL org.opencontainers.image.title="vaultwarden-hummingbird" \
      org.opencontainers.image.description="Vaultwarden ${VW_VERSION} + Tailscale ${TAILSCALE_VERSION} on Hummingbird core-runtime" \
      org.opencontainers.image.source="https://github.com/dani-garcia/vaultwarden"

# RUNTIME CONTENTS — the -openssl runtime image provides libssl/libcrypto;
# the sqlite-only vaultwarden build needs no other shared libs copied in.
# Zoneinfo keeps TZ useful.
COPY --from=vw-build /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=supervisor /out-supervisor /entrypoint
COPY --from=fetch /out/tailscale /usr/local/bin/tailscale
COPY --from=fetch /out/tailscaled /usr/local/bin/tailscaled
COPY --from=vw-build /out-vaultwarden /vaultwarden
# web-vault dir always exists (may be empty) so COPY succeeds
COPY --from=fetch /out/web-vault /web-vault
COPY --from=fetch --chown=65532:0 /data /data

# RUNTIME DEFAULTS — plain upstream names: the image-default layer, not
# user config (that flows via the dotenv file). ROCKET_ADDRESS is also
# hard-pinned to 127.0.0.1 by the supervisor at spawn (defense in depth:
# the image default must not reintroduce a 0.0.0.0 API listener if run
# without the supervisor). WEB_VAULT_ENABLED is likewise re-derived by
# the supervisor from the baked folder (ambient env is default-deny for
# the vault child), so an API-only build stays API-only under the
# supervisor too. Volatile storage: pointing /data at tmpfs (or running
# without a volume) loses everything on exit. vaultwarden's upstream
# I_REALLY_WANT_VOLATILE_STORAGE gate did NOT trigger on 1.37.2 (verified:
# a tmpfs /data boots clean, no refusal, no warning) — the safety net here
# is the supervisor's state sync + DB backup, not the vault's own check.

ENV DATA_FOLDER=/data \
    ORG_ATTACHMENT_LIMIT=0 \
    ORG_CREATION_USERS=all \
    ROCKET_ADDRESS=127.0.0.1 \
    SIGNUPS_ALLOWED=true \
    TZ=UTC \
    USER_ATTACHMENT_LIMIT=0 \
    WEB_VAULT_ENABLED=${VAULTWARDEN_WEB_VAULT} \
    WEB_VAULT_FOLDER=/web-vault

# CONTAINER SHAPE — persistent data volume, the gate port, non-root
# entrypoint (the supervisor).

VOLUME /data
EXPOSE 8080

USER 65532:0
ENTRYPOINT ["/entrypoint"]

# HEALTHCHECK — the supervisor dials its own gate in one-shot mode
# (`/entrypoint --healthcheck`), which reports 200 only when vaultwarden's
# own /alive answers 2xx — the full chain, probed without a shell (exec
# form; the runtime image has no curl/wget).

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/entrypoint", "--healthcheck"]
