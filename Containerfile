# ============================================================================
# VAULTWARDEN-HUMMINGBIRD — Vaultwarden + Tailscale on Red Hat Hummingbird
#   Checksum-pinned official sources, Rust supervisor as PID 1, web vault on
#   by default (VAULTWARDEN_WEB_VAULT=false for API-only).
#   Build with --format docker (or BUILDAH_FORMAT=docker): podman's default
#   OCI image format drops HEALTHCHECK (verified on podman 5.8.4).
# ============================================================================

# ============================================================================
# UPSTREAM PINS — Renovate-managed component versions
#   renovate.json regexes match these exact ARG lines — never reformat them.
#   VW_SHA256 pins the vaultwarden source tarball; Renovate has no manager
#   for the digest, so update it by hand alongside VW_VERSION.
# ============================================================================

ARG VW_VERSION=1.37.2
# sha256 of the source tarball; bump with VW_VERSION.
ARG VW_SHA256=d607cc00066f7ea62b27a3c198e0259955fd5591adabccb8d3414d1f3d91ecd7
ARG WEB_VAULT_VERSION=v2026.7.0
ARG TAILSCALE_VERSION=1.102.3
ARG RCLONE_VERSION=1.75.1

# ============================================================================
# BASE IMAGES — floating tags; rebuilds pick up upstream CVE patches
#   The runtime uses the -openssl variant: it ships libssl/libcrypto, so the
#   runtime stage needs no hand-copied OpenSSL from the builder (the two
#   images update independently and would drift). mariadb's client lib still
#   comes from the vw-build stage, gated by the DB build knob.
#   The DB client images supply the supervisor's backup tools (pg_dump/
#   pg_restore, mariadb-dump/mariadb) and their shared-lib closure; they
#   float too, so the dump client stays at-or-above the server majors it
#   must read.
# ============================================================================

ARG BUILDER_IMAGE=registry.access.redhat.com/hi/rust:1-builder
ARG RUNTIME_IMAGE=registry.access.redhat.com/hi/core-runtime:latest-openssl
ARG PG_CLIENT_IMAGE=registry.access.redhat.com/hi/postgresql:latest
ARG MARIADB_CLIENT_IMAGE=registry.access.redhat.com/hi/mariadb:latest

# ============================================================================
# BUILD KNOBS — build-time feature toggles (changing one requires a rebuild)
#   The authoritative documentation for every build arg lives here:
#   override with --build-arg; compose additionally passes
#   VAULTWARDEN_WEB_VAULT through from the environment/.env when set.
#   VAULTWARDEN_WEB_VAULT: web vault UI baked into the image; false =
#   API-only.
#   DB: backends compiled into vaultwarden — postgresql, sqlite, mysql, or
#   a comma-separated combination. Default: all three, so a bare build
#   matches upstream's feature set.
# ============================================================================

ARG VAULTWARDEN_WEB_VAULT=true
ARG DB=postgresql,sqlite,mysql

# ============================================================================
# STAGE 1 — FETCH: download + verify the release tarballs
#   Tailscale/rclone/web vault are checksum-verified at build against
#   official files (same origin), not pinned.
# ============================================================================

FROM ${BUILDER_IMAGE} AS fetch
# TARGETARCH is BuildKit-predefined; uname fallback for non-BuildKit builders
ARG TARGETARCH
ARG VW_VERSION
ARG VW_SHA256
ARG WEB_VAULT_VERSION
ARG VAULTWARDEN_WEB_VAULT
ARG TAILSCALE_VERSION
ARG RCLONE_VERSION
RUN dnf -y install tar gzip unzip && dnf clean all
WORKDIR /fetch
RUN mkdir -p /out /out/web-vault /data
RUN ARCH="${TARGETARCH:-$(uname -m)}" \
 && case "${ARCH}" in \
        amd64|x86_64) TAILSCALE_ARCH=amd64; RC_ARCH=linux-amd64 ;; \
        arm64|aarch64) TAILSCALE_ARCH=arm64; RC_ARCH=linux-arm64 ;; \
        *) echo "unsupported arch: ${ARCH}" && exit 1 ;; \
    esac \
 && curl -fsSL -o vw.tar.gz \
        "https://github.com/dani-garcia/vaultwarden/archive/refs/tags/${VW_VERSION}.tar.gz" \
 && echo "${VW_SHA256}  vw.tar.gz" | sha256sum -c - \
 && curl -fsSL -o SHA256SUMS \
        "https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/SHA256SUMS" \
 && curl -fsSL -o "rclone-v${RCLONE_VERSION}-${RC_ARCH}.zip" \
        "https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-${RC_ARCH}.zip" \
 && grep "rclone-v${RCLONE_VERSION}-${RC_ARCH}.zip$" SHA256SUMS | sha256sum -c - \
 && if [ "${VAULTWARDEN_WEB_VAULT}" = "true" ]; then \
        curl -fsSL -o "bw_web_${WEB_VAULT_VERSION}.tar.gz" \
            "https://github.com/dani-garcia/bw_web_builds/releases/download/${WEB_VAULT_VERSION}/bw_web_${WEB_VAULT_VERSION}.tar.gz" \
     && curl -fsSL -o wv.sums \
            "https://github.com/dani-garcia/bw_web_builds/releases/download/${WEB_VAULT_VERSION}/sha256sums.txt" \
     && grep "bw_web_${WEB_VAULT_VERSION}.tar.gz$" wv.sums | sha256sum -c - \
     && tar -xzf "bw_web_${WEB_VAULT_VERSION}.tar.gz" -C /out/web-vault --strip-components=1 \
     && test -f /out/web-vault/index.html ; \
    fi \
 && curl -fsSL -o ts.tgz \
        "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${TAILSCALE_ARCH}.tgz" \
 && curl -fsSL -o ts.tgz.sha256 \
        "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${TAILSCALE_ARCH}.tgz.sha256" \
 && echo "$(cat ts.tgz.sha256)  ts.tgz" | sha256sum -c - \
 && tar -xzf ts.tgz -C /out --strip-components=1 \
 && unzip -j "rclone-v${RCLONE_VERSION}-${RC_ARCH}.zip" "*/rclone" -d /out \
 && rm "rclone-v${RCLONE_VERSION}-${RC_ARCH}.zip" SHA256SUMS \
 && test -x /out/tailscale && test -x /out/tailscaled && test -x /out/rclone

# ============================================================================
# STAGE 2 — SUPERVISOR: Rust PID 1 (glibc lockstep with the runtime)
# ============================================================================

FROM ${BUILDER_IMAGE} AS supervisor
WORKDIR /src
COPY supervisor/Cargo.toml supervisor/Cargo.lock ./
COPY supervisor/src ./src
# --locked: fail closed on lockfile drift
RUN cargo build --release --locked && cp target/release/supervisor /out-supervisor

# ============================================================================
# STAGE 3 — VAULTWARDEN: built from source
#   Maintenance note: keep comments outside RUN chains — a '#' after '\'
#   truncates the chain.
# ============================================================================

FROM ${BUILDER_IMAGE} AS vw-build
ARG TARGETARCH
ARG VW_VERSION
ARG DB
# fail-closed: DB must enable at least one known backend
RUN case ",${DB}," in \
        *,sqlite,*|*,sqlite_system,*|*,mysql,*|*,postgresql,*) ;; \
        *) echo "DB: enable at least one of sqlite, mysql, postgresql (got '${DB}')" && exit 1 ;; \
    esac \
 && PKGS="tar gzip tzdata openssl-devel" \
 && case ",${DB}," in \
        *,mysql,*) PKGS="$PKGS mariadb-connector-c-devel" ;; \
    esac \
 && dnf -y install $PKGS && dnf clean all
WORKDIR /build
COPY --from=fetch /fetch/vw.tar.gz .
# pq-sys@= pinned for reproducible builds; the bundled libpq *source* inside
# pq-src floats in [0.2,0.4) and resolves at build time. mimalloc = hardened
# allocator; x86-64-v2 = RHEL 9 baseline. Only the mariadb client lib is
# staged (the -openssl runtime image provides libssl/libcrypto itself).
RUN tar -xzf vw.tar.gz --strip-components=1 && rm vw.tar.gz \
 && case ",${DB}," in \
        *,postgresql,*) cargo add pq-sys@=0.7.5 --features bundled ;; \
    esac \
 && case "${TARGETARCH:-$(uname -m)}" in \
        amd64|x86_64) export RUSTFLAGS="-Ctarget-cpu=x86-64-v2" ;; \
    esac \
 && VW_VERSION=${VW_VERSION} cargo build \
        --features "${DB},enable_mimalloc" --profile release \
 && mkdir /out-libs \
 && case ",${DB}," in \
        *,mysql,*) cp -a /usr/lib64/libmariadb.so.3* /out-libs/ ;; \
    esac \
 && cp target/release/vaultwarden /out-vaultwarden

# ============================================================================
# DB CLIENT TOOLS — extracted from official Red Hat client images
#   For the supervisor's backup feature (pg_dump/pg_restore, mariadb-dump/
#   mariadb). Extracted, not built from source — the hummingbird builder
#   repo lacks bison/flex/perl. Each stage collects the client binaries
#   plus their shared-lib closure, minus libs the core runtime already
#   provides (glibc, libstdc++, libz, selinux/pcre2). Libs land in a
#   private directory that the supervisor points LD_LIBRARY_PATH at, so
#   nothing in the runtime is replaced.
# ============================================================================

FROM ${PG_CLIENT_IMAGE} AS pg-clients
USER 0
RUN mkdir -p /out/bin /out/lib \
 && cp /usr/bin/pg_dump /usr/bin/pg_restore /out/bin/ \
 && for lib in $(ldd /usr/bin/pg_dump /usr/bin/pg_restore \
        | grep "=> /" | cut -d' ' -f3 | sort -u); do \
        case "$lib" in \
            /lib64/libc.so.6|/lib64/libgcc_s.so.1|/lib64/libm.so.6|\
            /lib64/libstdc++.so.6|/lib64/libz.so.1|/lib64/libselinux.so.1|\
            /lib64/libpcre2-8.so.0|/lib64/libresolv.so.2) ;; \
            *) cp -L "$lib" /out/lib/ ;; \
        esac; done

FROM ${MARIADB_CLIENT_IMAGE} AS mdb-clients
USER 0
RUN mkdir -p /out/bin /out/lib \
 && cp /usr/bin/mariadb-dump /usr/bin/mariadb /out/bin/ \
 && for lib in $(ldd /usr/bin/mariadb-dump /usr/bin/mariadb \
        | grep "=> /" | cut -d' ' -f3 | sort -u); do \
        case "$lib" in \
            /lib64/libc.so.6|/lib64/libgcc_s.so.1|/lib64/libm.so.6|\
            /lib64/libstdc++.so.6|/lib64/libz.so.1|/lib64/libselinux.so.1|\
            /lib64/libpcre2-8.so.0|/lib64/libresolv.so.2) ;; \
            *) cp -L "$lib" /out/lib/ ;; \
        esac; done

# ============================================================================
# STAGE 4 — RUNTIME: minimal shell-less image (uid 65532)
# ============================================================================

FROM ${RUNTIME_IMAGE} AS runtime
ARG VW_VERSION
ARG TAILSCALE_VERSION
ARG VAULTWARDEN_WEB_VAULT

LABEL org.opencontainers.image.title="vaultwarden-hummingbird" \
      org.opencontainers.image.description="Vaultwarden ${VW_VERSION} + Tailscale ${TAILSCALE_VERSION} on Hummingbird core-runtime" \
      org.opencontainers.image.source="https://github.com/dani-garcia/vaultwarden"

# mariadb lib only when DB included mysql (the -openssl runtime provides
# libssl/libcrypto itself). postgres/sqlite are static in vaultwarden.
COPY --from=vw-build /out-libs/ /usr/lib64/
COPY --from=vw-build /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=supervisor /out-supervisor /entrypoint
COPY --from=fetch /out/tailscale /usr/local/bin/tailscale
COPY --from=fetch /out/tailscaled /usr/local/bin/tailscaled
COPY --from=fetch /out/rclone /usr/local/bin/rclone
COPY --from=vw-build /out-vaultwarden /vaultwarden
# DB client tools + their shared-lib closure in a private dir (LD_LIBRARY_PATH
# set by the supervisor per invocation). Both dirs always exist (may be empty)
# so COPY succeeds regardless of the DB build arg.
COPY --from=pg-clients /out/ /usr/local/lib/dbclients/
COPY --from=mdb-clients /out/ /usr/local/lib/dbclients/
# web-vault dir always exists (may be empty) so COPY succeeds
COPY --from=fetch /out/web-vault /web-vault
# uid 65532 pre-exists in /etc/passwd
COPY --from=fetch --chown=65532:0 /data /data

# ============================================================================
# IMAGE DEFAULTS — vaultwarden runtime defaults (plain upstream names)
#   The image-default layer, not user config (that flows via the dotenv
#   file). ROCKET_ADDRESS is also hard-pinned to 127.0.0.1 by the
#   supervisor at spawn (defense in depth: the image default must not
#   reintroduce a 0.0.0.0 API listener if run without the supervisor).
# ============================================================================

ENV DATA_FOLDER=/data \
    I_REALLY_WANT_VOLATILE_STORAGE=true \
    ORG_ATTACHMENT_LIMIT=0 \
    ORG_CREATION_USERS=none \
    ROCKET_ADDRESS=127.0.0.1 \
    SIGNUPS_ALLOWED=false \
    TZ=UTC \
    USER_ATTACHMENT_LIMIT=0 \
    WEB_VAULT_ENABLED=${VAULTWARDEN_WEB_VAULT} \
    WEB_VAULT_FOLDER=/web-vault

VOLUME /data
EXPOSE 8080

USER 65532:0
ENTRYPOINT ["/entrypoint"]

# ============================================================================
# HEALTHCHECK — container-native health probe
#   The supervisor dials its own gate in one-shot mode (`/entrypoint
#   --healthcheck`), which reports 200 only when vaultwarden's own /alive
#   answers 2xx — the full chain, probed without a shell (exec form; the
#   runtime image has no curl/wget).
# ============================================================================

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/entrypoint", "--healthcheck"]
