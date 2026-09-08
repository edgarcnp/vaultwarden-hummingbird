# Vaultwarden + Tailscale on Red Hat Hummingbird. Checksum-pinned official
# sources, Rust supervisor as PID 1, web vault on by default (WEB_VAULT=false
# for API-only).

# Base images float on their tags: rebuilds pick up upstream CVE patches.
ARG BUILDER_IMAGE=registry.access.redhat.com/hi/rust:1-builder
ARG RUNTIME_IMAGE=registry.access.redhat.com/hi/core-runtime:latest
ARG VW_VERSION=1.37.2
# sha256 of the source tarball; bump with VW_VERSION
ARG VW_SHA256=d607cc00066f7ea62b27a3c198e0259955fd5591adabccb8d3414d1f3d91ecd7
# NOTE: Renovate has no manager for the digests; its PRs fail the build
# until they are updated by hand.
ARG WEB_VAULT_VERSION=v2026.7.0
ARG WEB_VAULT=true
ARG TAILSCALE_VERSION=1.102.3
ARG CMAKE_VERSION=4.3.0
# per-arch sha256; bump with CMAKE_VERSION
ARG CMAKE_SHA256_X86_64=201bdabe17a54e017f119cffa247648e9c44327e52473c2cc60a88fded94652a
ARG CMAKE_SHA256_AARCH64=26fe3011f497eb9398115dcabcc094685e634b1841f7c01dc01c5a89b8b0ea0d
ARG RCLONE_VERSION=1.75.1
# DB backends compiled into vaultwarden: postgresql, sqlite, mysql, or a
# comma-separated combination. Default: all three, so a bare build matches
# upstream's feature set.
ARG DB=postgresql,sqlite,mysql
# Official Red Hat client images supplying the supervisor's DB backup tools
# (pg_dump/pg_restore, mariadb-dump/mariadb) and their shared-lib closure.
# Floating like the base images: rebuilds track upstream patches, and the
# dump client stays at-or-above the server majors it must read.
ARG PG_CLIENT_IMAGE=registry.access.redhat.com/hi/postgresql:latest
ARG MARIADB_CLIENT_IMAGE=registry.access.redhat.com/hi/mariadb:latest

# Stage 1: fetch + verify release tarballs. Tailscale/rclone/web vault are
# checksum-verified at build against official files (same origin), not pinned.
FROM ${BUILDER_IMAGE} AS fetch
# TARGETARCH is BuildKit-predefined; uname fallback for non-BuildKit builders
ARG TARGETARCH
ARG VW_VERSION
ARG VW_SHA256
ARG WEB_VAULT_VERSION
ARG WEB_VAULT
ARG TAILSCALE_VERSION
ARG RCLONE_VERSION
RUN dnf -y install tar gzip unzip && dnf clean all
WORKDIR /fetch
RUN ARCH="${TARGETARCH:-$(uname -m)}" \
 && case "${ARCH}" in \
        amd64|x86_64) TS_ARCH=amd64; RC_ARCH=linux-amd64 ;; \
        arm64|aarch64) TS_ARCH=arm64; RC_ARCH=linux-arm64 ;; \
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
 && mkdir -p /out/web-vault \
 && if [ "${WEB_VAULT}" = "true" ]; then \
        curl -fsSL -o "bw_web_${WEB_VAULT_VERSION}.tar.gz" \
            "https://github.com/dani-garcia/bw_web_builds/releases/download/${WEB_VAULT_VERSION}/bw_web_${WEB_VAULT_VERSION}.tar.gz" \
     && curl -fsSL -o wv.sums \
            "https://github.com/dani-garcia/bw_web_builds/releases/download/${WEB_VAULT_VERSION}/sha256sums.txt" \
     && grep "bw_web_${WEB_VAULT_VERSION}.tar.gz$" wv.sums | sha256sum -c - \
     && tar -xzf "bw_web_${WEB_VAULT_VERSION}.tar.gz" -C /out/web-vault --strip-components=1 \
     && test -f /out/web-vault/index.html ; \
    fi \
 && curl -fsSL -o ts.tgz \
        "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${TS_ARCH}.tgz" \
 && curl -fsSL -o ts.tgz.sha256 \
        "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${TS_ARCH}.tgz.sha256" \
 && echo "$(cat ts.tgz.sha256)  ts.tgz" | sha256sum -c - \
 && mkdir -p /out /data \
 && tar -xzf ts.tgz -C /out --strip-components=1 \
 && unzip -j "rclone-v${RCLONE_VERSION}-${RC_ARCH}.zip" "*/rclone" -d /out \
 && rm "rclone-v${RCLONE_VERSION}-${RC_ARCH}.zip" SHA256SUMS \
 && test -x /out/tailscale && test -x /out/tailscaled && test -x /out/rclone

# Stage 2: supervisor (glibc lockstep with the runtime)
FROM ${BUILDER_IMAGE} AS supervisor
WORKDIR /src
COPY supervisor/Cargo.toml supervisor/Cargo.lock ./
COPY supervisor/src ./src
# --locked: fail closed on lockfile drift
RUN cargo build --release --locked && cp target/release/supervisor /out-supervisor

# Stage 3: vaultwarden from source
FROM ${BUILDER_IMAGE} AS vw-build
ARG TARGETARCH
ARG VW_VERSION
ARG DB
ARG CMAKE_VERSION
ARG CMAKE_SHA256_X86_64
ARG CMAKE_SHA256_AARCH64
# fail-closed: DB must enable at least one known backend
RUN case ",${DB}," in \
        *,sqlite,*|*,sqlite_system,*|*,mysql,*|*,postgresql,*) ;; \
        *) echo "DB: enable at least one of sqlite, mysql, postgresql (got '${DB}')" && exit 1 ;; \
    esac \
 && PKGS="tar gzip tzdata openssl-devel" \
 && case ",${DB}," in \
        *,mysql,*) PKGS="$PKGS mariadb-connector-c-devel" ;; \
    esac \
 && dnf -y install $PKGS && dnf clean all \
 && ARCH="${TARGETARCH:-$(uname -m)}" \
 && case "${ARCH}" in \
        amd64|x86_64) CMAKE_ARCH=x86_64; CMAKE_SHA=${CMAKE_SHA256_X86_64} ;; \
        arm64|aarch64) CMAKE_ARCH=aarch64; CMAKE_SHA=${CMAKE_SHA256_AARCH64} ;; \
        *) echo "unsupported arch: ${ARCH}" && exit 1 ;; \
    esac \
 && case ",${DB}," in \
        *,postgresql,*) \
            curl -fsSL -o /tmp/cmake.tar.gz \
                "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.tar.gz" \
         && echo "${CMAKE_SHA}  /tmp/cmake.tar.gz" | sha256sum -c - \
         && tar -xzf /tmp/cmake.tar.gz -C /usr/local --strip-components=1 \
         && rm /tmp/cmake.tar.gz ;; \
    esac
WORKDIR /build
COPY --from=fetch /fetch/vw.tar.gz .
# pq-sys@= exact pin for reproducible builds; mimalloc = hardened allocator;
# x86-64-v2 = RHEL 9 baseline. Runtime libs staged to /out-libs.
# NOTE: keep comments outside RUN chains — a '#' after '\' truncates the chain.
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
 && cp -a /usr/lib64/libssl.so.3* /usr/lib64/libcrypto.so.3* /out-libs/ \
 && case ",${DB}," in \
        *,mysql,*) cp -a /usr/lib64/libmariadb.so.3* /out-libs/ ;; \
    esac \
 && cp target/release/vaultwarden /out-vaultwarden

# DB client tools for the supervisor's backup feature: extracted from the
# official Red Hat client images (glibc lockstep with the runtime), not
# built from source — the hummingbird builder repo lacks bison/flex/perl.
# Each stage collects the client binaries plus their shared-lib closure,
# minus libs the core runtime already provides (glibc, libstdc++, libz,
# selinux/pcre2). Libs land in a private directory that the supervisor
# points LD_LIBRARY_PATH at, so nothing in the runtime is replaced.
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

# Stage 4: runtime (shell-less, uid 65532)
FROM ${RUNTIME_IMAGE} AS runtime
ARG VW_VERSION
ARG TAILSCALE_VERSION
ARG WEB_VAULT

LABEL org.opencontainers.image.title="vaultwarden-hummingbird" \
      org.opencontainers.image.description="Vaultwarden ${VW_VERSION} + Tailscale ${TAILSCALE_VERSION} on Hummingbird core-runtime" \
      org.opencontainers.image.source="https://github.com/dani-garcia/vaultwarden"

# openssl always; mariadb only when DB included mysql. postgres/sqlite static.
COPY --from=vw-build /out-libs/ /usr/lib64/
COPY --from=vw-build /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=supervisor /out-supervisor /entrypoint
COPY --from=fetch /out/tailscale /usr/local/bin/tailscale
COPY --from=fetch /out/tailscaled /usr/local/bin/tailscaled
COPY --from=fetch /out/rclone /usr/local/bin/rclone
COPY --from=vw-build /out-vaultwarden /vaultwarden
# DB client tools (pg_dump/pg_restore, mariadb-dump/mariadb) + their
# shared-lib closure in a private dir (LD_LIBRARY_PATH set by the
# supervisor per invocation). Both dirs always exist (may be empty) so
# COPY succeeds regardless of the DB build arg.
COPY --from=pg-clients /out/ /usr/local/lib/dbclients/
COPY --from=mdb-clients /out/ /usr/local/lib/dbclients/
# web-vault dir always exists (may be empty) so COPY succeeds
COPY --from=fetch /out/web-vault /web-vault
# uid 65532 pre-exists in /etc/passwd
COPY --from=fetch --chown=65532:0 /data /data

# defaults; env vars override. ROCKET_ADDRESS is also hard-pinned to
# 127.0.0.1 by the supervisor at spawn (defense in depth: the image default
# must not reintroduce a 0.0.0.0 API listener if run without the supervisor).
ENV DATA_FOLDER=/data \
    SIGNUPS_ALLOWED=false \
    ORG_CREATION_USERS=none \
    USER_ATTACHMENT_LIMIT=0 \
    ORG_ATTACHMENT_LIMIT=0 \
    WEB_VAULT_ENABLED=${WEB_VAULT} \
    WEB_VAULT_FOLDER=/web-vault \
    I_REALLY_WANT_VOLATILE_STORAGE=true \
    TZ=UTC \
    ROCKET_ADDRESS=127.0.0.1

VOLUME /data
EXPOSE 8080

USER 65532:0
ENTRYPOINT ["/entrypoint"]

# Container-native health: the supervisor dials its own gate in one-shot
# mode (`/entrypoint --healthcheck`), which reports 200 only when
# vaultwarden's own /alive answers 2xx — the full chain, probed without a
# shell (exec form; the runtime image has no curl/wget).
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/entrypoint", "--healthcheck"]
