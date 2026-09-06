# syntax=docker/dockerfile:1

# Vaultwarden + Tailscale on Red Hat Hummingbird. Checksum-pinned official
# sources, Rust supervisor as PID 1, web vault optional (WEB_VAULT=true).

ARG BUILDER_IMAGE=registry.access.redhat.com/hi/rust:1-builder@sha256:6c5a4c3f0d419a2694c5f1d7482f17d2b7f76474f157af3a25061a3ed789380a
ARG RUNTIME_IMAGE=registry.access.redhat.com/hi/core-runtime:latest@sha256:8f4f90ae5941225e09ef034c4476bbe7918d084b72aaf78e0e198c36e7117270
ARG VW_VERSION=1.37.2
# sha256 of the source tarball; bump with VW_VERSION
ARG VW_SHA256=d607cc00066f7ea62b27a3c198e0259955fd5591adabccb8d3414d1f3d91ecd7
# NOTE: Renovate has no manager for the digests; its PRs fail the build
# until they are updated by hand.
ARG WEB_VAULT_VERSION=v2026.7.0
ARG WEB_VAULT=false
ARG TAILSCALE_VERSION=1.102.3
ARG CMAKE_VERSION=4.3.0
# per-arch sha256; bump with CMAKE_VERSION
ARG CMAKE_SHA256_X86_64=201bdabe17a54e017f119cffa247648e9c44327e52473c2cc60a88fded94652a
ARG CMAKE_SHA256_AARCH64=26fe3011f497eb9398115dcabcc094685e634b1841f7c01dc01c5a89b8b0ea0d
ARG RCLONE_VERSION=1.75.1
# DB backends compiled into vaultwarden: postgresql (default), sqlite, mysql,
# or a comma-separated combination.
ARG DB=postgresql

# Stage 1: fetch + verify release tarballs
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
# web-vault dir always exists (may be empty) so COPY succeeds
COPY --from=fetch /out/web-vault /web-vault
# uid 65532 pre-exists in /etc/passwd
COPY --from=fetch --chown=65532:0 /data /data

# defaults; env vars override
ENV DATA_FOLDER=/data \
    SIGNUPS_ALLOWED=false \
    ORG_CREATION_USERS=none \
    USER_ATTACHMENT_LIMIT=0 \
    ORG_ATTACHMENT_LIMIT=0 \
    WEB_VAULT_ENABLED=${WEB_VAULT} \
    WEB_VAULT_FOLDER=/web-vault \
    I_REALLY_WANT_VOLATILE_STORAGE=true \
    TZ=UTC \
    ROCKET_ADDRESS=0.0.0.0

VOLUME /data
EXPOSE 8080

USER 65532:0
ENTRYPOINT ["/entrypoint"]
