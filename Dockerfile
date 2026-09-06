# syntax=docker/dockerfile:1

# Vaultwarden + Tailscale on Red Hat Hardened (Hummingbird) images.
#   builds:  registry.access.redhat.com/hi/rust:1-builder (rust 1.97.1 = upstream pin)
#   runtime: registry.access.redhat.com/hi/core-runtime:latest (shell-less, no pkg mgr)
# - vaultwarden: official source tarball; sqlite static, libpq bundled/static
#   (Hummingbird repo ships no libpq), openssl distro-shared
# - tailscale: official release tarball, sha256-verified
# - rclone: official release zip, SHA256SUMS-verified (S3 state sync)
# - web vault: optional build arg (upstream-style). Default false (API-only,
#   Bitwarden apps talk to the API directly). Rebuild with --build-arg
#   WEB_VAULT=true to include it.
# - PID 1: our Rust supervisor (supervisor/), glibc lockstep with runtime

ARG BUILDER_IMAGE=registry.access.redhat.com/hi/rust:1-builder
ARG RUNTIME_IMAGE=registry.access.redhat.com/hi/core-runtime:latest
ARG VW_VERSION=1.37.2
ARG WEB_VAULT_VERSION=v2026.7.0
ARG WEB_VAULT=false
ARG TAILSCALE_VERSION=1.102.3
ARG CMAKE_VERSION=4.3.0
ARG RCLONE_VERSION=1.75.1

############################################################################
# Stage 1: fetch + verify + extract official release tarballs
# (rclone is used by the supervisor's optional S3 state sync)
############################################################################
FROM ${BUILDER_IMAGE} AS fetch
ARG VW_VERSION
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

############################################################################
# Stage 2: supervisor (hardened rust toolchain, glibc lockstep with runtime)
############################################################################
FROM ${BUILDER_IMAGE} AS supervisor
WORKDIR /src
COPY supervisor/Cargo.toml supervisor/Cargo.lock ./
COPY supervisor/src ./src
RUN cargo build --release && cp target/release/supervisor /out-supervisor

############################################################################
# Stage 3: vaultwarden from official source
# (repo has no cmake: use official Kitware tarball; no libpq: pq-sys/bundled)
############################################################################
FROM ${BUILDER_IMAGE} AS vw-build
ARG VW_VERSION
ARG CMAKE_VERSION
RUN dnf -y install tar gzip tzdata openssl-devel mariadb-connector-c-devel \
 && dnf clean all \
 && ARCH="${TARGETARCH:-$(uname -m)}" \
 && case "${ARCH}" in \
        amd64|x86_64) CMAKE_ARCH=x86_64 ;; \
        arm64|aarch64) CMAKE_ARCH=aarch64 ;; \
        *) echo "unsupported arch: ${ARCH}" && exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/cmake.tar.gz \
        "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.tar.gz" \
 && tar -xzf /tmp/cmake.tar.gz -C /usr/local --strip-components=1 \
 && rm /tmp/cmake.tar.gz
WORKDIR /build
COPY --from=fetch /fetch/vw.tar.gz .
RUN tar -xzf vw.tar.gz --strip-components=1 && rm vw.tar.gz \
 # pq-sys/bundled: compile libpq (via pq-src+cmake) against distro openssl
 && cargo add pq-sys@0.7.5 --features bundled \
 && VW_VERSION=${VW_VERSION} cargo build \
        --features sqlite,mysql,postgresql --profile release \
 && cp target/release/vaultwarden /out-vaultwarden

############################################################################
# Stage 4: runtime — hi/core-runtime (no shell tooling assumed, uid 65532)
############################################################################
FROM ${RUNTIME_IMAGE} AS runtime
ARG VW_VERSION
ARG TAILSCALE_VERSION
ARG WEB_VAULT

LABEL org.opencontainers.image.title="vaultwarden-hummingbird" \
      org.opencontainers.image.description="Vaultwarden ${VW_VERSION} + Tailscale ${TAILSCALE_VERSION} on Hummingbird core-runtime" \
      org.opencontainers.image.source="https://github.com/dani-garcia/vaultwarden"

# Runtime shared libs (mariadb is the only dynamically linked DB backend;
# postgres/sqlite are linked statically; libmariadb.so.3 needs libssl/crypto,
# which core-runtime does not ship)
COPY --from=vw-build /usr/lib64/libmariadb.so.3* /usr/lib64/
COPY --from=vw-build /usr/lib64/libssl.so.3* /usr/lib64/
COPY --from=vw-build /usr/lib64/libcrypto.so.3* /usr/lib64/
COPY --from=vw-build /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=supervisor /out-supervisor /entrypoint
COPY --from=fetch /out/tailscale /usr/local/bin/tailscale
COPY --from=fetch /out/tailscaled /usr/local/bin/tailscaled
COPY --from=fetch /out/rclone /usr/local/bin/rclone
COPY --from=vw-build /out-vaultwarden /vaultwarden
# web vault files are present only when built with WEB_VAULT=true; the dir
# always exists (possibly empty) so the unconditional COPY succeeds
COPY --from=fetch /out/web-vault /web-vault
# uid 65532 is the pre-existing "container user" in /etc/passwd
COPY --from=fetch --chown=65532:0 /data /data

# personal posture baked in as image defaults (env vars override them):
# no signups after account creation, no orgs, attachments off (Taildrop)
ENV DATA_FOLDER=/data \
    SIGNUPS_ALLOWED=false \
    ORG_CREATION_USERS=none \
    USER_ATTACHMENT_LIMIT=0 \
    ORG_ATTACHMENT_LIMIT=0 \
    WEB_VAULT_ENABLED=${WEB_VAULT} \
    WEB_VAULT_FOLDER=/web-vault \
    I_REALLY_WANT_VOLATILE_STORAGE=true \
    TS_SOCKET=/tmp/tailscaled.sock \
    TZ=UTC \
    ROCKET_ADDRESS=0.0.0.0

VOLUME /data
# Render injects PORT (10000); default 8080 locally (non-root can't bind 80)
EXPOSE 8080

USER 65532:0
ENTRYPOINT ["/entrypoint"]
