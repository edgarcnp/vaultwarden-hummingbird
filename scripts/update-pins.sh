#!/usr/bin/env bash
# Recompute the upstream checksum pins in the Containerfile from its
# version ARGs, rewriting each *_SHA256 ARG line in place.
#
# The script is the single writer of the digests: Renovate runs it after
# every version bump (postUpgradeTasks), and CI runs it followed by
# `git diff --exit-code Containerfile`, so a version bumped without its
# digest - or an upstream artifact replaced at the same tag - is red
# build. Never hand-edit a digest; if you bump a version yourself, run
# this script. Idempotent: correct pins mean no changes.
#
# Requires: curl, sha256sum, sed. Downloads each artifact once.

set -euo pipefail
cd "$(dirname "$0")/.."

containerfile=Containerfile

arg() { # arg NAME -> the version pinned by `ARG NAME=...`
  sed -n "s/^ARG $1=//p" "$containerfile"
}

set_pin() { # set_pin NAME digest - rewrite the pin, report only on change
  local name=$1 digest=$2 current
  current=$(sed -n "s/^ARG $name=//p" "$containerfile")
  if [ "$current" = "$digest" ]; then
    echo "$name up to date"
    return
  fi
  sed -i "s/^ARG $name=.*/ARG $name=$digest/" "$containerfile"
  echo "$name -> $digest"
}

fetch_digest() { # fetch_digest URL -> the artifact's sha256
  local url=$1 file
  file=$(mktemp)
  curl -fsSL -o "$file" "$url"
  sha256sum "$file" | cut -d' ' -f1
  rm -f "$file"
}

# vaultwarden source tarball
vw=$(arg VW_VERSION)
set_pin VW_SHA256 \
  "$(fetch_digest "https://github.com/dani-garcia/vaultwarden/archive/refs/tags/${vw}.tar.gz")"

# web-vault tarball (tag and artifact name share the v-prefixed version)
wv=$(arg WEB_VAULT_VERSION)
set_pin WEB_VAULT_SHA256 \
  "$(fetch_digest "https://github.com/dani-garcia/bw_web_builds/releases/download/${wv}/bw_web_${wv}.tar.gz")"

# tailscale per-arch tarballs
ts=$(arg TAILSCALE_VERSION)
set_pin TAILSCALE_SHA256_AMD64 \
  "$(fetch_digest "https://pkgs.tailscale.com/stable/tailscale_${ts}_amd64.tgz")"
set_pin TAILSCALE_SHA256_ARM64 \
  "$(fetch_digest "https://pkgs.tailscale.com/stable/tailscale_${ts}_arm64.tgz")"
