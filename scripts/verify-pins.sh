#!/usr/bin/env bash
# Verify every supply-chain pin the repository depends on:
#   - every Containerfile base image ARG carries a sha256 digest;
#   - every FROM references an image ARG (or a digest literal);
#   - every artifact checksum ARG is a 64-hex sha256;
#   - every GitHub Action is pinned to a 40-hex commit.
# Run by the Pins workflow and the lint-extra suite. Version bumps are
# Renovate's job; this script only proves the pins exist and are shaped
# right.
set -euo pipefail

fail=0

while IFS= read -r line; do
  if [[ $line =~ ^ARG\ ([A-Z0-9_]+_IMAGE)=([^[:space:]]+)$ ]]; then
    name=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    if [[ ! $value =~ @sha256:[0-9a-f]{64}$ ]]; then
      echo "unpinned base image: $name=$value" >&2
      fail=1
    fi
  fi
done <Containerfile

while IFS= read -r line; do
  case $line in
    "FROM \${"*) : ;;
    "FROM "*"@sha256:"*) : ;;
    *)
      echo "FROM must reference a pinned image ARG or a digest: $line" >&2
      fail=1
      ;;
  esac
done < <(grep -E '^FROM ' Containerfile)

while IFS= read -r line; do
  value=${line#*=}
  if [[ ! $value =~ ^[0-9a-f]{64}$ ]]; then
    echo "bad artifact checksum: $line" >&2
    fail=1
  fi
done < <(grep -E '^ARG [A-Z0-9_]+_SHA256(_[A-Z0-9]+)?=' Containerfile)

while IFS= read -r line; do
  ref=${line##*@}
  if [[ ! $ref =~ ^[0-9a-f]{40}$ ]]; then
    echo "unpinned GitHub Action: $line" >&2
    fail=1
  fi
done < <(grep -RhoE 'uses: [^[:space:]]+' .github/workflows | sed 's/^uses: //')

if [[ $fail -ne 0 ]]; then
  exit 1
fi
echo "pins: base images, checksums, and actions are pinned"
