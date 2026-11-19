#!/usr/bin/env bash
# Extra static checks: actionlint, shellcheck, hadolint. Each tool is
# fetched from its release page and verified against the checksum recorded
# here (no floating packages); a replaced release at the same tag fails the
# download check.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # fetch URL SHA256 OUT
  local url=$1 sha=$2 out=$3
  curl -fsSL --max-time 300 --retry 3 --retry-delay 2 -o "$out" "$url"
  echo "$sha  $out" | sha256sum -c -
}

fetch "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz" \
  "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8" \
  "$work/actionlint.tgz"
tar -xzf "$work/actionlint.tgz" -C "$work"

fetch "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz" \
  "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198" \
  "$work/shellcheck.tar.xz"
tar -xJf "$work/shellcheck.tar.xz" -C "$work"

fetch "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-Linux-x86_64" \
  "c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507" \
  "$work/hadolint"
chmod +x "$work/hadolint"

"$work/actionlint" -color
"$work/shellcheck-v0.11.0/shellcheck" scripts/*.sh
"$work/hadolint" Containerfile
