#!/usr/bin/env bash
# Retention for the ghcr.io package: keep the newest N releases and delete the
# older ones - manifest list, per-arch manifests, attestation index, and the
# untagged attestation payloads a pruned release leaves behind.
#
# ghcr.io has no retention setting - a package version lives until something
# deletes it - and no "drop the image, keep the tag" operation either: a tag
# is a pointer to a manifest, so a version is pruned whole or not at all.
# That is why this script decides on versions and prints the tags they carry.
#
# What a release owns: a tag `X.Y.Z` (or `X.Y.Z-<prerelease>`; publish.yml
# strips the `v` from the git tag), the two per-arch tags `vX.Y.Z-amd64` and
# `vX.Y.Z-arm64`, and the attestation index tagged `sha256-<digest of the
# manifest list>`. The newest list also carries `:latest`, which therefore
# never falls into the prune set.
#
# Safety: a version carrying tags is deleted only when *all* of them are in the
# computed prune set, so a tag the script cannot attribute - a manual
# dispatch's `main`, a hand-pushed image - keeps its version. An untagged
# version goes only when no live index points at it: that is what collects the
# attestation payloads of a pruned release while the kept releases keep
# theirs. GitHub refuses to delete a public package version with more than
# 5,000 downloads (documented API limit): reported as a warning, any other
# failure fails the run.
#
# Pruning a version also deletes its attestations, so `gh attestation verify`
# stops working for the pruned releases: keep enough releases that a verifier
# can still check what it is running.
#
# Requires: curl, jq, GH_TOKEN with admin on the package (GitHub grants that
# to the repository whose workflow publishes it) and GITHUB_REPOSITORY
# (`owner/name`) - the package name is the repository name, lowercased.
# PRUNE_API_URL and PRUNE_REGISTRY_URL override the two endpoints (offline
# rehearsal against a stub).
#
# Usage:
#   scripts/prune-image-versions.sh --keep 3 --dry-run
#   scripts/prune-image-versions.sh --keep 3
#   scripts/prune-image-versions.sh --keep 3 --versions-file captured.json

set -euo pipefail

api_url=${PRUNE_API_URL:-https://api.github.com}
registry_url=${PRUNE_REGISTRY_URL:-https://ghcr.io}

keep=3
dry_run=false
versions_file=

usage() {
  cat <<'EOF'
usage: prune-image-versions.sh [--keep N] [--dry-run] [--versions-file FILE]

  --keep N           how many of the newest releases to keep (default 3)
  --dry-run          report the plan and delete nothing
  --versions-file F  rehearse offline against a captured `GET .../versions`
                     response instead of listing the package (needs --dry-run)
EOF
}

while [ $# -gt 0 ]; do
  case $1 in
    --keep)
      keep=${2:-}
      shift 2
      ;;
    --keep=*)
      keep=${1#*=}
      shift
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --versions-file)
      versions_file=${2:-}
      shift 2
      ;;
    --versions-file=*)
      versions_file=${1#*=}
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "prune: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! [[ $keep =~ ^[1-9][0-9]*$ ]]; then
  echo "prune: --keep wants a positive integer, got '${keep:-<empty>}'" >&2
  exit 2
fi

: "${GH_TOKEN:?prune: GH_TOKEN is required (a token with admin on the package)}"
: "${GITHUB_REPOSITORY:?prune: GITHUB_REPOSITORY (owner/name) is required}"

owner=${GITHUB_REPOSITORY%%/*}
repo_name=${GITHUB_REPOSITORY#*/}
# ghcr.io rejects uppercase in image paths, and the package name is the
# lowercased repository name (publish.yml normalizes the same way).
package=$(printf '%s' "$repo_name" | tr '[:upper:]' '[:lower:]')
image="$registry_url/$owner/$package"

tmpdir=$(mktemp -d)
# The working files are removed on every exit path.
trap 'rm -rf "$tmpdir"' EXIT

api() { # api METHOD PATH -> the response body; fails on 4xx/5xx
  local method=$1 path=$2 status
  local out="$tmpdir/response"
  status=$(curl -sS --max-time 60 -o "$out" -w '%{http_code}' -X "$method" \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$api_url$path")
  if [[ $status != 2* ]]; then
    echo "prune: $method $path failed: HTTP $status: $(head -c 400 "$out")" >&2
    return 1
  fi
  cat "$out"
}

token=
registry_token() { # a pull token for the package, fetched once
  if [ -z "$token" ]; then
    token=$(curl -fsS --max-time 60 -u "${GITHUB_ACTOR:-git}:$GH_TOKEN" \
      "$registry_url/token?scope=repository:$owner/$package:pull&service=ghcr.io" |
      jq -r '.token // empty')
    if [ -z "$token" ]; then
      echo "prune: could not get a registry pull token for $image" >&2
      return 1
    fi
  fi
  printf '%s\n' "$token"
}

manifest_digest() { # manifest_digest TAG -> the digest a tag points at
  local tag=$1 bearer
  bearer=$(registry_token) || return 1
  curl -fsSI --max-time 60 \
    -H "Authorization: Bearer $bearer" \
    -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
    "$registry_url/v2/$owner/$package/manifests/$tag" |
    tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" { print $2; exit }'
}

index_children() { # index_children REF -> child digests (sha256: stripped), one per line
  local bearer
  bearer=$(registry_token) || return 1
  curl -fsS --max-time 60 \
    -H "Authorization: Bearer $bearer" \
    -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" \
    "$registry_url/v2/$owner/$package/manifests/$1" |
    jq -r '.manifests[]?.digest | sub("^sha256:"; "")'
}

if [ -n "$versions_file" ]; then
  if [ ! -f "$versions_file" ]; then
    echo "prune: no such versions file: $versions_file" >&2
    exit 2
  fi
  # The file replaces the listing only; a rehearsal must not reach the API's
  # delete endpoint by accident.
  if [ "$dry_run" != true ]; then
    echo "prune: --versions-file rehearses offline; add --dry-run" >&2
    exit 2
  fi
  cp "$versions_file" "$tmpdir/versions.json"
else
  owner_type=$(api GET "/users/$owner" | jq -r '.type // empty')
  case $owner_type in
    Organization) scope="/orgs/$owner" ;;
    User) scope="/users/$owner" ;;
    *)
      echo "prune: unexpected owner type '${owner_type:-<empty>}' for '$owner'" >&2
      exit 1
      ;;
  esac

  # Every version, newest first as the API returns them; the listing is only
  # a page at a time.
  page=1
  while :; do
    api GET "$scope/packages/container/$package/versions?per_page=100&page=$page" \
      >"$tmpdir/page-$page.json"
    count=$(jq 'length' "$tmpdir/page-$page.json")
    if [ "$count" -lt 100 ]; then break; fi
    page=$((page + 1))
    if [ "$page" -gt 20 ]; then
      echo "prune: more than 2000 versions; refusing to guess past that" >&2
      exit 1
    fi
  done
  jq -s 'add // []' "$tmpdir"/page-*.json >"$tmpdir/versions.json"
fi

# A release tag: X.Y.Z, with an optional prerelease suffix (publish.yml
# publishes the git tag with its `v` stripped, `main` on a manual dispatch).
release_re='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'

releases=$(jq -r '.[].metadata.container.tags[]?' "$tmpdir/versions.json" |
  grep -E "$release_re" | sort -u | sort -V || true)
total_releases=$(grep -c . <<<"$releases" || true)

# No release tag at all usually means the package name or the owner is wrong.
# Report it rather than dying on a grep that matched nothing: there is nothing
# to delete either way.
if [ "$total_releases" -eq 0 ]; then
  echo "prune: $image has no release tags (X.Y.Z); nothing to prune"
  exit 0
fi
kept=$(tail -n "$keep" <<<"$releases")
pruned=$(head -n "-$keep" <<<"$releases") # GNU head: all but the last $keep

# The prune set: every tag a pruned release owns. Anything outside it is kept,
# so a version has to be identifiable as an old release to be deleted.
prune_tags="$tmpdir/prune-tags.txt"
: >"$prune_tags"
while read -r release; do
  [ -n "$release" ] || continue
  printf '%s\n' "$release" "v$release-amd64" "v$release-arm64" >>"$prune_tags"
  digest=$(manifest_digest "$release") || digest=
  if [ -n "$digest" ]; then
    printf 'sha256-%s\n' "${digest#sha256:}" >>"$prune_tags"
  else
    echo "prune: warning: no manifest digest for tag $release; its attestation version stays" >&2
  fi
done <<<"$pruned"

prune_json=$(jq -R -s 'split("\n") | map(select(length > 0))' "$prune_tags")

tagged_plan="$tmpdir/tagged-plan.tsv"
jq -r --argjson prune "$prune_json" '
    .[]
    | { id, tags: (.metadata.container.tags // []) }
    | select((.tags | length) > 0)
    | select([.tags[] as $t | ($prune | index($t)) != null] | all)
    | [.id, (.tags | join(" "))] | @tsv' "$tmpdir/versions.json" >"$tagged_plan"
skipped=$(
  jq --argjson prune "$prune_json" '
    [ .[]
      | { id, tags: (.metadata.container.tags // []) }
      | select((.tags | length) > 0)
      | select([.tags[] as $t | ($prune | index($t)) != null] | all | not)
    ]' "$tmpdir/versions.json"
)

# --- untagged versions -------------------------------------------------------
# A pruned release leaves its attestation payloads behind: the sigstore bundles
# carry no tag, so the tag pass cannot see them and ghcr keeps them forever.
# They are collected here - every version without tags that no live index
# points at. What a kept release needs stays: the children of its tagged
# sha256-<digest> index, and the index GitHub pushes in front of it, are what
# `gh attestation verify` reads.
protected="$tmpdir/protected.txt"
: >"$protected"
while read -r tag; do
  [ -n "$tag" ] || continue
  case $tag in
    sha256-* | [0-9]*) : ;;
    *) continue ;; # per-arch tags, `latest`, a dispatch's `main`: nothing to protect
  esac
  # An index this run deletes protects nothing, so a rehearsal sees exactly
  # what the run would do.
  grep -qxF "$tag" "$prune_tags" && continue
  index_children "$tag" >>"$protected" ||
    echo "prune: warning: could not read the children of $tag; its payloads stay" >&2
done < <(jq -r '.[].metadata.container.tags[]?' "$tmpdir/versions.json" | sort -u)
sort -u -o "$protected" "$protected"

untagged_plan="$tmpdir/untagged-plan.tsv"
: >"$untagged_plan"
while IFS=$'\t' read -r id name; do
  [ -n "${id:-}" ] || continue
  # Without a digest for a name there is nothing to attribute: leave it alone.
  if ! [[ $name =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "prune: warning: untagged version $id has no digest name ('$name'); left alone" >&2
    continue
  fi
  grep -qxF "${name#sha256:}" "$protected" && continue
  # An index in front of a protected child belongs to a kept attestation.
  kids=$(index_children "$name") || kids=
  if [ -n "$kids" ] && printf '%s\n' "$kids" | grep -qxF -f "$protected"; then
    continue
  fi
  printf '%s\t%s\n' "$id" "$name" >>"$untagged_plan"
done < <(jq -r '.[] | select((.metadata.container.tags // []) | length == 0) | [.id, .name] | @tsv' "$tmpdir/versions.json")

deleted=0
refused=0
failed=0
delete_plan() { # delete_plan LABEL PLAN-FILE (id<TAB>description per line)
  local label=$1 file=$2 id desc status
  while IFS=$'\t' read -r id desc; do
    [ -n "${id:-}" ] || continue
    if [ "$dry_run" = true ]; then
      echo "prune: would delete $label $id ($desc)"
      deleted=$((deleted + 1))
      continue
    fi
    status=$(curl -sS --max-time 60 -o "$tmpdir/response" -w '%{http_code}' -X DELETE \
      -H "Authorization: Bearer $GH_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$api_url${scope:-}/packages/container/$package/versions/$id") || status=000
    if [[ $status = 2* ]]; then
      echo "prune: deleted $label $id ($desc)"
      deleted=$((deleted + 1))
    elif grep -qiE '5,?000 downloads' "$tmpdir/response"; then
      # GitHub's documented refusal; the version stays and the run reports it.
      echo "prune: refused $label $id ($desc): $(head -c 200 "$tmpdir/response")" >&2
      refused=$((refused + 1))
    else
      echo "prune: $label $id ($desc) failed: HTTP $status: $(head -c 400 "$tmpdir/response")" >&2
      failed=$((failed + 1))
    fi
  done <"$file"
}

echo "prune: $image"
echo "prune: keeping $(grep -c . <<<"$kept") release(s): $(tr '\n' ' ' <<<"$kept" | sed 's/ $//')"
if [ -n "$pruned" ]; then
  echo "prune: pruning $(grep -c . <<<"$pruned") older release(s): $(tr '\n' ' ' <<<"$pruned" | sed 's/ $//')"
else
  echo "prune: nothing older than the newest $keep"
fi
jq -r '.[] | "prune: keeping version \(.id) (tags: \(.tags | join(" ")))"' <<<"$skipped"
echo "prune: selected $(grep -c . "$tagged_plan" || true) tagged and $(grep -c . "$untagged_plan" || true) untagged version(s)"

delete_plan tagged "$tagged_plan"
delete_plan untagged "$untagged_plan"

if [ "$dry_run" = true ]; then
  echo "prune: dry run: $deleted version(s) would be deleted, $failed failed"
else
  echo "prune: $deleted deleted, $refused refused, $failed failed"
fi
[ "$failed" -eq 0 ] || exit 1
