# Releasing

A release is a tag. The tag must match the `version` in
`supervisor/Cargo.toml`; the publish workflow verifies it.

```sh
git tag v1.2.0
git push origin v1.2.0
```

Or run `publish.yml` by hand. A tag push publishes both architectures, their
per-arch images, and the multi-arch manifest on
`ghcr.io/edgarcnp/vaultwarden-hummingbird`, with provenance and SPDX SBOM
attestations. A manual dispatch publishes the ref name alone and does not move
`:latest`.

The workflow never changes versions itself. Bump upstream versions first (via
Renovate or `scripts/update-pins.sh`) and let CI confirm the digests before you
tag.

## Retention

ghcr.io has no retention setting, and a tag cannot outlive the image it points
at. The prune job deletes older releases whole: manifest list, both per-arch
images, the attestation index, and the untagged provenance/SBOM payloads.
It keeps the three newest releases plus `:latest`.

- A kept release keeps its payloads, because `gh attestation verify` reads
  them.
- A version carrying a tag the prune cannot attribute (for example a manual
  dispatch's `main`) is never touched.
- A version past 5,000 downloads is refused by GitHub and reported as a
  warning.

Between releases, run the `Prune` workflow by hand (dry run by default), or
rehearse locally:

```sh
scripts/prune-image-versions.sh --keep 3 --dry-run
```

## Verify a release

```sh
podman manifest inspect ghcr.io/edgarcnp/vaultwarden-hummingbird:v1.2.0
podman pull ghcr.io/edgarcnp/vaultwarden-hummingbird:v1.2.0
podman image inspect --format '{{json .Config.Healthcheck}}' \
  ghcr.io/edgarcnp/vaultwarden-hummingbird:v1.2.0
podman image inspect --format '{{.Labels}}' \
  ghcr.io/edgarcnp/vaultwarden-hummingbird:v1.2.0
```

The labels should name the release version and the tagged commit, not the
Hummingbird base values.

Check the publish workflow run and its attestations. Both the Image workflow
(on build-context changes) and publish (on each release, both architectures)
run the fail-closed smoke suite. Do not claim a release is healthy until that
run is green and the published image pulls.

## Rolling back a bad release

Images are immutable. Do not move or reuse a tag. Publish a new patch release
with the fix; the retention job keeps the previous two releases available for
pinning in the meantime.

If the problem is in the build pins, revert the pin commit and tag the patch.
If the problem is in the supervisor, revert the commit and tag the patch. Keep
the database manifest generation in mind: a `v2` bucket is not readable by a
`v1`-era image. See [backup rollback](backup.md#rollback-compatibility).
