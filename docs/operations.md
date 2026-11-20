# Operations

## Deploying

The quick-start command in the [README](../README.md) runs the published image
with two named volumes. The included `compose.yaml` has the same layout and
builds the image locally:

```sh
cp .env.example .env
# edit TAILSCALE_AUTHKEY and VAULTWARDEN_DOMAIN
podman compose up -d        # or docker compose up -d
curl -i http://127.0.0.1:8080/alive
```

To use the published image with compose, replace the `build:` block in
`compose.yaml` with:

```yaml
image: ghcr.io/edgarcnp/vaultwarden-hummingbird:latest
```

The compose file sets `stop_grace_period: 180s`, a health check, a read-only
root filesystem with a `/tmp` tmpfs, and the four required capabilities.

## Volumes and permissions

`/data` and `/state` must both persist, and they belong together: `/state`
holds the node identity that `/data`'s vault belongs to. Losing one without the
other can leave a vault that cannot authenticate to the tailnet.

Named volumes inherit the image's ownership and modes on first use. Bind mounts
do not:

- Rootful: the host directories must be owned by uid/gid `65532`.
- Rootless Podman: use `podman unshare chown 65532:65532 <dir>` so the mapped
  uid matches inside the container.
- On an SELinux host, add `:Z` to the mount.

The supervisor refuses to boot rather than run with a state directory the vault
could write into.

## Capabilities

| Capability | Needed by | Why |
| --- | --- | --- |
| `SETUID`, `SETGID` | supervisor | Start `tailscaled` as `65531` and the vault as `65533`. |
| `KILL` | supervisor | Signal children after the uid change. |
| `DAC_READ_SEARCH` | supervisor | Read tailscaled's `0600` identity and certificate files for state sync. |
| `NET_ADMIN` | tailscaled, TUN mode only | Create and configure the TUN device. |
| `NET_RAW` | tailscaled, some TUN setups | Raw socket access. |

Drop everything else. `no-new-privileges` keeps the restriction across exec.
The vault and the `tailscale` CLI receive no capabilities.

Userspace networking is the default and needs none of the network
capabilities. TUN mode is slightly faster but needs `NET_ADMIN`, sometimes
`NET_RAW`, and `/dev/net/tun`; rootless Podman cannot create a TUN in its user
namespace.

## Upgrading

1. Pull the new image.
2. Stop the old container and let it drain. A graceful stop takes a final
   database dump and state push; allow up to 180 seconds.
3. Start the new image with the same `/data` and `/state` volumes.
4. Check `/alive` and the logs.

The first boot of a newer image may migrate the `/data` layout into `/state`.
The migration is one-time and idempotent. A failed copy leaves the source in
place and refuses the boot.

Pin a version tag for production. The registry keeps the three newest releases
plus `:latest`; older tags are pruned after each release.

### Coming from the single-volume layout

The older layout kept the Tailscale identity and sync sidecars on `/data` and
mounted `.env` anywhere. Update the deployment:

- add a persistent `/state` volume;
- move `.env` to `/state/.env` (a dotenv file elsewhere is refused);
- add `SETUID`, `SETGID`, `KILL`, and `DAC_READ_SEARCH` after `cap_drop: ALL`;
- move a custom `TAILSCALE_STATE_FILE` to a direct child of
  `/state/tailscale-state`, and a custom `TAILSCALE_SOCKET` under
  `/state/tailscale`. A legacy state file that is a direct child of
  `/state/tailscale` is mapped onto the link.

On first boot the supervisor:

- moves `tailscaled.state`, `certs/`, and the backup lineage from `/data` to
  `/state`;
- moves the identity and certificates into `/state/tailscale`;
- creates the `tailscale-state` link;
- makes the vault's existing files group-accessible.

Old-layout identity and certificate files must be owned by uid `65532`. A
foreign-owned file is refused rather than adopted. Bucket key names do not
change, so an existing state-sync bucket restores into either layout.

### Rolling back

- An image from before the uid split expects the identity at the old paths.
  Move `/state/tailscale/tailscaled.state` and `/state/tailscale/certs/` back
  to `/state` first. That image does not understand the v3 layout or the link.
- Do not roll back to the first dedicated-uid image (before the state-link
  fix). It cannot change the state directory's mode and runs tailscaled with an
  in-memory store. Keep this image, or roll back past the uid split.
- A database backup manifest written as `v2` cannot be read by a `v1`-era
  supervisor. Keep the image and manifest generation matched, or restore by
  hand. See [backups](backup.md#rollback-compatibility).

## Health and shutdown

The public port answers only `/alive`:

| Response | Meaning |
| --- | --- |
| `200` | The vault answered its own `/alive`. |
| `503` | The gate is up but the vault is not answering. |
| `403` | Any other path or method. |

The image health check runs `/entrypoint --healthcheck`, which probes the same
chain without a shell. Compose repeats it every 60 seconds with a 30-second
start period.

On `SIGTERM`, the supervisor sends `SIGTERM` to the child process groups,
escalates to `SIGKILL` after 10 seconds, then runs the final dump and state
push within 120 seconds. A second stop signal shortens that budget to 15
seconds. A `SIGKILL` from the orchestrator skips the final cycle but leaves the
previous backup intact.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Container exits immediately | The auth key, `VAULTWARDEN_DOMAIN`, and the log line `refusing to run the vault without Tailscale`. With `TAILSCALE_SERVE=true`, a failed serve exits the same way; enable MagicDNS and HTTPS certificates, or set `TAILSCALE_SERVE=false`. |
| `/alive` returns `503` | The vault is not answering, usually the database. Its error is in the container log. |
| `db backup: ... skipped/failed` | That cycle did not run and nothing was lost; the next one retries. The message names S3 settings, free space on `/state`, or the lineage guard (`refusing to shadow it`). |
| State sync cannot read the identity | `DAC_READ_SEARCH` is missing. tailscaled writes its files `0600`; add the capability and restart. |
| Dotenv file refused | It must be a regular file under `/state`, outside `/state/tailscale` and `/state/tailscale-state`, and every `SUPERVISOR_*`/`TAILSCALE_*` key must be known. |
| Bind mount refused | The host directory is not owned by `65532` (or the rootless mapping), or SELinux needs `:Z`. |
| TUN mode fails | Rootless Podman cannot create a TUN. Use userspace mode, or a rootful runtime with `NET_ADMIN`, `NET_RAW`, and `/dev/net/tun`. |
| Push refused | The bucket cannot be proven complete, a mass deletion tripped the guard, or a partial restore left it inconsistent. The log names the reason. |
| `permission denied` under `/state` | A bind mount or restored file has the wrong owner. Use named volumes, or fix the ownership as above. |

More detail: [configuration](configuration.md), [state sync](state-sync.md),
[backups](backup.md).

## Ephemeral hosts

On a platform with temporary storage, use
`TAILSCALE_STATE_FILE=mem:` and an `ephemeral=true` auth key, and configure S3
for the data you want to keep. Set `SUPERVISOR_EPHEMERAL=true` (or use `mem:`)
so an explicitly configured but unusable S3 or backup setting refuses the boot
instead of silently losing persistence.

A tmpfs `/data` and `VAULTWARDEN_I_REALLY_WANT_VOLATILE_STORAGE` are detected
as temporary storage too. Without a real volume or state sync, treat `/data` as
gone on every redeploy.

Run one container per bucket or prefix.
