# vaultwarden-hummingbird

A Bitwarden-compatible password vault that only your devices can reach.

This image runs [Vaultwarden](https://github.com/dani-garcia/vaultwarden) and
[Tailscale](https://tailscale.com) in one hardened container on Red Hat's
[Hummingbird](https://images.redhat.com/) base. The vault listens on loopback,
Tailscale is the only way in, and the container runs without root, a shell, or
a package manager.

- Works with the Bitwarden apps, browser extensions, and web vault.
- Your vault is never published to the internet; only tailnet devices can open it.
- `/data` holds the vault. `/state` holds the node identity and sync state.
- Optional state sync and SQLite backups to any S3-compatible bucket.
- `amd64` and `arm64` images.

## Requirements

- A [Tailscale](https://tailscale.com) account with MagicDNS and HTTPS
  certificates enabled. Both are switches in the Tailscale admin console.
- Podman or Docker.
- Persistent storage for `/data` and `/state`, or an S3-compatible bucket for
  [state sync](docs/state-sync.md) and database backups when the host wipes
  them. The run command creates two named volumes.

## Quick start

1. Pull the image.

   ```sh
   podman pull ghcr.io/edgarcnp/vaultwarden-hummingbird:latest
   ```

2. Create the configuration file and fill in two values.

   ```sh
   cp .env.example .env
   ```

   - `TAILSCALE_AUTHKEY`: an auth key from the Tailscale admin console.
   - `VAULTWARDEN_DOMAIN`: the address Tailscale will serve, for example
     `https://vaultwarden-hummingbird.your-tailnet.ts.net`.

3. Start the container. The `.env` file is mounted under `/state`, not passed
   as container environment, so its secrets stay out of `podman inspect`.

   ```sh
   podman run -d --name vaultwarden \
     --restart unless-stopped \
     -p 127.0.0.1:8080:8080 \
     -e SUPERVISOR_ENV_FILE=/state/.env \
     -v "$PWD/.env:/state/.env:ro,z" \
     --cap-drop=all \
     --cap-add=SETUID --cap-add=SETGID --cap-add=KILL \
     --cap-add=DAC_READ_SEARCH \
     --security-opt no-new-privileges \
     --read-only --tmpfs /tmp:size=64m \
     -v vw-data:/data -v vw-state:/state \
     ghcr.io/edgarcnp/vaultwarden-hummingbird:latest
   ```

4. From a device on your tailnet, open `VAULTWARDEN_DOMAIN` and create your
   account.

5. Once your accounts exist, set `VAULTWARDEN_SIGNUPS_ALLOWED=false` in `.env`
   and restart:

   ```sh
   podman restart vaultwarden
   ```

The copied `.env` works as-is; the supervisor logs a warning if it is
world-readable. For owner-only permissions, see
[the dotenv file](docs/configuration.md#the-dotenv-file).

The published port answers only `/alive`: `200` when the vault is up, `503`
when it is down, and `403` for everything else.

```sh
curl -i http://127.0.0.1:8080/alive
```

The included `compose.yaml` has the same layout and builds the image locally.
See [operations](docs/operations.md) for compose and bind-mount setups.

## Common settings

| Key | Effect |
| --- | --- |
| `VAULTWARDEN_SIGNUPS_ALLOWED` | Set `false` after you create your accounts. |
| `VAULTWARDEN_ADMIN_TOKEN` | Enables the `/admin` panel; use a long random value. |
| `VAULTWARDEN_USER_ATTACHMENT_LIMIT` | `0` disables attachments; raise it to allow them. |
| `VAULTWARDEN_WEB_VAULT_ENABLED` | `false` hides the web vault; the apps still work. |
| `VAULTWARDEN_PUSH_ENABLED` | Mobile push; needs Bitwarden host credentials. |
| `TAILSCALE_HOSTNAME` | The node name; default `vaultwarden-hummingbird`. |

Every key, default, and rule is in [`.env.example`](.env.example) and the
[configuration guide](docs/configuration.md).

## Keeping data

If `/data` and `/state` are real volumes, you are done. Keep them together:
`/state` holds the node identity that `/data`'s vault belongs to.

If your platform wipes them, configure an S3-compatible bucket. State sync
keeps the node identity, the vault's signing key, `config.json`, attachments,
and Sends; scheduled backups keep the SQLite database. See
[state sync](docs/state-sync.md) and [backups](docs/backup.md).

## Updating

Pull the new image and recreate the container with the same volumes. Pin a
version tag for stability; the registry keeps the three newest releases plus
`:latest`. See [operations](docs/operations.md#upgrading) for the exact steps,
rollback rules, and the one-time layout migration.

## If something is wrong

- **The container exits immediately.** Check the auth key, the domain, and the
  log line `refusing to run the vault without Tailscale`.
- **`/alive` returns `503`.** The vault is not answering; its error is in the
  container log.
- **A backup was skipped.** Nothing was lost; the next cycle retries. The log
  names the S3 setting, free space on `/state`, or the lineage guard.

More cases: [troubleshooting](docs/operations.md#troubleshooting).

## Documentation

| Guide | Contents |
| --- | --- |
| [Configuration](docs/configuration.md) | Keys, precedence, dotenv rules, paths |
| [Architecture](docs/architecture.md) | Processes, identities, volumes, boot, security model |
| [State sync](docs/state-sync.md) | S3 layout, restore, tombstones, garbage collection |
| [Backups](docs/backup.md) | SQLite dumps, manifests, restore, retention |
| [Operations](docs/operations.md) | Deploy, upgrade, rollback, troubleshooting |
| [Development](docs/development.md) | Build, test, source map, house rules |
| [Releasing](docs/releasing.md) | Tags, workflows, image retention |
| [Security policy](SECURITY.md) | Reporting and scope |

## Security and license

Report vulnerabilities through GitHub's private reporting, as described in
[SECURITY.md](SECURITY.md). The S3 bucket is part of your security boundary:
anyone who can write to it can plant a file that looks like a backup.

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
Vaultwarden and Tailscale keep their own licenses.
