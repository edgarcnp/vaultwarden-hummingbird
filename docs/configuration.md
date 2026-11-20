# Configuration

The container reads configuration from two sources:

1. the container environment (`-e`, `--env-file`, or your platform's settings);
2. a dotenv file named by `SUPERVISOR_ENV_FILE`, normally mounted at
   `/state/.env`.

The environment wins over the file, and the file wins over built-in defaults.
An empty value means "unset".

## Key namespaces

Every key must belong to one of three namespaces.

| Prefix | Consumer | Rules |
| --- | --- | --- |
| `TAILSCALE_*` | supervisor and tailscaled | Closed set. An unknown key refuses the boot. |
| `SUPERVISOR_*` | supervisor | Closed set. An unknown key refuses the boot. |
| `VAULTWARDEN_*` | vaultwarden | The prefix is stripped: `VAULTWARDEN_SIGNUPS_ALLOWED` becomes `SIGNUPS_ALLOWED`. Unknown keys pass through to Vaultwarden. |

In the dotenv file, a key outside those prefixes refuses the boot and names the
offender; that strictness catches typos. Values passed in the container
environment are filtered instead: only `VAULTWARDEN_*` keys reach the vault,
and unknown supervisor keys are ignored.

## The dotenv file

Copy [`.env.example`](../.env.example) and fill in the values. The file is the
recommended place for secrets because it is not visible in `podman inspect`.

The file must:

- live under `/state`;
- stay outside `/state/tailscale` and `/state/tailscale-state`, which the
  tailscaled user can write;
- be a regular file, not a symlink (Kubernetes secret projections are
  symlinks; copy them to a volume first);
- be readable by container uid `65532`.

Use `0600` owned by `65532`, or `0640` with group `65532`. The default `0644`
works but the supervisor logs a warning, because the tailscaled group can
traverse `/state` and read a world-readable file.

On a rootful runtime:

```sh
sudo chown 65532:65532 .env
sudo chmod 600 .env
```

On rootless Podman, change ownership inside the user namespace:

```sh
podman unshare chown 65532:65532 .env
podman unshare chmod 600 .env
```

Other rules:

- `SUPERVISOR_ENV_FILE` is read from the process environment only. Putting it
  in the file itself refuses the boot.
- An unquoted `$VAR` is substituted from the container environment. Use single
  quotes to keep a literal `$`.
- Never reference `TAILSCALE_AUTHKEY` or a `SUPERVISOR_S3_*` secret from a
  `VAULTWARDEN_*` value. The substitution would copy the secret into the
  vault's environment.
- Quote values that contain `#`.

## Required values

- `TAILSCALE_AUTHKEY`: an auth key, unless the node identity already exists on
  `/state` or can be restored from S3.
- `VAULTWARDEN_DOMAIN`: the HTTPS address Tailscale serves, for example
  `https://vaultwarden-hummingbird.your-tailnet.ts.net`. It must match the
  `*.ts.net` name produced by MagicDNS and HTTPS certificates.

## Tailscale

| Key | Default | Purpose |
| --- | --- | --- |
| `TAILSCALE_AUTHKEY` | none | Auth key or OAuth client secret. |
| `TAILSCALE_HOSTNAME` | `vaultwarden-hummingbird` | Node name in the tailnet. |
| `TAILSCALE_SERVE` | `true` | Publish the vault over tailnet HTTPS. Needs MagicDNS and HTTPS certificates. `false` runs without the `*.ts.net` address. |
| `TAILSCALE_SERVICE` | none | Advertise the vault as a Tailscale Service. Needs a tag-based auth key and approval in the admin console. |
| `TAILSCALE_USERSPACE` | `true` | Userspace networking, no extra privileges. `false` uses TUN mode: slightly faster, needs `NET_ADMIN`, sometimes `NET_RAW`, and `/dev/net/tun`. Rootless Podman cannot create a TUN in its user namespace. |
| `TAILSCALE_SOCKET` | `/state/tailscale/tailscaled.sock` | LocalAPI socket. Must be under `/state/tailscale`. |
| `TAILSCALE_STATE_FILE` | `/state/tailscale-state/tailscaled.state` | Node identity. Must be a direct child of the link directory, or `mem:` for an in-memory identity. A legacy direct child of `/state/tailscale` is mapped onto the link. |

## Supervisor

| Key | Default | Purpose |
| --- | --- | --- |
| `SUPERVISOR_ENV_FILE` | none | Dotenv file to load. Process environment only. |
| `SUPERVISOR_EPHEMERAL` | `false` | Declare temporary storage. When true, an explicitly configured but unusable S3 or backup setting refuses the boot instead of silently losing persistence. A tmpfs `/data` and `I_REALLY_WANT_VOLATILE_STORAGE` are detected too. |

### S3 state sync

| Key | Default | Purpose |
| --- | --- | --- |
| `SUPERVISOR_S3_REMOTE` | none | `label:bucket[/prefix]`. The label is accepted for compatibility and ignored. The bucket must already exist. |
| `SUPERVISOR_S3_ACCESS_KEY_ID` | none | Access key. |
| `SUPERVISOR_S3_SECRET_ACCESS_KEY` | none | Secret key. |
| `SUPERVISOR_S3_ENDPOINT` | none | Required. No provider is a default, AWS included. A bare host uses HTTPS. |
| `SUPERVISOR_S3_SYNC_INTERVAL` | `3600` | Seconds between periodic pushes. `0` disables the periodic cadence. Values above seven days fall back to the default. |
| `SUPERVISOR_S3_URL_STYLE` | `path` | `path` works with every provider; `virtual` uses virtual-hosted bucket URLs (AWS). |
| `SUPERVISOR_S3_REGION` | derived | Derived from AWS endpoints; `auto` elsewhere. Set it only when a provider needs another value. |
| `SUPERVISOR_S3_CA_FILE` | none | PEM bundle replacing the built-in roots. Must be under `/state`, outside the tailscaled-writable subtree, and contain the full chain the endpoint presents. |
| `SUPERVISOR_S3_ALLOW_HTTP` | `false` | Permit plaintext HTTP to a non-loopback endpoint. Loopback is always allowed. Use only on a trusted private network. |

The access key needs object read, write, and delete, plus bucket listing
(`ListObjectsV2`). The client never creates or heads the bucket; one object
`HEAD` verifies that the newest backup still exists.

Examples:

```sh
# Cloudflare R2
SUPERVISOR_S3_REMOTE=r2:vaultwarden
SUPERVISOR_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com

# MinIO on a private network (plain HTTP is opt-in)
SUPERVISOR_S3_REMOTE=minio:vaultwarden
SUPERVISOR_S3_ENDPOINT=http://minio.internal:9000
SUPERVISOR_S3_ALLOW_HTTP=true

# AWS S3
SUPERVISOR_S3_REMOTE=aws:vaultwarden
SUPERVISOR_S3_ENDPOINT=https://s3.us-east-1.amazonaws.com
SUPERVISOR_S3_URL_STYLE=virtual
```

### Database backups

| Key | Default | Purpose |
| --- | --- | --- |
| `SUPERVISOR_DB_BACKUP` | `false` | Enable scheduled dumps. Requires the S3 settings above. |
| `SUPERVISOR_DB_BACKUP_INTERVAL` | `21600` | Seconds between dumps. `0` or more than seven days falls back to the default. |
| `SUPERVISOR_DB_BACKUP_KEEP` | `3` | Dumps to keep. `0` or more than `1000` falls back to the default. |
| `SUPERVISOR_DB_BACKUP_RESTORE` | `false` | At boot, load the newest usable dump into an empty database. Never overwrites existing data. |

See [backups](backup.md) for the dump, manifest, and restore rules.

## Vaultwarden

Any upstream Vaultwarden key works with the `VAULTWARDEN_` prefix. The
[upstream `.env.template`](https://github.com/dani-garcia/vaultwarden/blob/1.37.5/.env.template)
lists every key. Since 1.37.5, an invalid value refuses the vault at startup
instead of being coerced, so a rejected setting appears in the container log.

Special cases:

- `VAULTWARDEN_PORT` (default `8080`) is the public gate port. The vault itself
  binds loopback on the next port (`8081` by default).
- `VAULTWARDEN_DATABASE_URL` must stay SQLite. The image is built with SQLite
  only; the default is `sqlite:///data/db.sqlite3`.
- `ROCKET_PORT` and `VAULTWARDEN_ROCKET_PORT` are refused. Use
  `VAULTWARDEN_PORT`.

Image defaults you may want to change:

| Key | Image default | Effect |
| --- | --- | --- |
| `VAULTWARDEN_SIGNUPS_ALLOWED` | `true` | Set `false` after creating accounts. |
| `VAULTWARDEN_ORG_ATTACHMENT_LIMIT` | `0` | Organization attachments disabled. |
| `VAULTWARDEN_USER_ATTACHMENT_LIMIT` | `0` | Personal attachments disabled. |
| `VAULTWARDEN_SENDS_ALLOWED` | `true` | Bitwarden Sends enabled. |
| `VAULTWARDEN_WEB_VAULT_ENABLED` | `true` | Web vault included. |
| `VAULTWARDEN_ADMIN_TOKEN` | none | `/admin` stays disabled until set. |

`VAULTWARDEN_WEB_VAULT=false` is a build argument, not a runtime key: it bakes
an API-only image with no web vault files.

## Path rules

The supervisor owns `/state`. Two settings name paths inside it, and both are
validated before the boot:

- `TAILSCALE_STATE_FILE` must be `mem:` or a direct child of
  `/state/tailscale-state`. That directory is a supervisor-created symlink to
  `/state/tailscale`; the different name keeps Tailscale from changing the real
  tree to `0700`.
- `TAILSCALE_SOCKET` must be a normal path under `/state/tailscale`, not the
  directory itself.
- `SUPERVISOR_S3_CA_FILE` must be under `/state` and outside the
  tailscaled-writable subtree.

A custom identity file cannot use a name the supervisor reserves (for example
`manifest`, `tombstones`, `db`, `objects`, `certs`, `attachments`, `sends`, or
a backup sidecar). Such a name refuses the boot.

## Migrating from an older image

- Prefix every bare Vaultwarden key with `VAULTWARDEN_`.
- Rename `ROCKET_PORT` or `VAULTWARDEN_ROCKET_PORT` to `VAULTWARDEN_PORT`.
- Move `.env` to `/state/.env`; a dotenv file elsewhere is refused.
- Add the `/state` volume and the new capabilities. See
  [operations](operations.md#upgrading).
