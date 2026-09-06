# Vaultwarden configuration reference

Extracted from vaultwarden's `.env.template` at tag **1.37.2** — the version compiled into this image. Values shown are the shipped defaults; every line ships commented out upstream.

Build-base notes (Hummingbird repo gaps this repo works around): no `libpq` client package (=> `pq-sys/bundled` compiles libpq via the official Kitware cmake tarball, since the in-repo cmake RPM is broken); `perl` is too fragmented for OpenSSL's `Configure` (=> links distro `libssl.so.3` instead of vendored OpenSSL).

## How configuration works in this deployment

- **Env vars are the interface.** Keys below are set as env vars (exact uppercase names) in `render.yaml` / the Render dashboard. Unknown env vars are silently ignored — a typo (or a nonexistent flag) does nothing.
- **Admin panel edits are lost on Render.** The `/admin` panel writes `/data/config.json`, and **config.json overrides env vars** (vaultwarden prints a startup warning naming the overridden keys). `/data` is ephemeral here, so the panel is only useful for throwaway experiments — real values belong in env vars.
- In `config.json`, the same keys appear camelCase (`signupsAllowed`, `databaseUrl`, `smtpHost`).
- Some keys are env-only and never appear in the panel (e.g. `ROCKET_ADDRESS`, `ROCKET_PORT`, `ROCKET_TLS`, `DATA_FOLDER`, `ENV_FILE`, `CONFIG_FILE`).
- The supervisor sets `ROCKET_PORT` for vaultwarden: Render's `PORT` wins, then an explicit `ROCKET_PORT`, else 8080 (non-root can't bind 80).

## Keys set by this repo

Image-baked defaults (env vars override them): `SIGNUPS_ALLOWED=false`, `ORG_CREATION_USERS=none`, `USER_ATTACHMENT_LIMIT=0`, `ORG_ATTACHMENT_LIMIT=0`, `WEB_VAULT_ENABLED` (per `WEB_VAULT` build arg), `DATA_FOLDER=/data`, `ROCKET_ADDRESS=0.0.0.0`. The same keys + secrets are set per-environment: see `.env.example` (the one universal dotenv file); `render.yaml` only carries Render wiring and deploy-time secret prompts.

| Key | Where | Notes |
| --- | --- | --- |
| `DATABASE_URL` | secret | external Postgres connection string |
| `DOMAIN` | dashboard/.env | `https://<service>.onrender.com` or your domain |
| `TS_AUTHKEY` | secret | not a vaultwarden key — consumed by the supervisor (Tailscale auth key or OAuth client secret) |
| `SIGNUPS_ALLOWED` | image default `false` | flip to `true` to create your account, then flip back |
| `ORG_CREATION_USERS` | image default `none` | personal instance: blocks organization creation |
| `USER_ATTACHMENT_LIMIT` | image default `0` | disables attachment uploads (Taildrop is used instead) |
| `ORG_ATTACHMENT_LIMIT` | image default `0` | disables org attachment uploads (orgs are disabled anyway) |
| `I_REALLY_WANT_VOLATILE_STORAGE` | `true` | required for ephemeral `/data` (Render; set `false` with a real volume) |
| `PUSH_ENABLED` | optional | flip to `true` after setting the two keys below |
| `PUSH_INSTALLATION_ID` | secret | free from https://bitwarden.com/host |
| `PUSH_INSTALLATION_KEY` | secret | free from https://bitwarden.com/host |

Note: upstream has **no** `ATTACHMENTS_ENABLED` key — setting it does nothing (unknown env vars are ignored). The storage limits above are the supported way to disable attachments. `I_REALLY_WANT_VOLATILE_STORAGE` is a boot-time check flag, not a `config.rs` setting, so it does not appear in the list below.

The Dockerfile ships no web-vault files by default (`WEB_VAULT` build arg, default `false`, which bakes in `WEB_VAULT_ENABLED=false`): vaultwarden's `check_web_vault()` skips the `index.html` existence check when disabled, so the container boots without the static files. Browser access to `/` or `/admin` serves nothing; use the Bitwarden apps. Rebuild with `--build-arg WEB_VAULT=true` to include the browser vault.

## Admin panel

`/admin` is disabled until `ADMIN_TOKEN` is set (dashboard secret). Generate the Argon2 hash with:

    docker run --rm -it vaultwarden/server:latest /vaultwarden hash

Panel changes are saved to `/data/config.json`, which is ephemeral on Render — see above.

## Full key list (139 keys, grouped as in `.env.template`)

### Data folders

```ini
DATA_FOLDER=data
RSA_KEY_FILENAME=data/rsa_key
ICON_CACHE_FOLDER=data/icon_cache
ATTACHMENTS_FOLDER=data/attachments
SENDS_FOLDER=data/sends
TMP_FOLDER=data/tmp
TEMPLATES_FOLDER=data/templates
RELOAD_TEMPLATES=false
WEB_VAULT_FOLDER=web-vault/
WEB_VAULT_ENABLED=true
```

### Database settings

```ini
DATABASE_URL=sqlite://data/db.sqlite3
ENABLE_DB_WAL=true
DB_CONNECTION_RETRIES=15
DATABASE_TIMEOUT=30
DATABASE_IDLE_TIMEOUT=600
DATABASE_MIN_CONNS=2
DATABASE_MAX_CONNS=10
DATABASE_CONN_INIT=""
```

### WebSocket

```ini
ENABLE_WEBSOCKET=true
```

### Push notifications

```ini
PUSH_ENABLED=false
PUSH_INSTALLATION_ID=CHANGEME
PUSH_INSTALLATION_KEY=CHANGEME
PUSH_RELAY_URI=https://push.bitwarden.com
PUSH_IDENTITY_URI=https://identity.bitwarden.com
```

### Schedule jobs

```ini
JOB_POLL_INTERVAL_MS=30000
SEND_PURGE_SCHEDULE="0 5 * * * *"
TRASH_PURGE_SCHEDULE="0 5 0 * * *"
INCOMPLETE_2FA_SCHEDULE="30 * * * * *"
EMERGENCY_NOTIFICATION_REMINDER_SCHEDULE="0 3 * * * *"
EMERGENCY_REQUEST_TIMEOUT_SCHEDULE="0 7 * * * *"
EVENT_CLEANUP_SCHEDULE="0 10 0 * * *"
EVENTS_DAYS_RETAIN=
AUTH_REQUEST_PURGE_SCHEDULE="30 * * * * *"
DUO_CONTEXT_PURGE_SCHEDULE="30 * * * * *"
PURGE_INCOMPLETE_SSO_AUTH="0 20 0 * * *"
```

### General settings

```ini
DOMAIN=http://localhost
SENDS_ALLOWED=true
HIBP_API_KEY=
ORG_ATTACHMENT_LIMIT=
USER_ATTACHMENT_LIMIT=
USER_SEND_LIMIT=
TRASH_AUTO_DELETE_DAYS=
INCOMPLETE_2FA_TIME_LIMIT=3
DISABLE_ICON_DOWNLOAD=false
SIGNUPS_ALLOWED=true
SIGNUPS_VERIFY=false
SIGNUPS_VERIFY_RESEND_TIME=3600
SIGNUPS_VERIFY_RESEND_LIMIT=6
SIGNUPS_DOMAINS_WHITELIST=example.com,example.net,example.org
ORG_EVENTS_ENABLED=false
ORG_CREATION_USERS=
INVITATIONS_ALLOWED=true
INVITATION_ORG_NAME=Vaultwarden
INVITATION_EXPIRATION_HOURS=120
EMERGENCY_ACCESS_ALLOWED=true
EMAIL_CHANGE_ALLOWED=true
PASSWORD_ITERATIONS=600000
PASSWORD_HINTS_ALLOWED=true
SHOW_PASSWORD_HINT=false
```

### Client settings

```ini
CLIENT_SUPPRESS_ONBOARDING=false
```

### Advanced settings

```ini
IP_HEADER=X-Real-IP
IP_HEADER_TRUSTED_PROXIES=local
ICON_SERVICE=internal
ICON_REDIRECT_CODE=302
ICON_CACHE_TTL=2592000
ICON_CACHE_NEGTTL=259200
ICON_DOWNLOAD_TIMEOUT=10
HTTP_REQUEST_BLOCK_REGEX='^(192\.168\.0\.[0-9]+|192\.168\.1\.[0-9]+)$'
HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS=true
EXPERIMENTAL_CLIENT_FEATURE_FLAGS=
REQUIRE_DEVICE_EMAIL=false
EXTENDED_LOGGING=true
LOG_TIMESTAMP_FORMAT="%Y-%m-%d %H:%M:%S.%3f"
USE_SYSLOG=false
LOG_FILE=/path/to/log
LOG_LEVEL=info
ADMIN_TOKEN='$argon2id$v=19$m=65540,t=3,p=4$MmeKRnGK5RW5mJS7h3TOL89GrpLPXJPAtTK8FTqj9HM$DqsstvoSAETl9YhnsXbf43WeaUwJC6JhViIvuPoig78'
DISABLE_ADMIN_TOKEN=false
ADMIN_RATELIMIT_SECONDS=300
ADMIN_RATELIMIT_MAX_BURST=3
ADMIN_SESSION_LIFETIME=20
ALLOWED_IFRAME_ANCESTORS=
ALLOWED_CONNECT_SRC=""
LOGIN_RATELIMIT_SECONDS=60
LOGIN_RATELIMIT_MAX_BURST=10
UNAUTHENTICATED_RATELIMIT_SECONDS=60
UNAUTHENTICATED_RATELIMIT_MAX_BURST=50
ORG_GROUPS_ENABLED=false
INCREASE_NOTE_SIZE_LIMIT=false
ENFORCE_SINGLE_ORG_WITH_RESET_PW_POLICY=false
DNS_PREFER_IPV6=false
```

### SSO settings (OpenID Connect)

```ini
SSO_ENABLED=false
SSO_ONLY=false
SSO_SIGNUPS_MATCH_EMAIL=true
SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=false
SSO_AUTHORITY=https://auth.example.com
SSO_SCOPES="email profile"
SSO_AUTHORIZE_EXTRA_PARAMS="access_type=offline&prompt=consent"
SSO_PKCE=true
SSO_AUDIENCE_TRUSTED='^$'
SSO_CLIENT_ID=11111
SSO_CLIENT_SECRET=AAAAAAAAAAAAAAAAAAAAAAAA
SSO_MASTER_PASSWORD_POLICY='{"enforceOnLogin":false,"minComplexity":3,"minLength":12,"requireLower":false,"requireNumbers":false,"requireSpecial":false,"requireUpper":false}'
SSO_AUTH_ONLY_NOT_SESSION=false
SSO_CLIENT_CACHE_EXPIRATION=0
SSO_DEBUG_TOKENS=false
```

### MFA/2FA settings

```ini
YUBICO_CLIENT_ID=11111
YUBICO_SECRET_KEY=AAAAAAAAAAAAAAAAAAAAAAAA
YUBICO_SERVER=http://yourdomain.com/wsapi/2.0/verify
DUO_IKEY=<Client ID>
DUO_SKEY=<Client Secret>
DUO_HOST=<API Hostname>
DUO_USE_IFRAME=false
EMAIL_TOKEN_SIZE=6
EMAIL_EXPIRATION_TIME=600
EMAIL_ATTEMPTS_LIMIT=3
EMAIL_2FA_ENFORCE_ON_VERIFIED_INVITE=false
EMAIL_2FA_AUTO_FALLBACK=false
DISABLE_2FA_REMEMBER=false
AUTHENTICATOR_DISABLE_TIME_DRIFT=false
```

### SMTP Email settings

```ini
SMTP_HOST=smtp.domain.tld
SMTP_FROM=vaultwarden@domain.tld
SMTP_FROM_NAME=Vaultwarden
SMTP_USERNAME=username
SMTP_PASSWORD=password
SMTP_TIMEOUT=15
SMTP_SECURITY=starttls
SMTP_PORT=587
USE_SENDMAIL=false
SENDMAIL_COMMAND="/path/to/sendmail"
SMTP_AUTH_MECHANISM=
HELO_NAME=
SMTP_EMBED_IMAGES=true
SMTP_DEBUG=false
SMTP_ACCEPT_INVALID_CERTS=false
SMTP_ACCEPT_INVALID_HOSTNAMES=false
```

### Rocket settings

```ini
ROCKET_ADDRESS=0.0.0.0
ROCKET_PORT=8000
ROCKET_TLS={certs="/path/to/certs.pem",key="/path/to/key.pem"}
```

Source: https://github.com/dani-garcia/vaultwarden/blob/1.37.2/.env.template
