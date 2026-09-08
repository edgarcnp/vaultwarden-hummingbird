//! Static configuration baked into the image: child binary paths and hard
//! timeouts. No lookups, no env — pure constants.

use std::time::Duration;

/// Hard-coded child binary paths (baked into the image, no PATH lookup).
pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
/// `tailscale` CLI (drives `up`/`serve` over the LocalAPI socket).
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
/// vaultwarden server binary (the payload this container exists to run).
pub const VAULTWARDEN: &str = "/vaultwarden";
/// rclone binary (S3 state sync + DB backup push; baked into the image by
/// the fetch stage).
pub const RCLONE: &str = "/usr/local/bin/rclone";
/// pg_dump binary (postgres DB backup; shipped from the official Red Hat
/// postgres client image).
pub const PG_DUMP: &str = "/usr/local/lib/dbclients/bin/pg_dump";
/// pg_restore binary (postgres DB restore; shipped alongside pg_dump).
pub const PG_RESTORE: &str = "/usr/local/lib/dbclients/bin/pg_restore";
/// mariadb-dump binary (mysql DB backup; shipped from the official Red Hat
/// mariadb client image).
pub const MARIADB_DUMP: &str = "/usr/local/lib/dbclients/bin/mariadb-dump";
/// mariadb client binary (mysql DB restore).
pub const MARIADB: &str = "/usr/local/lib/dbclients/bin/mariadb";
/// Shared-lib closure for the DB client tools, extracted into a private
/// directory so the shell-less runtime's own libs are never replaced; the
/// supervisor sets LD_LIBRARY_PATH for these tools' invocations only.
pub const DB_TOOL_LIB: &str = "/usr/local/lib/dbclients/lib";

/// Hard timeouts: never let a hung tailscaled block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
/// Hard timeout for `tailscale serve`.
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard timeout waiting for tailscaled's LocalAPI socket.
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);
/// Hard timeout for one rclone state-sync operation.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
/// Default cadence (seconds) for periodic state pushes.
pub const SYNC_INTERVAL_DEFAULT: u64 = 3600;
/// Hard timeout for one DB keepalive ping (bounded like every other phase;
/// a hung DB must never stall the watch loop).
pub const DB_PING_TIMEOUT: Duration = Duration::from_secs(15);
/// Hard timeout for one DB backup or restore phase (dump, import, and the
/// dump-side of push/prune orchestration; each rclone call is additionally
/// bounded by SYNC_TIMEOUT).
pub const BACKUP_TIMEOUT: Duration = Duration::from_secs(600);
/// Delay before the first periodic DB backup after the vault starts (a
/// fresh boot does not stall on a dump; the first one follows shortly).
pub const BACKUP_FIRST_DELAY: Duration = Duration::from_secs(300);
/// Default cadence (seconds) for periodic DB dumps.
pub const BACKUP_INTERVAL_DEFAULT: u64 = 43200;
/// Default number of per-backend dumps kept in the bucket.
pub const BACKUP_KEEP_DEFAULT: u64 = 3;
/// Local staging directory (on the data volume) for in-flight dumps and
/// restore pulls; swept before each run and after each restore.
pub const BACKUP_STAGING: &str = "/data/db-backups";
