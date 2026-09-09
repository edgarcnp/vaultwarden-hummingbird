//! Static configuration baked into the image: child binary paths and hard
//! timeouts. No lookups, no env — pure constants.

use std::time::Duration;

// Child binaries baked into the image; no PATH lookup.
pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
pub const VAULTWARDEN: &str = "/vaultwarden";
pub const RCLONE: &str = "/usr/local/bin/rclone";

// DB client tools extracted from the official Red Hat client images. Their
// shared-lib closure lives in DB_TOOL_LIB, on LD_LIBRARY_PATH for these
// tools' invocations only, so the runtime's own libs are never replaced.
pub const PG_DUMP: &str = "/usr/local/lib/dbclients/bin/pg_dump";
pub const PG_RESTORE: &str = "/usr/local/lib/dbclients/bin/pg_restore";
pub const MARIADB_DUMP: &str = "/usr/local/lib/dbclients/bin/mariadb-dump";
pub const MARIADB: &str = "/usr/local/lib/dbclients/bin/mariadb";
pub const DB_TOOL_LIB: &str = "/usr/local/lib/dbclients/lib";

// Hard timeouts: a hung child must never block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
pub const DB_PING_TIMEOUT: Duration = Duration::from_secs(15);
/// One backup/restore phase (dump, import, prune); each rclone call is
/// additionally bounded by SYNC_TIMEOUT.
pub const BACKUP_TIMEOUT: Duration = Duration::from_secs(600);
/// Delay before the first periodic backup after the vault starts.
pub const BACKUP_FIRST_DELAY: Duration = Duration::from_secs(300);

// Default cadences/counts; seconds where applicable.
pub const SYNC_INTERVAL_DEFAULT: u64 = 3600;
pub const BACKUP_INTERVAL_DEFAULT: u64 = 43200;
pub const BACKUP_KEEP_DEFAULT: u64 = 3;

/// Local staging directory (on the data volume) for in-flight dumps and
/// restore pulls; swept before each run and after each restore.
pub const BACKUP_STAGING: &str = "/data/db-backups";
