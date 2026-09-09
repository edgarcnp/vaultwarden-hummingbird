//! The parsed vaultwarden database URL (`VAULTWARDEN_DATABASE_URL`): a
//! [`DbSpec`] carrying exactly the components the dump/restore tools need.
//! Nothing is logged.

/// The parsed vaultwarden database URL (`VAULTWARDEN_DATABASE_URL`).
/// Variants carry exactly the components the dump/restore tools need;
/// nothing is logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbSpec {
    Postgres {
        /// None = libpq's default (local socket)
        host: Option<String>,
        port: u16,
        user: Option<String>,
        password: Option<String>,
        /// None = server default database
        db: Option<String>,
        /// `sslmode` query parameter, verbatim
        sslmode: Option<String>,
    },
    Mysql {
        host: Option<String>,
        port: u16,
        user: Option<String>,
        password: Option<String>,
        db: Option<String>,
    },
    Sqlite {
        /// absolute or relative path (relative resolves like the child's)
        path: String,
    },
}

impl DbSpec {
    /// Backend label: object-name prefix and prune filter for the backup
    /// bucket prefix.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Postgres { .. } => "postgres",
            Self::Mysql { .. } => "mysql",
            Self::Sqlite { .. } => "sqlite",
        }
    }

    /// Backup file extension for this backend's dump format.
    pub fn ext(&self) -> &'static str {
        match self {
            Self::Postgres { .. } => "dump",
            Self::Mysql { .. } => "sql",
            Self::Sqlite { .. } => "sqlite3",
        }
    }
}
