//! DATABASE_URL parsing into a [`DbSpec`], built on the `url` crate
//! (WHATWG URL semantics, the same family of rules browsers and libpq-ish
//! tooling apply) with `percent-encoding` for component decoding. The
//! components kept are exactly the ones the dump/restore tools need;
//! nothing is logged.

use url::{Host, Url};

/// Stand-in host for the libpq default-socket form (`postgres://u:p@/db`,
/// `postgres://:5432/db`, `postgres:///db`): the `url` crate rejects empty
/// hosts, so those URLs are parsed against this placeholder whose value is
/// discarded — the host is blanked to `None` afterwards.
const EMPTY_HOST: &str = "empty-host.invalid";

/// The parsed vaultwarden DATABASE_URL. Variants carry exactly the
/// components the dump/restore tools need; nothing is logged.
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

/// Parse a DATABASE_URL. `None` = empty, unparseable URL, unrecognized
/// scheme, or malformed port. sqlite URLs are paths after the scheme
/// (`sqlite:///a/b` → `/a/b`); no scheme at all is not sqlite — callers
/// decide the default.
pub fn parse(raw: &str) -> Option<DbSpec> {
    let url = raw.trim();
    let (scheme, rest) = url.split_once("://")?;
    match scheme {
        "postgres" | "postgresql" => net_spec(scheme, url, rest, 5432, false),
        "mysql" | "mariadb" => net_spec(scheme, url, rest, 3306, true),
        "sqlite" => Some(sqlite_spec(rest)),
        _ => None,
    }
}

/// The scheme of a DATABASE_URL (for secret-free logs): the text before
/// `://`, or the whole (malformed) value trimmed to 32 chars.
pub fn scheme_for_log(raw: &str) -> String {
    let raw = raw.trim();
    match raw.split_once("://") {
        Some((s, _)) => s.to_string(),
        None => raw.chars().take(32).collect(),
    }
}

/// Net spec from a parsed URL. An absent/empty port falls back to the
/// backend default; port 0 is malformed (None = fail closed).
fn net_spec(scheme: &str, url: &str, rest: &str, default_port: u16, mysql: bool) -> Option<DbSpec> {
    // The authority is the part of `rest` before the first path/query/
    // fragment separator; the host is what follows the last '@'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let hostpart = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let empty_host = hostpart.is_empty() || hostpart.starts_with(':');
    let parsed = if empty_host {
        let userinfo = &authority[..authority.len() - hostpart.len()];
        let tail = &rest[authority.len()..];
        Url::parse(&format!(
            "{scheme}://{userinfo}{EMPTY_HOST}{hostpart}{tail}"
        ))
        .ok()?
    } else {
        Url::parse(url).ok()?
    };
    let port = match parsed.port() {
        Some(p) if p != 0 => p,
        Some(_) => return None,
        None => default_port,
    };
    let host = if empty_host { None } else { host_of(&parsed) };
    let user = non_empty(&percent_decode_str(parsed.username()));
    let password = parsed.password().map(percent_decode_str);
    let db = non_empty(parsed.path().trim_start_matches('/'));
    let sslmode = (!mysql).then(|| query_param(&parsed, "sslmode")).flatten();
    Some(if mysql {
        DbSpec::Mysql {
            host,
            port,
            user,
            password,
            db,
        }
    } else {
        DbSpec::Postgres {
            host,
            port,
            user,
            password,
            db,
            sslmode,
        }
    })
}

/// sqlite: everything after the scheme is the path, percent-decoded —
/// `sqlite:///a/b` → `/a/b`, `sqlite://a/b` → relative `a/b`. Raw string
/// handling (not `Url`) keeps opaque path shapes intact.
fn sqlite_spec(rest: &str) -> DbSpec {
    DbSpec::Sqlite {
        path: percent_decode_str(rest),
    }
}

/// Host component, decoded (IPv6 literals arrive bracket-stripped from
/// `Host::Ipv6`; domain case is preserved). Empty = None (tool defaults).
fn host_of(url: &Url) -> Option<String> {
    let host = match url.host() {
        Some(Host::Domain(d)) => d.to_string(),
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => ip.to_string(),
        None => String::new(),
    };
    non_empty(&host)
}

/// First `key` query parameter, percent-decoded; empty value = None.
fn query_param(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Percent-decode a URL component; invalid escapes pass through literally
/// and non-UTF-8 bytes are replaced (a mangled credential must fail the
/// connection later, not panic here).
fn percent_decode_str(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg(url: &str) -> DbSpec {
        parse(url).expect("parses")
    }

    #[test]
    fn full_postgres_url() {
        let spec = pg("postgres://user:s3cr%3at@db.example.com:6543/vault?sslmode=require");
        assert_eq!(
            spec,
            DbSpec::Postgres {
                host: Some("db.example.com".into()),
                port: 6543,
                user: Some("user".into()),
                password: Some("s3cr:t".into()),
                db: Some("vault".into()),
                sslmode: Some("require".into()),
            }
        );
        assert_eq!(spec.label(), "postgres");
        assert_eq!(spec.ext(), "dump");
    }

    #[test]
    fn postgresql_scheme_and_defaults() {
        assert_eq!(
            pg("postgresql://u:p@host/db"),
            DbSpec::Postgres {
                host: Some("host".into()),
                port: 5432,
                user: Some("u".into()),
                password: Some("p".into()),
                db: Some("db".into()),
                sslmode: None,
            }
        );
    }

    #[test]
    fn postgres_edge_credentials() {
        // password with raw ':' and '@' — WHATWG splits userinfo at the
        // LAST '@' and keeps raw ':' in the password
        let spec = pg("postgres://us%40er:p%40ss:wo%3Ard@h/db");
        assert_eq!(
            spec,
            DbSpec::Postgres {
                host: Some("h".into()),
                port: 5432,
                user: Some("us@er".into()),
                password: Some("p@ss:wo:rd".into()),
                db: Some("db".into()),
                sslmode: None,
            }
        );
        // no password at all
        let spec = pg("postgres://u@h:5433/db");
        assert_eq!(
            spec,
            DbSpec::Postgres {
                host: Some("h".into()),
                port: 5433,
                user: Some("u".into()),
                password: None,
                db: Some("db".into()),
                sslmode: None,
            }
        );
        // no userinfo: `Url` parses the would-be user as the host
        let spec = pg("postgres://h/db");
        assert_eq!(
            spec,
            DbSpec::Postgres {
                host: Some("h".into()),
                port: 5432,
                user: None,
                password: None,
                db: Some("db".into()),
                sslmode: None,
            }
        );
        // empty host = libpq default socket
        let spec = pg("postgres://u:p@/db");
        assert_eq!(
            spec,
            DbSpec::Postgres {
                host: None,
                port: 5432,
                user: Some("u".into()),
                password: Some("p".into()),
                db: Some("db".into()),
                sslmode: None,
            }
        );
        // empty host with an explicit port still defaults the host
        let spec = pg("postgres://u:p@:5433/db");
        assert_eq!(
            spec,
            DbSpec::Postgres {
                host: None,
                port: 5433,
                user: Some("u".into()),
                password: Some("p".into()),
                db: Some("db".into()),
                sslmode: None,
            }
        );
        // ipv6 host (brackets stripped by `Url`)
        let spec = pg("postgres://u:p@[2001:db8::1]:5432/db");
        assert_eq!(
            spec,
            DbSpec::Postgres {
                host: Some("2001:db8::1".into()),
                port: 5432,
                user: Some("u".into()),
                password: Some("p".into()),
                db: Some("db".into()),
                sslmode: None,
            }
        );
        // db and query can be absent
        let spec = pg("postgres://u:p@h");
        assert_eq!(
            spec,
            DbSpec::Postgres {
                host: Some("h".into()),
                port: 5432,
                user: Some("u".into()),
                password: Some("p".into()),
                db: None,
                sslmode: None,
            }
        );
    }

    #[test]
    fn mysql_and_mariadb_urls() {
        let spec = pg("mysql://root:pw%40@db.local/vault");
        assert_eq!(
            spec,
            DbSpec::Mysql {
                host: Some("db.local".into()),
                port: 3306,
                user: Some("root".into()),
                password: Some("pw@".into()),
                db: Some("vault".into()),
            }
        );
        assert_eq!(spec.label(), "mysql");
        assert_eq!(spec.ext(), "sql");
        let spec = pg("mariadb://u:p@h:3307/db");
        assert_eq!(
            spec,
            DbSpec::Mysql {
                host: Some("h".into()),
                port: 3307,
                user: Some("u".into()),
                password: Some("p".into()),
                db: Some("db".into()),
            }
        );
    }

    #[test]
    fn sqlite_paths() {
        let spec = pg("sqlite:///data/db.sqlite3");
        assert_eq!(
            spec,
            DbSpec::Sqlite {
                path: "/data/db.sqlite3".into()
            }
        );
        assert_eq!(spec.label(), "sqlite");
        assert_eq!(spec.ext(), "sqlite3");
        // relative path resolves like the child's working dir
        assert_eq!(
            pg("sqlite://data/db.sqlite3"),
            DbSpec::Sqlite {
                path: "data/db.sqlite3".into()
            }
        );
        // percent-escaped path components are decoded
        assert_eq!(
            pg("sqlite:///data/my%20db.sqlite3"),
            DbSpec::Sqlite {
                path: "/data/my db.sqlite3".into()
            }
        );
    }

    #[test]
    fn rejects_malformed_and_unknown() {
        assert!(parse("").is_none());
        assert!(parse("   ").is_none());
        assert!(parse("not-a-url").is_none());
        assert!(parse("oracle://u:p@h/db").is_none());
        // port zero and non-numeric port are malformed
        assert!(parse("postgres://u:p@h:0/db").is_none());
        assert!(parse("postgres://u:p@h:port/db").is_none());
        // unclosed ipv6 bracket
        assert!(parse("postgres://u:p@[::1/db").is_none());
    }

    #[test]
    fn scheme_for_log_never_carries_secrets() {
        assert_eq!(scheme_for_log("postgres://u:p@h/db"), "postgres");
        assert_eq!(scheme_for_log("  mysql://x  "), "mysql");
        assert_eq!(scheme_for_log("garbage"), "garbage");
        assert_eq!(scheme_for_log("no-secret-here://x"), "no-secret-here");
    }

    #[test]
    fn invalid_escapes_pass_through() {
        // WHATWG keeps invalid percent-escapes verbatim in userinfo
        let DbSpec::Postgres { password, .. } = pg("postgres://u:%ZZ@h/db") else {
            panic!("expected postgres spec");
        };
        assert_eq!(password.as_deref(), Some("%ZZ"));
        // truncated escape at the end
        let DbSpec::Postgres { password, .. } = pg("postgres://u:ab%2@h/db") else {
            panic!("expected postgres spec");
        };
        assert_eq!(password.as_deref(), Some("ab%2"));
    }
}
