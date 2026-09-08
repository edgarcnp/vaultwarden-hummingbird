//! DATABASE_URL parsing into a [`DbSpec`]: a minimal, hand-rolled URL
//! reader (scheme, userinfo, host, port, path, query) — narrow input,
//! no URL crate. Percent-decoding is byte-exact for credentials that
//! contain URL metacharacters (`@`, `:`, `/`).

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

/// Parse a DATABASE_URL. `None` = empty, unrecognized scheme, or malformed
/// authority. sqlite URLs are paths after the scheme (`sqlite:///a/b` →
/// `/a/b`); no scheme at all is not sqlite — callers decide the default.
pub fn parse(raw: &str) -> Option<DbSpec> {
    let url = raw.trim();
    let (scheme, rest) = url.split_once("://")?;
    match scheme {
        "postgres" | "postgresql" => Some(net_spec(rest, 5432, false)?),
        "mysql" | "mariadb" => Some(net_spec(rest, 3306, true)?),
        "sqlite" => Some(DbSpec::Sqlite {
            path: percent_decode(rest),
        }),
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

fn net_spec(rest: &str, default_port: u16, mysql: bool) -> Option<DbSpec> {
    let (authority_path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (authority, path) = authority_path
        .split_once('/')
        .unwrap_or((authority_path, ""));

    // userinfo ends at the LAST '@' (host never contains a raw '@'; a
    // password might) and splits on the FIRST ':' (user never contains a
    // raw ':').
    let (user, password, hostport) = match authority.rfind('@') {
        Some(i) => {
            let userinfo = &authority[..i];
            // "u:p@h" carries a password; "u@h" carries none ("u:@h" is an
            // explicitly empty one)
            match userinfo.split_once(':') {
                Some((u, p)) => (
                    percent_decode(u),
                    Some(percent_decode(p)),
                    &authority[i + 1..],
                ),
                None => (percent_decode(userinfo), None, &authority[i + 1..]),
            }
        }
        None => (String::new(), None, authority),
    };
    let (host, port) = split_host_port(hostport, default_port)?;
    let db = non_empty(percent_decode(path));

    let spec = if mysql {
        DbSpec::Mysql {
            host,
            port,
            user: non_empty(user),
            password,
            db,
        }
    } else {
        let sslmode = query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "sslmode")
            .map(|(_, v)| percent_decode(v))
            .filter(|v| !v.is_empty());
        DbSpec::Postgres {
            host,
            port,
            user: non_empty(user),
            password,
            db,
            sslmode,
        }
    };
    Some(spec)
}

/// `host[:port]`, IPv6 brackets honored. Empty host = None (tool defaults).
fn split_host_port(s: &str, default_port: u16) -> Option<(Option<String>, u16)> {
    let (host, port_str) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        (h, tail.strip_prefix(':').unwrap_or(""))
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => (s, ""),
        }
    };
    let port = match port_str.parse::<u16>() {
        Ok(p) if p != 0 => p,
        Ok(_) => return None,
        Err(_) if port_str.is_empty() => default_port,
        Err(_) => return None,
    };
    let host = non_empty(host.to_string());
    Some((host, port))
}

fn non_empty(s: String) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Percent-decode a URL component; invalid escapes pass through literally
/// and non-UTF-8 bytes are replaced (a mangled credential must fail the
/// connection later, not panic here).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0) as u8;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
        // password with raw ':' and '@' — first ':' and last '@' split
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
        // ipv6 host
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
