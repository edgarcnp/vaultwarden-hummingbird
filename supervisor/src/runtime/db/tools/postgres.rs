//! External client tool plumbing for the postgres backend: libpq
//! environment for `pg_dump`/`pg_restore`. The native client equivalent
//! lives in [`super::super::pg`]. Secrets ride env — never argv (/proc
//! cmdline is world-readable). TLS 1.3 only.

use crate::config::{DB_TOOL_LIB, DbSpec};

/// libpq env vars for the dump/restore tools.
///
/// `PGSSLMINPROTOCOLVERSION=TLSv1.3` (libpq `ssl_min_protocol_version`,
/// whose default is TLSv1.2) pins every libpq connection to TLS 1.3; it is
/// ignored when no TLS is attempted (sslmode=disable, unix socket).
/// `PGSSLROOTCERT` is forwarded from the supervisor env when set: bounded
/// children do not inherit the environment, but strict sslmodes (verify-ca/
/// verify-full) fail closed in libpq without a trust root.
pub fn pg_env(db: &DbSpec) -> Vec<(String, String)> {
    pg_env_with(db, std::env::var("PGSSLROOTCERT").ok())
}

/// [`pg_env`] with an explicit root-cert path (tests).
fn pg_env_with(db: &DbSpec, ssl_root_cert: Option<String>) -> Vec<(String, String)> {
    let DbSpec::Postgres {
        host,
        port,
        user,
        password,
        db,
        sslmode,
    } = db
    else {
        return Vec::new();
    };
    let mut env = vec![
        ("LD_LIBRARY_PATH".to_string(), DB_TOOL_LIB.to_string()),
        ("PGSSLMINPROTOCOLVERSION".to_string(), "TLSv1.3".to_string()),
    ];
    if let Some(h) = host {
        env.push(("PGHOST".to_string(), h.clone()));
    }
    env.push(("PGPORT".to_string(), port.to_string()));
    if let Some(u) = user {
        env.push(("PGUSER".to_string(), u.clone()));
    }
    if let Some(p) = password {
        env.push(("PGPASSWORD".to_string(), p.clone()));
    }
    if let Some(d) = db {
        env.push(("PGDATABASE".to_string(), d.clone()));
    }
    if let Some(s) = sslmode {
        env.push(("PGSSLMODE".to_string(), s.clone()));
    }
    if let Some(root) = ssl_root_cert.filter(|r| !r.trim().is_empty()) {
        env.push(("PGSSLROOTCERT".to_string(), root));
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_env_carries_connection_config() {
        let db = DbSpec::Postgres {
            host: Some("h".into()),
            port: 6543,
            user: Some("u".into()),
            password: Some("p@".into()),
            db: Some("vault".into()),
            sslmode: Some("require".into()),
        };
        let env = pg_env(&db);
        assert!(env.contains(&("PGHOST".to_string(), "h".to_string())));
        assert!(env.contains(&("PGPORT".to_string(), "6543".to_string())));
        assert!(env.contains(&("PGUSER".to_string(), "u".to_string())));
        assert!(env.contains(&("PGPASSWORD".to_string(), "p@".to_string())));
        assert!(env.contains(&("PGDATABASE".to_string(), "vault".to_string())));
        assert!(env.contains(&("PGSSLMODE".to_string(), "require".to_string())));
    }

    #[test]
    fn pg_env_pins_tls_1_3() {
        let db = DbSpec::Postgres {
            host: Some("h".into()),
            port: 5432,
            user: None,
            password: None,
            db: None,
            sslmode: Some("require".into()),
        };
        assert!(
            pg_env(&db).contains(&("PGSSLMINPROTOCOLVERSION".to_string(), "TLSv1.3".to_string()))
        );
    }

    #[test]
    fn non_postgres_spec_yields_no_env() {
        let db = DbSpec::Sqlite {
            path: "/data/db.sqlite3".into(),
        };
        assert!(pg_env(&db).is_empty());
    }

    /// A staged trust root is forwarded so strict sslmodes can verify;
    /// empty/absent values are not (libpq would fail on an empty path).
    #[test]
    fn pg_env_forwards_the_trust_root_when_set() {
        let db = DbSpec::Postgres {
            host: Some("h".into()),
            port: 5432,
            user: None,
            password: None,
            db: None,
            sslmode: Some("verify-full".into()),
        };
        let env = pg_env_with(&db, Some("/etc/ca.pem".into()));
        assert!(env.contains(&("PGSSLROOTCERT".to_string(), "/etc/ca.pem".to_string())));
        // empty string: not forwarded (libpq treats it as unset anyway,
        // and a blank value must never shadow a URL-embedded path)
        let env = pg_env_with(&db, Some("  ".into()));
        assert!(!env.iter().any(|(k, _)| k == "PGSSLROOTCERT"));
        // absent: not forwarded
        let env = pg_env_with(&db, None);
        assert!(!env.iter().any(|(k, _)| k == "PGSSLROOTCERT"));
    }
}
