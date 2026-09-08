//! Environment plumbing for the DB client tools: libpq variables, the
//! mariadb 0600 defaults-file, and the shared-lib path. Secrets ride env
//! / a 0600 file — never argv (/proc cmdline is world-readable). Both
//! toolchains are pinned to TLS 1.3.

use std::os::unix::fs::PermissionsExt;

use crate::config::{DbSpec, DB_TOOL_LIB};

/// libpq env vars for the dump/restore tools.
///
/// `PGSSLMINPROTOCOLVERSION=TLSv1.3` (libpq `ssl_min_protocol_version`,
/// whose default is TLSv1.2) pins every libpq connection to TLS 1.3; it is
/// ignored when no TLS is attempted (sslmode=disable, unix socket).
pub fn pg_env(db: &DbSpec) -> Vec<(String, String)> {
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
    env
}

/// Shared-lib dir for the mariadb tools, extracted by the image build.
pub fn mysql_env() -> Vec<(String, String)> {
    vec![("LD_LIBRARY_PATH".to_string(), DB_TOOL_LIB.to_string())]
}

/// 0600 defaults file for mariadb tools; under /tmp (tmpfs,
/// container-private); removed by the caller after the run.
///
/// `tls-version=TLSv1.3` (the `--tls-version` client option) pins every
/// mariadb TLS connection to TLS 1.3; it is ignored when the connection
/// does not use TLS (unix socket, no TLS server).
pub fn defaults_file(
    user: Option<&str>,
    password: Option<&str>,
    host: Option<&str>,
    port: u16,
) -> Option<String> {
    let path = format!("/tmp/.my-{}", std::process::id());
    let mut content = String::from("[client]\ntls-version=TLSv1.3\n");
    if let Some(u) = user {
        content.push_str(&format!("user={u}\n"));
    }
    if let Some(p) = password {
        // my.cnf quoting: embedded quotes/backslashes are escaped with '\'
        content.push_str(&format!(
            "password=\"{}\"\n",
            p.replace('\\', "\\\\").replace('"', "\\\"")
        ));
    }
    if let Some(h) = host {
        content.push_str(&format!("host={h}\n"));
    }
    content.push_str(&format!("port={port}\n"));
    std::fs::write(&path, content).ok()?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Some(path)
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
    fn mysql_env_pins_the_shared_lib_dir() {
        assert_eq!(
            mysql_env(),
            vec![(
                "LD_LIBRARY_PATH".to_string(),
                "/usr/local/lib/dbclients/lib".to_string()
            )]
        );
    }

    /// The defaults file: 0600, TLS 1.3 pin, and my.cnf escaping of
    /// embedded quotes/backslashes in the password.
    #[test]
    fn defaults_file_is_0600_pins_tls_and_escapes() {
        use std::os::unix::fs::PermissionsExt;
        let path = defaults_file(Some("u"), Some("p\"a\\ss"), Some("h"), 3307).expect("staged");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[client]\ntls-version=TLSv1.3\nuser=u\npassword=\"p\\\"a\\\\ss\"\nhost=h\nport=3307\n"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }
}
