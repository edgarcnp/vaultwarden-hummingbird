//! Environment plumbing for the DB client tools: libpq variables, the
//! mariadb 0600 defaults-file, and the shared-lib path. Secrets ride env
//! / a 0600 file — never argv (/proc cmdline is world-readable).

use std::os::unix::fs::PermissionsExt;

use crate::config::{DB_TOOL_LIB, DbSpec};

/// libpq env vars for the dump/restore tools.
pub(super) fn pg_env(db: &DbSpec) -> Vec<(String, String)> {
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
    let mut env = vec![("LD_LIBRARY_PATH".to_string(), DB_TOOL_LIB.to_string())];
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
pub(super) fn mysql_env() -> Vec<(String, String)> {
    vec![("LD_LIBRARY_PATH".to_string(), DB_TOOL_LIB.to_string())]
}

/// 0600 defaults file for mariadb tools; under /tmp (tmpfs,
/// container-private); removed by the caller after the run.
pub(super) fn defaults_file(
    user: Option<&str>,
    password: Option<&str>,
    host: Option<&str>,
    port: u16,
) -> Option<String> {
    let path = format!("/tmp/.my-{}", std::process::id());
    let mut content = String::from("[client]\n");
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
}
