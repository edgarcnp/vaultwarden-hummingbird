//! MariaDB/MySQL dump: `mariadb-dump` with `--single-transaction` (InnoDB
//! snapshot). Credentials ride a 0600 defaults-file — mariadb tools have
//! no password env var and argv is world-readable in /proc.

use crate::config::{DbBackupConfig, DbSpec, MARIADB_DUMP};
use crate::runtime::db::tools::{defaults_file, mysql_env};
use crate::util::log;

use super::super::tools::tool;

/// mariadb-dump (`--single-transaction` InnoDB snapshot) into `staged`.
pub(crate) fn dump(cfg: &DbBackupConfig, staged: &str, abort: &impl Fn() -> bool) -> bool {
    let DbSpec::Mysql {
        host,
        port,
        user,
        password,
        db,
    } = &cfg.db
    else {
        return false;
    };
    let Some(cnf) = defaults_file(user.as_deref(), password.as_deref(), host.as_deref(), *port)
    else {
        log::err("db backup: cannot stage mariadb defaults file");
        return false;
    };
    let mut args: Vec<String> = vec![
        format!("--defaults-extra-file={cnf}"),
        "--single-transaction".into(),
        "--quick".into(),
        format!("--result-file={staged}"),
    ];
    args.extend(db.iter().cloned());
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    // tool() bounds the run and removes the staged file on failure:
    // mariadb-dump writes --result-file directly, so a failed run leaves a
    // partial (sensitive) dump that must not linger.
    let ok = tool(
        "mariadb-dump",
        MARIADB_DUMP,
        &argv,
        &mysql_env(),
        staged,
        abort,
    );
    let _ = std::fs::remove_file(&cnf);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::backup::support;

    /// A failed run (no mariadb binary in the test env -> spawn error)
    /// must not leave a partial staged dump behind.
    #[test]
    fn mariadb_dump_failure_removes_the_partial_staged_file() {
        let dir = std::env::temp_dir().join(format!("vw-sup-mdbfail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("dump.sql");
        std::fs::write(&staged, b"pre-existing sentinel").unwrap();
        let cfg = support::cfg_with(
            "mariadb://u:p@127.0.0.1:1/vault",
            DbSpec::Mysql {
                host: Some("127.0.0.1".into()),
                port: 1,
                user: Some("u".into()),
                password: Some("p".into()),
                db: Some("vault".into()),
            },
        );
        assert!(!dump(&cfg, staged.to_str().unwrap(), &|| false));
        assert!(
            !staged.exists(),
            "failed dump must not leave partial output"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
