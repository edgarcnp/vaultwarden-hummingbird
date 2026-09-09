//! External client tool plumbing for the mysql/mariadb backend: the 0600
//! defaults-file for `mariadb-dump`/`mariadb` and the shared-lib env.
//! Secrets ride a 0600 file — never argv, and the mariadb tools have no
//! password env var. TLS 1.3 only.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::config::DB_TOOL_LIB;

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
    /// Sequence number keeps the staged path collision-proof across the
    /// sequential invocations of one process (count, dump, import).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = format!(
        "/tmp/.my-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
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
    // create_new + 0600 in one step: the password never sits at wider
    // perms, a pre-existing file/symlink is never followed (same contract
    // as the tailscale authkey staging), and a partial write removes the
    // file we created.
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return None,
    };
    if file.write_all(content.as_bytes()).is_err() {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return None;
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
