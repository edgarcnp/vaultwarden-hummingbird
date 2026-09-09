//! Supervisor-owned dotenv file (SUPERVISOR_ENV_FILE), split after parse:
//! `TAILSCALE_*`/`SUPERVISOR_*` keys -> supervisor knobs (never the child,
//! never `podman inspect`); `VAULTWARDEN_*` keys -> the vaultwarden child
//! under the stripped plain upstream name; everything else -> forwarded to
//! the child verbatim. Parsed by `dotenvy`, the standard dotenv dialect:
//! KEY=value, `#` full-line comments, optional `export ` prefix, optional
//! matching quotes (single quotes raw; double quotes support `\n` escapes
//! and `$VAR`/`${VAR}` substitution from the process env and earlier keys),
//! inline ` #` comments after values, and multi-line quoted values.
//! Invalid lines are logged (never their content — they may carry
//! credentials) and skipped; later duplicates win.

use std::collections::BTreeMap;

use super::env::{is_supervisor_key, vaultwarden_key};
use crate::util::log;

/// Env var holding the dotenv file path (absent/empty = env-only mode).
const ENV_NAME: &str = "SUPERVISOR_ENV_FILE";

#[derive(Default)]
pub struct FileConfig {
    /// supervisor knobs (TAILSCALE_*/SUPERVISOR_* keys)
    pub knobs: BTreeMap<String, String>,
    /// vaultwarden env under plain upstream names (VAULTWARDEN_* keys with
    /// the prefix stripped), forwarded to the child
    pub child: BTreeMap<String, String>,
}

impl FileConfig {
    /// Load from the SUPERVISOR_ENV_FILE env var (absent/empty -> env-only mode).
    pub fn load() -> Self {
        match std::env::var(ENV_NAME) {
            Ok(p) if !p.is_empty() => Self::load_from(Some(&p)),
            _ => Self::default(),
        }
    }

    /// path=None simulates "no config file" (used by tests).
    pub fn load_from(path: Option<&str>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) => {
                log::err(&format!(
                    "config: cannot read {path}: {e}; using env/defaults"
                ));
                return Self::default();
            }
        };
        let mut cfg = Self::default();
        for item in dotenvy::from_read_iter(raw.as_bytes()) {
            match item {
                Ok((k, v)) => {
                    if is_supervisor_key(&k) {
                        cfg.knobs.insert(k, v);
                    } else if let Some(stripped) = vaultwarden_key(&k) {
                        cfg.child.insert(stripped.to_string(), v);
                    } else {
                        cfg.child.insert(k, v);
                    }
                }
                // LineParse embeds the raw line — never log it (it may hold
                // credentials); the byte offset is safe.
                Err(dotenvy::Error::LineParse(_, pos)) => {
                    log::err(&format!(
                        "config: dotenv: invalid line (byte {pos}); ignored"
                    ));
                }
                Err(e) => log::err(&format!("config: dotenv: {e}; file partially applied")),
            }
        }
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(content: &str) -> String {
        let dir = std::env::temp_dir().join(format!("vw-sup-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(format!("env-{}.test", content.len()));
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().to_string()
    }

    #[test]
    fn parses_quotes_comments_and_splits_namespaces() {
        let path = write_tmp(
            r#"
# full-line comment
DOMAIN = https://vault.example.com   # trailing comment stripped
SIGNUPS_ALLOWED=false
QUOTED = "hello world # not a comment"
SINGLE = 'raw # value'
export TAILSCALE_AUTHKEY=tskey-auth-file
SUPERVISOR_ENV_FILE=/elsewhere
VAULTWARDEN_DATABASE_URL=postgres://db/vw

not a valid line
"#,
        );
        let cfg = FileConfig::load_from(Some(&path));
        assert_eq!(
            cfg.child.get("DOMAIN").map(String::as_str),
            Some("https://vault.example.com")
        );
        assert_eq!(
            cfg.child.get("SIGNUPS_ALLOWED").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            cfg.child.get("QUOTED").map(String::as_str),
            Some("hello world # not a comment")
        );
        assert_eq!(
            cfg.child.get("SINGLE").map(String::as_str),
            Some("raw # value")
        );
        assert!(!cfg.child.keys().any(|k| k.starts_with("TAILSCALE_")));
        assert!(!cfg.child.keys().any(|k| k.starts_with("SUPERVISOR_")));
        // VAULTWARDEN_ keys land under the stripped upstream name
        assert!(!cfg.child.keys().any(|k| k.starts_with("VAULTWARDEN_")));
        assert_eq!(
            cfg.knobs.get("TAILSCALE_AUTHKEY").map(String::as_str),
            Some("tskey-auth-file")
        );
        assert_eq!(
            cfg.child.get("DATABASE_URL").map(String::as_str),
            Some("postgres://db/vw")
        );
        assert_eq!(
            cfg.knobs.get("SUPERVISOR_ENV_FILE").map(String::as_str),
            Some("/elsewhere")
        );
    }

    /// The dotenvy dialect: double quotes unescape `\n` and substitute
    /// `$VAR`/`${VAR}` (earlier file keys; the process env would win if
    /// set), single quotes are raw.
    #[test]
    fn double_quotes_expand_and_single_quotes_stay_raw() {
        let path = write_tmp(
            "BASE=base\nNEWLINE=\"a\\nb\"\nRAW='a\\nb'\nEXPANDED=\"${BASE}/x\"\nLITERAL='no ${BASE} here'\nPASS='p@ss:wo\"rd'\n",
        );
        let cfg = FileConfig::load_from(Some(&path));
        assert_eq!(cfg.child.get("NEWLINE").map(String::as_str), Some("a\nb"));
        assert_eq!(cfg.child.get("RAW").map(String::as_str), Some("a\\nb"));
        assert_eq!(
            cfg.child.get("EXPANDED").map(String::as_str),
            Some("base/x")
        );
        assert_eq!(
            cfg.child.get("LITERAL").map(String::as_str),
            Some("no ${BASE} here")
        );
        assert_eq!(
            cfg.child.get("PASS").map(String::as_str),
            Some("p@ss:wo\"rd")
        );
    }

    #[test]
    fn none_is_env_only_mode() {
        let cfg = FileConfig::load_from(None);
        assert!(cfg.child.is_empty());
        assert!(cfg.knobs.is_empty());
    }

    #[test]
    fn missing_file_degrades() {
        let cfg = FileConfig::load_from(Some("/nonexistent/.env"));
        assert!(cfg.child.is_empty());
    }

    #[test]
    fn duplicates_win_later_and_bad_keys_are_dropped() {
        let path = write_tmp("A=1\nA=2\nBAD-KEY=3\njust words\n");
        let cfg = FileConfig::load_from(Some(&path));
        assert_eq!(cfg.child.len(), 1);
        assert_eq!(cfg.child.get("A").map(String::as_str), Some("2"));
    }
}
