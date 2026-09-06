//! Supervisor-owned dotenv file layer (opt-in via SUPERVISOR_ENV_FILE).
//!
//! One universal format: the same .env that `--env-file`, compose `env_file:`
//! and PaaS dashboards consume can be mounted for the supervisor, which
//! distributes it:
//!   - `TS_*`/`SUPERVISOR_*` keys -> its own knobs (localized to PID 1;
//!     never reach the vaultwarden child, never appear in `podman inspect`)
//!   - everything else            -> forwarded verbatim to the child
//!
//! Syntax: KEY=value, `#` comments, optional `export ` or `export<TAB>`
//! prefix, optional matching single/double quotes around values (quote
//! values containing `#`). Precedence is resolved in `config::env`.

use std::collections::BTreeMap;

use super::env::is_supervisor_key;
use crate::util::log;

/// Env var holding the dotenv file path (absent/empty = env-only mode).
const ENV_NAME: &str = "SUPERVISOR_ENV_FILE";

#[derive(Default)]
pub struct FileConfig {
    /// supervisor knobs (TS_*/SUPERVISOR_* keys)
    pub knobs: BTreeMap<String, String>,
    /// verbatim vaultwarden env names -> values (forwarded to the child)
    pub child: BTreeMap<String, String>,
}

/// Parse dotenv syntax (see module docs); invalid lines are logged and
/// skipped, later duplicates win.
fn parse(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (n, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .or_else(|| line.strip_prefix("export\t"))
            .unwrap_or(line)
            .trim();
        let Some((key, val)) = line.split_once('=') else {
            log::err(&format!("config: line {}: not KEY=value; ignored", n + 1));
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            log::err(&format!("config: line {}: invalid key; ignored", n + 1));
            continue;
        }
        let val = val.trim();
        let val = if val.len() >= 2
            && ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
        {
            &val[1..val.len() - 1]
        } else {
            val
        };
        out.insert(key.to_string(), val.to_string());
    }
    out
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
        for (k, v) in parse(&raw) {
            if is_supervisor_key(&k) {
                cfg.knobs.insert(k, v);
            } else {
                cfg.child.insert(k, v);
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
DOMAIN = https://vault.example.com   # no inline comments unquoted: this # stays
SIGNUPS_ALLOWED=false
USER_ATTACHMENT_LIMIT=0
QUOTED = "hello world # not a comment"
SINGLE = 'raw # value'
export TS_AUTHKEY=tskey-auth-file
SUPERVISOR_ENV_FILE=/elsewhere

not a valid line
"#,
        );
        let cfg = FileConfig::load_from(Some(&path));
        assert_eq!(
            cfg.child.get("DOMAIN").map(String::as_str),
            Some("https://vault.example.com   # no inline comments unquoted: this # stays")
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
        // TS_*/SUPERVISOR_* stay with the supervisor, never reach the child
        assert!(!cfg.child.keys().any(|k| k.starts_with("TS_")));
        assert!(!cfg.child.keys().any(|k| k.starts_with("SUPERVISOR_")));
        assert_eq!(
            cfg.knobs.get("TS_AUTHKEY").map(String::as_str),
            Some("tskey-auth-file")
        );
        assert_eq!(
            cfg.knobs.get("SUPERVISOR_ENV_FILE").map(String::as_str),
            Some("/elsewhere")
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
