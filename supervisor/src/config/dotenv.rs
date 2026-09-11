//! Supervisor-owned dotenv file (SUPERVISOR_ENV_FILE). The file is the
//! explicit grant surface and is STRICT: every key must belong to one of
//! the three namespaces — `TAILSCALE_*`/`SUPERVISOR_*` (supervisor knobs,
//! never the child, never `podman inspect`), `VAULTWARDEN_*` (forwarded
//! to the vaultwarden child under the stripped plain upstream name), or
//! nothing else — bare upstream names (`DATABASE_URL`) and any other key
//! are collected in [`FileConfig::invalid`] and REFUSE the boot: a
//! typo'd or legacy key must never be silently ignored. Parsed by
//! `dotenvy`; invalid syntax is logged (never its content — lines may
//! carry credentials) and skipped; later duplicates win.

use std::collections::BTreeMap;

use super::env::{is_supervisor_consumed, is_supervisor_key, vaultwarden_key};
use crate::util::log;

/// Env var holding the dotenv file path (absent/empty = env-only mode).
const ENV_NAME: &str = "SUPERVISOR_ENV_FILE";

#[derive(Default)]
pub struct FileConfig {
    /// supervisor-consumed keys (TAILSCALE_*/SUPERVISOR_*/port knob)
    pub knobs: BTreeMap<String, String>,
    /// vaultwarden child env, `VAULTWARDEN_*` keys under the stripped
    /// plain upstream name
    pub child: BTreeMap<String, String>,
    /// keys outside the accepted namespaces — boot refuses when
    /// non-empty (key names only; values may be secrets)
    pub invalid: Vec<String>,
}

impl FileConfig {
    /// Load from the SUPERVISOR_ENV_FILE env var (absent/empty -> env-only).
    pub fn load() -> Self {
        match std::env::var(ENV_NAME) {
            Ok(p) if !p.is_empty() => Self::load_from(Some(&p)),
            _ => Self::default(),
        }
    }

    /// path=None = no config file (tests).
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
                    if is_supervisor_consumed(&k) {
                        cfg.knobs.insert(k, v);
                    } else if let Some(stripped) = vaultwarden_key(&k) {
                        // A VAULTWARDEN_ key stripping into the supervisor's
                        // namespace (VAULTWARDEN_TAILSCALE_*) is a dangerous
                        // misconfiguration, not a child key: strict refusal.
                        if is_supervisor_key(stripped) {
                            cfg.invalid.push(k);
                        } else {
                            cfg.child.insert(stripped.to_string(), v);
                        }
                    } else {
                        // bare upstream names and anything unrecognized
                        cfg.invalid.push(k);
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
VAULTWARDEN_DOMAIN = https://vault.example.com   # trailing comment stripped
VAULTWARDEN_SIGNUPS_ALLOWED=false
VAULTWARDEN_QUOTED = "hello world # not a comment"
VAULTWARDEN_SINGLE = 'raw # value'
export TAILSCALE_AUTHKEY=tskey-auth-file
VAULTWARDEN_DATABASE_URL=sqlite:///data/db.sqlite3

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
        assert!(cfg.invalid.is_empty(), "prefixed keys are all valid");
        assert_eq!(
            cfg.knobs.get("TAILSCALE_AUTHKEY").map(String::as_str),
            Some("tskey-auth-file")
        );
        assert_eq!(
            cfg.child.get("DATABASE_URL").map(String::as_str),
            Some("sqlite:///data/db.sqlite3")
        );
    }

    /// Everything outside the three namespaces is invalid — bare upstream
    /// names included: the file is the explicit grant surface, so a
    /// legacy or typo'd key refuses the boot instead of being ignored.
    #[test]
    fn unprefixed_keys_are_invalid() {
        let path = write_tmp(
            "DATABASE_URL=sqlite:///data/db.sqlite3\nDOMAIN=https://x.example\nTAILSCALE_AUTHKEY=ok\n",
        );
        let cfg = FileConfig::load_from(Some(&path));
        assert_eq!(
            cfg.invalid,
            vec!["DATABASE_URL".to_string(), "DOMAIN".to_string()]
        );
        // valid keys still route normally
        assert!(cfg.child.is_empty());
        assert!(cfg.knobs.contains_key("TAILSCALE_AUTHKEY"));
    }

    /// A VAULTWARDEN_ key stripping into the supervisor's namespace is a
    /// dangerous misconfiguration (a secret in the wrong namespace):
    /// strict refusal, never a silent drop.
    #[test]
    fn vaultwarden_prefixed_supervisor_names_are_invalid() {
        let path = write_tmp("VAULTWARDEN_TAILSCALE_AUTHKEY=leak\nTAILSCALE_HOSTNAME=ok\n");
        let cfg = FileConfig::load_from(Some(&path));
        assert_eq!(
            cfg.invalid,
            vec!["VAULTWARDEN_TAILSCALE_AUTHKEY".to_string()]
        );
        assert!(cfg.knobs.contains_key("TAILSCALE_HOSTNAME"));
    }

    /// The port knobs are supervisor-consumed: they land in the knobs map
    /// from the file, never in the child env (the supervisor binds the
    /// gate on them and pins the child's port).
    #[test]
    fn port_knobs_route_to_the_supervisor() {
        let path =
            write_tmp("VAULTWARDEN_PORT=8443\nVAULTWARDEN_ROCKET_PORT=9999\nROCKET_PORT=2222\n");
        let cfg = FileConfig::load_from(Some(&path));
        assert_eq!(
            cfg.knobs.get("VAULTWARDEN_PORT").map(String::as_str),
            Some("8443")
        );
        // the legacy alias routes to knobs (it is consumed) and is
        // refused at resolution time
        assert_eq!(
            cfg.knobs.get("VAULTWARDEN_ROCKET_PORT").map(String::as_str),
            Some("9999")
        );
        // the bare upstream spelling is simply invalid
        assert_eq!(cfg.invalid, vec!["ROCKET_PORT".to_string()]);
        assert!(!cfg.child.contains_key("PORT"));
    }

    /// The dotenvy dialect: double quotes unescape `\n` and substitute
    /// `$VAR`/`${VAR}` from earlier file keys, single quotes are raw.
    #[test]
    fn double_quotes_expand_and_single_quotes_stay_raw() {
        let path = write_tmp(
            "VAULTWARDEN_BASE=base\nVAULTWARDEN_NEWLINE=\"a\\nb\"\nVAULTWARDEN_RAW='a\\nb'\nVAULTWARDEN_EXPANDED=\"${VAULTWARDEN_BASE}/x\"\nVAULTWARDEN_LITERAL='no ${BASE} here'\n",
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
    }

    #[test]
    fn none_is_env_only_mode() {
        let cfg = FileConfig::load_from(None);
        assert!(cfg.child.is_empty());
        assert!(cfg.knobs.is_empty());
        assert!(cfg.invalid.is_empty());
    }

    #[test]
    fn missing_file_degrades() {
        let cfg = FileConfig::load_from(Some("/nonexistent/.env"));
        assert!(cfg.child.is_empty());
    }

    #[test]
    fn duplicates_win_later() {
        let path = write_tmp("VAULTWARDEN_A=1\nVAULTWARDEN_A=2\n");
        let cfg = FileConfig::load_from(Some(&path));
        assert_eq!(cfg.child.len(), 1);
        assert_eq!(cfg.child.get("A").map(String::as_str), Some("2"));
        assert!(cfg.invalid.is_empty());
    }
}
