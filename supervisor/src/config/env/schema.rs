//! The supervisor's knob inventory: one table behind dotenv validation,
//! the scalar defaults `merge` assembles, and the `.env.example` contract
//! test. Feature resolvers (sync, backup) keep their own defaults in
//! `config::consts`; this table is the one place that knows which
//! supervisor keys exist and which of them a dotenv file may set.

/// How a supervisor key may appear in the dotenv file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FilePolicy {
    /// Accepted from the dotenv file and documented in `.env.example`.
    File,
    /// Recognized only so resolution can refuse it with a message naming
    /// the valid spelling; never accepted.
    Legacy,
    /// Read from the process env only: inside the dotenv file it could
    /// never take effect, so it refuses the boot.
    ProcessOnly,
}

/// A declared default for the scalar knobs `merge` assembles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Default {
    Str(&'static str),
    Bool(bool),
}

pub(crate) struct Knob {
    pub name: &'static str,
    pub policy: FilePolicy,
    /// `None` = the resolver owning the knob handles its default.
    pub default: Option<Default>,
}

/// Every key the supervisor consumes. Keep in sync with `.env.example`:
/// the contract test fails when the two drift.
static KNOBS: &[Knob] = &[
    Knob {
        name: "TAILSCALE_AUTHKEY",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "TAILSCALE_STATE_FILE",
        policy: FilePolicy::File,
        default: Some(Default::Str("/data/tailscaled.state")),
    },
    Knob {
        name: "TAILSCALE_SOCKET",
        policy: FilePolicy::File,
        default: Some(Default::Str("/tmp/tailscaled.sock")),
    },
    Knob {
        name: "TAILSCALE_HOSTNAME",
        policy: FilePolicy::File,
        default: Some(Default::Str("vaultwarden-hummingbird")),
    },
    Knob {
        name: "TAILSCALE_SERVE",
        policy: FilePolicy::File,
        default: Some(Default::Bool(true)),
    },
    Knob {
        name: "TAILSCALE_SERVICE",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "TAILSCALE_USERSPACE",
        policy: FilePolicy::File,
        default: Some(Default::Bool(true)),
    },
    Knob {
        name: "VAULTWARDEN_PORT",
        policy: FilePolicy::File,
        default: Some(Default::Str("8080")),
    },
    Knob {
        name: "VAULTWARDEN_ROCKET_PORT",
        policy: FilePolicy::Legacy,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_ENV_FILE",
        policy: FilePolicy::ProcessOnly,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_DB_BACKUP",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_DB_BACKUP_INTERVAL",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_DB_BACKUP_KEEP",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_DB_BACKUP_RESTORE",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_S3_REMOTE",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_S3_ACCESS_KEY_ID",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_S3_SECRET_ACCESS_KEY",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_S3_ENDPOINT",
        policy: FilePolicy::File,
        default: None,
    },
    Knob {
        name: "SUPERVISOR_S3_SYNC_INTERVAL",
        policy: FilePolicy::File,
        default: None,
    },
];

fn find(name: &str) -> Option<&'static Knob> {
    KNOBS.iter().find(|knob| knob.name == name)
}

/// How `name` may appear in the dotenv file; `None` = not a supervisor
/// key at all (a typo, or a bare upstream name).
pub(crate) fn file_policy(name: &str) -> Option<FilePolicy> {
    find(name).map(|knob| knob.policy)
}

/// Whether a `VAULTWARDEN_*` name is consumed by the supervisor rather
/// than forwarded to the child. Derived from the table, so a future
/// `VAULTWARDEN_*` knob is routed to the supervisor automatically instead
/// of silently reaching the child.
pub(crate) fn consumed_child_key(name: &str) -> bool {
    name.starts_with("VAULTWARDEN_") && find(name).is_some()
}

/// The declared string default of a scalar knob assembled by `merge`.
pub(crate) fn string_default(name: &str) -> &'static str {
    match find(name).and_then(|knob| knob.default) {
        Some(Default::Str(value)) => value,
        other => panic!("{name}: expected a string default, found {other:?}"),
    }
}

/// The declared boolean default of a flag knob assembled by `merge`.
pub(crate) fn bool_default(name: &str) -> bool {
    match find(name).and_then(|knob| knob.default) {
        Some(Default::Bool(value)) => value,
        other => panic!("{name}: expected a boolean default, found {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_has_no_duplicates_and_sane_defaults() {
        let mut names: Vec<&str> = KNOBS.iter().map(|k| k.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), KNOBS.len(), "duplicate knob in the table");
        for knob in KNOBS {
            match knob.default {
                Some(Default::Str(v)) => assert!(!v.is_empty(), "{}", knob.name),
                Some(Default::Bool(_)) | None => {}
            }
        }
        // the flags merge parses keep typed defaults
        assert!(bool_default("TAILSCALE_SERVE"));
        assert!(bool_default("TAILSCALE_USERSPACE"));
        assert_eq!(string_default("VAULTWARDEN_PORT"), "8080");
        assert_eq!(
            string_default("TAILSCALE_STATE_FILE"),
            "/data/tailscaled.state"
        );
    }

    /// `.env.example` is the user-facing contract: every key it shows
    /// must be a known supervisor knob or a `VAULTWARDEN_*` child key,
    /// and every file-facing knob must be documented there. Adding a knob
    /// without documenting it (or documenting a typo) fails the build.
    #[test]
    fn env_example_and_the_table_agree() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../.env.example");
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
        let mut documented: Vec<String> = Vec::new();
        for line in text.lines() {
            let line = line.trim().trim_start_matches('#').trim();
            let Some((key, _)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if key.is_empty() || !key.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                continue;
            }
            if !key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                continue;
            }
            documented.push(key.to_string());
        }

        for key in &documented {
            if let Some(child) = key.strip_prefix("VAULTWARDEN_") {
                assert!(!child.is_empty(), "bare VAULTWARDEN_ documented");
                continue;
            }
            assert!(
                find(key).is_some(),
                "{key} is documented in .env.example but is not a supervisor knob"
            );
        }
        for knob in KNOBS
            .iter()
            .filter(|k| matches!(k.policy, FilePolicy::File | FilePolicy::ProcessOnly))
        {
            assert!(
                documented.iter().any(|d| d == knob.name),
                "{} is a supervisor knob but is missing from .env.example",
                knob.name
            );
        }
        // legacy spellings are intentionally not offered as usable keys
        for knob in KNOBS.iter().filter(|k| k.policy == FilePolicy::Legacy) {
            assert!(
                !documented.iter().any(|d| d == knob.name),
                "{} is legacy and must not be documented as usable",
                knob.name
            );
        }
    }

    /// `VAULTWARDEN_*` routing is derived from the table: a declared knob
    /// is consumed by the supervisor, everything else is forwarded to the
    /// child.
    #[test]
    fn child_namespace_routing_comes_from_the_table() {
        assert!(consumed_child_key("VAULTWARDEN_PORT"));
        assert!(consumed_child_key("VAULTWARDEN_ROCKET_PORT"));
        assert!(!consumed_child_key("VAULTWARDEN_DATABASE_URL"));
        assert!(!consumed_child_key("DATABASE_URL"));
        for knob in KNOBS.iter().filter(|k| k.name.starts_with("VAULTWARDEN_")) {
            assert!(consumed_child_key(knob.name), "{}", knob.name);
        }
    }
}
