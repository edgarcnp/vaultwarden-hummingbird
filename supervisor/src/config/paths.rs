//! Supervisor-owned path policy: the supervisor state volume, the identity
//! file, the LocalAPI socket, and the names reserved for supervisor sidecars.
//! One helper behind every check, so a hardening change cannot leave one
//! copy of the rule weaker than another.

use std::path::{Component, Path, PathBuf};

use crate::util::fs::under_root;

/// The tailscaled-writable subtree under the state root.
pub(crate) fn tailscale_dir(root: &Path) -> PathBuf {
    root.join("tailscale")
}

/// The link tailscaled is told to use for `--state`: a supervisor-created
/// symlink to [`tailscale_dir`]. The differently named parent keeps
/// Tailscale from chmod'ing the real group-writable tree to 0700 (the daemon
/// uid cannot do that, and would fall back to an in-memory store).
pub(crate) fn tailscale_state_dir(root: &Path) -> PathBuf {
    root.join("tailscale-state")
}

/// Map a legacy direct child of the real tree (`/state/tailscale/<name>`)
/// onto the link directory, so existing custom identities keep working.
/// Only a direct child is mapped; deeper paths are left for validation to
/// reject.
pub(crate) fn normalize_state_path(root: &Path, value: &str) -> String {
    if value == "mem:" {
        return value.to_string();
    }
    let actual = tailscale_dir(root);
    let path = Path::new(value);
    if under_root(&actual, value)
        && path.parent() == Some(actual.as_path())
        && let Some(name) = path.file_name().and_then(|name| name.to_str())
    {
        return tailscale_state_dir(root)
            .join(name)
            .to_string_lossy()
            .into_owned();
    }
    value.to_string()
}

/// The identity file: `mem:` (Tailscale's in-memory state) or a direct
/// child of the link directory. The daemon derives the state store's
/// parent from this path; the differently named link is what keeps it from
/// chmod'ing the real tree.
pub(crate) fn state_file(root: &Path, value: &str) -> bool {
    if value == "mem:" {
        return true;
    }
    let dir = tailscale_state_dir(root);
    value.trim() == value
        && !value.ends_with('/')
        && under_root(&dir, value)
        && Path::new(value).parent() == Some(dir.as_path())
}

/// The LocalAPI socket: any normal path under `/state/tailscale`. The CLI
/// reaches it through the tailscale group.
pub(crate) fn socket(root: &Path, value: &str) -> bool {
    let dir = tailscale_dir(root);
    value.trim() == value && under_root(&dir, value) && Path::new(value) != dir
}

/// The direct-child name of a valid state file, for the sync manifest.
/// `None` for `mem:` or anything outside the subtree. The bucket key stays
/// the bare name (`tailscaled.state`), independent of the local directory.
pub(crate) fn state_rel<'a>(root: &Path, value: &'a str) -> Option<&'a str> {
    if !state_file(root, value) || value == "mem:" {
        return None;
    }
    let dir = tailscale_state_dir(root);
    let rel = Path::new(value).strip_prefix(&dir).ok()?;
    let mut parts = rel.components();
    let Component::Normal(name) = parts.next()? else {
        return None;
    };
    parts.next().is_none().then(|| name.to_str()).flatten()
}

/// Names the supervisor already owns on the state volume, or in the bucket
/// namespace. A custom identity file must not shadow one: the cache,
/// repair, missing and lineage sidecars, the migration marker, the backup
/// staging/prefix, the content-addressed object namespace, and the durable
/// vault keys.
pub(crate) fn reserved_state_name(rel: &str) -> bool {
    if rel.is_empty() || rel.trim() != rel || rel.contains('/') || rel.chars().any(char::is_control)
    {
        return true;
    }
    if rel.starts_with('.') || crate::util::fs::is_partial_name(rel) {
        return true;
    }
    matches!(
        rel,
        "config.json"
            | "manifest"
            | "tombstones"
            | "certs"
            | "attachments"
            | "sends"
            | "db"
            | "db-backups"
            | "objects"
            | "tailscaled.sock"
    ) || rel.starts_with("rsa_key")
        || rel.starts_with("db-backups")
        || rel.starts_with("db-")
        // StagedFile::create_in(STATE_ROOT, "ts-authkey") reclaims this
        // namespace by name; a state file there would be unlinked.
        || rel.starts_with("ts-authkey")
}

#[cfg(test)]
mod tests {
    //! State-file, socket, and reserved-name policy edges.

    use super::*;

    const ROOT: &str = "/state";

    #[test]
    fn state_files_are_direct_children_of_the_link_dir() {
        assert!(state_file(Path::new(ROOT), "mem:"));
        assert!(state_file(
            Path::new(ROOT),
            "/state/tailscale-state/tailscaled.state"
        ));
        assert!(state_file(
            Path::new(ROOT),
            "/state/tailscale-state/node.state"
        ));
        for path in [
            "/state",
            "/state/",
            "/state/tailscaled.state",
            "/state/tailscale/tailscaled.state",
            "/state/sub/node.state",
            "/state/tailscale-state/sub/node.state",
            "/state/tailscale-state/../data/node.state",
            "/state/tailscale-state/",
            "/data/node.state",
            "/custom/node.state",
            "node.state",
            "/state/tailscale-state/node\n.state",
            "/state/tailscale-state/node.state ",
        ] {
            assert!(!state_file(Path::new(ROOT), path), "{path}");
        }
        // Legacy custom identities under the real tree are normalized onto
        // the link directory; deeper paths are not.
        assert_eq!(
            normalize_state_path(Path::new(ROOT), "/state/tailscale/node.state"),
            "/state/tailscale-state/node.state"
        );
        assert_eq!(
            normalize_state_path(Path::new(ROOT), "/state/tailscale/sub/node.state"),
            "/state/tailscale/sub/node.state"
        );
        assert_eq!(normalize_state_path(Path::new(ROOT), "mem:"), "mem:");
    }

    #[test]
    fn sockets_stay_under_the_root() {
        assert!(socket(Path::new(ROOT), "/state/tailscale/tailscaled.sock"));
        assert!(socket(
            Path::new(ROOT),
            "/state/tailscale/run/tailscaled.sock"
        ));
        for path in [
            "/state",
            "/state/tailscaled.sock",
            "/state/tailscale/../data/sock",
            "/data/sock",
            "/custom/sock",
            "sock",
            "/state/tailscale/sock\n",
        ] {
            assert!(!socket(Path::new(ROOT), path), "{path}");
        }
    }

    #[test]
    fn state_rel_is_a_single_normal_component() {
        assert_eq!(
            state_rel(Path::new(ROOT), "/state/tailscale-state/node.state"),
            Some("node.state")
        );
        assert_eq!(state_rel(Path::new(ROOT), "mem:"), None);
        assert_eq!(
            state_rel(Path::new(ROOT), "/state/tailscale-state/sub/node.state"),
            None
        );
        assert_eq!(
            state_rel(Path::new(ROOT), "/state/tailscale/node.state"),
            None
        );
        assert_eq!(state_rel(Path::new(ROOT), "/state/node.state"), None);
        assert_eq!(state_rel(Path::new(ROOT), "/data/node.state"), None);
    }

    #[test]
    fn supervisor_names_are_reserved() {
        for name in [
            "",
            ".",
            "..",
            ".sync-cache",
            ".sync-repair",
            ".sync-missing",
            ".layout-v2",
            "config.json",
            "manifest",
            "tombstones",
            "certs",
            "attachments",
            "sends",
            "db",
            "db-backups",
            "db-backups.state",
            "db-backups-abc.last",
            "objects",
            "rsa_key",
            "rsa_key.pem",
            "tailscaled.sock",
            "ts-authkey-1-0",
            "ts-authkey",
            "sub/node.state",
            "bad\nname",
        ] {
            assert!(reserved_state_name(name), "{name:?} must be reserved");
        }
        for name in ["node.state", "tailscaled.state", "identity", "my-state"] {
            assert!(!reserved_state_name(name), "{name:?} must be allowed");
        }
    }
}
