//! Supervisor-owned path policy: the supervisor state volume, the identity
//! file, the LocalAPI socket, and the names reserved for supervisor sidecars.
//! One helper behind every check, so a hardening change cannot leave one
//! copy of the rule weaker than another.

use std::path::{Component, Path};

use crate::util::fs::under_root;

/// The identity file: `mem:` (Tailscale's in-memory state) or a direct
/// child of the state root. The daemon derives its `--statedir` (and thus
/// the cert cache) from the file's parent; a subdirectory would move the
/// cert cache outside the synced tree.
pub(crate) fn state_file(root: &Path, value: &str) -> bool {
    if value == "mem:" {
        return true;
    }
    value.trim() == value && under_root(root, value) && Path::new(value).parent() == Some(root)
}

/// The LocalAPI socket: any normal path under the state root. It need not
/// be a direct child.
pub(crate) fn socket(root: &Path, value: &str) -> bool {
    value.trim() == value && under_root(root, value) && Path::new(value) != root
}

/// The direct-child name of a valid state file, for the sync manifest.
/// `None` for `mem:` or anything outside the root.
pub(crate) fn state_rel<'a>(root: &Path, value: &'a str) -> Option<&'a str> {
    if !state_file(root, value) || value == "mem:" {
        return None;
    }
    let rel = Path::new(value).strip_prefix(root).ok()?;
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
    ) || rel.starts_with("rsa_key")
        || rel.starts_with("db-backups")
        || rel.starts_with("db-")
        // StagedFile::create_in(STATE_ROOT, "ts-authkey") reclaims this
        // namespace by name; a state file there would be unlinked.
        || rel.starts_with("ts-authkey")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/state";

    #[test]
    fn state_files_are_direct_children_of_the_root() {
        assert!(state_file(Path::new(ROOT), "mem:"));
        assert!(state_file(Path::new(ROOT), "/state/tailscaled.state"));
        assert!(state_file(Path::new(ROOT), "/state/node.state"));
        for path in [
            "/state",
            "/state/",
            "/state/sub/node.state",
            "/state/../data/node.state",
            "/data/node.state",
            "/custom/node.state",
            "node.state",
            "/state/node\n.state",
            "/state/node.state ",
        ] {
            assert!(!state_file(Path::new(ROOT), path), "{path}");
        }
    }

    #[test]
    fn sockets_stay_under_the_root() {
        assert!(socket(Path::new(ROOT), "/state/tailscaled.sock"));
        assert!(socket(Path::new(ROOT), "/state/run/tailscaled.sock"));
        for path in [
            "/state",
            "/state/../data/sock",
            "/data/sock",
            "/custom/sock",
            "sock",
            "/state/sock\n",
        ] {
            assert!(!socket(Path::new(ROOT), path), "{path}");
        }
    }

    #[test]
    fn state_rel_is_a_single_normal_component() {
        assert_eq!(
            state_rel(Path::new(ROOT), "/state/node.state"),
            Some("node.state")
        );
        assert_eq!(state_rel(Path::new(ROOT), "mem:"), None);
        assert_eq!(state_rel(Path::new(ROOT), "/state/sub/node.state"), None);
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
