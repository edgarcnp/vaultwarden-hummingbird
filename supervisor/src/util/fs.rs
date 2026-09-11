//! File-permission policy for sensitive files: the owner-only mode the
//! supervisor applies everywhere it writes secrets or vault data — staged
//! authkeys, lineage sidecars, retained dumps, restored databases —
//! regardless of the writing process's umask.

use std::os::unix::fs::PermissionsExt;

/// Restrict `path` to owner-only (0600).
pub fn make_private(path: &str) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn file_ends_up_owner_only() {
        let dir = std::env::temp_dir().join(format!("vw-sup-fs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        make_private(path.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
