//! Bucket helpers for the backup cycle, over the in-crate S3 client
//! ([`crate::s3`]). The sqlite dump/restore itself is in-process
//! (`sqlite/`), and the dump set's bucket-side authority is the manifest
//! ([`super::manifest`]).

use crate::config::{DbBackupConfig, SYNC_TIMEOUT};
pub(crate) use crate::s3::Client;

use super::manifest::{MAX_MANIFEST_BYTES, Manifest};

/// One client for a backup run. `Err` = unusable configuration; callers
/// log the cause and skip rather than guess.
pub(crate) fn client(cfg: &DbBackupConfig) -> anyhow::Result<Client> {
    Client::connect(&cfg.sync.target, SYNC_TIMEOUT)
}

/// The manifest's bucket key (inside the backup prefix).
pub(crate) fn manifest_key(cfg: &DbBackupConfig) -> String {
    format!("{}manifest", cfg.prefix())
}

/// Load the manifest. `Ok(None)` = the bucket has none yet (legacy layout
/// or first run); network and parse errors are returned for the caller's
/// recovery policy.
pub(crate) fn load_manifest(
    client: &Client,
    cfg: &DbBackupConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Option<Manifest>> {
    match client.get_optional_text(&manifest_key(cfg), MAX_MANIFEST_BYTES, abort)? {
        Some(text) => Manifest::parse(&text).map(Some),
        None => Ok(None),
    }
}

/// Publish the manifest. Call only after the dump it names is in place,
/// so a crash can leave an unreferenced object but never a reference to
/// a missing one.
pub(crate) fn store_manifest(
    client: &Client,
    cfg: &DbBackupConfig,
    manifest: &Manifest,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<()> {
    client.put_bytes(&manifest_key(cfg), manifest.render().as_bytes(), abort)
}

/// The legacy dump listing (`<prefix><label>-*.<ext>`, name + size,
/// sorted): used while no manifest exists and as the recovery fallback
/// when one is unreadable. `Err` = listing failed — callers must never
/// delete blind.
pub(crate) fn list_objects(
    client: &Client,
    cfg: &DbBackupConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Vec<(String, u64)>> {
    let keys = client.list(&cfg.prefix(), abort)?;
    let bucket_prefix = cfg.prefix();
    let name_prefix = format!("{}-", cfg.db_label());
    let name_suffix = format!(".{}", cfg.db_ext());
    let mut names: Vec<(String, u64)> = keys
        .into_iter()
        .filter_map(|listed| {
            let name = listed.key.strip_prefix(&bucket_prefix)?;
            (name.starts_with(&name_prefix) && name.ends_with(&name_suffix))
                .then(|| (name.to_string(), listed.size))
        })
        .collect();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::config::SyncConfig;
    use crate::s3::Listed;

    use super::*;

    #[test]
    fn listing_filters_to_dump_names_only() {
        // parse the strip/filter logic without a bucket: same closure
        // shape as list_objects, exercised on a synthetic listing
        let sync = SyncConfig::new(
            "r2:vw-state".into(),
            "id".into(),
            "s".into(),
            "http://127.0.0.1:1".into(),
            Duration::from_secs(60),
        )
        .unwrap();
        let cfg = crate::runtime::backup::support::cfg_with_sync(sync);
        let bucket_prefix = cfg.prefix();
        let name_prefix = format!("{}-", cfg.db_label());
        let name_suffix = format!(".{}", cfg.db_ext());
        let listed = vec![
            Listed {
                key: format!("{}sqlite-1.sqlite3", bucket_prefix),
                size: 11,
            },
            Listed {
                key: "certs/x".to_string(),
                size: 0,
            },
            Listed {
                key: format!("{}sqlite-not-a-dump.txt", bucket_prefix),
                size: 0,
            },
            Listed {
                key: format!("{}sqlite-2.sqlite3", bucket_prefix),
                size: 22,
            },
        ];
        let mut names: Vec<(String, u64)> = listed
            .into_iter()
            .filter_map(|l| {
                let name = l.key.strip_prefix(&bucket_prefix)?;
                (name.starts_with(&name_prefix) && name.ends_with(&name_suffix))
                    .then(|| (name.to_string(), l.size))
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ("sqlite-1.sqlite3".to_string(), 11),
                ("sqlite-2.sqlite3".to_string(), 22),
            ]
        );
    }

    /// The manifest is a sibling of the dumps inside the backup prefix.
    #[test]
    fn manifest_key_lives_inside_the_backup_prefix() {
        for remote in ["r2:bucket", "r2:bucket/sub"] {
            let sync = SyncConfig::new(
                remote.into(),
                "id".into(),
                "s".into(),
                "http://127.0.0.1:1".into(),
                Duration::from_secs(60),
            )
            .unwrap();
            let cfg = crate::runtime::backup::support::cfg_with_sync(sync);
            assert_eq!(manifest_key(&cfg), format!("{}manifest", cfg.prefix()));
            assert!(!manifest_key(&cfg).contains("//"));
        }
    }
}
