//! Bucket helpers for the backup cycle, over the in-crate S3 client
//! ([`crate::s3`]). The sqlite dump/restore itself is in-process
//! (`sqlite/`).

use crate::config::{DbBackupConfig, SYNC_TIMEOUT};
pub(crate) use crate::s3::Client;

/// One client for a backup run. `None` = unusable configuration (logged
/// by the client); callers skip the run rather than guess.
pub(crate) fn client(cfg: &DbBackupConfig) -> Option<Client> {
    Client::new(&cfg.sync, SYNC_TIMEOUT).ok()
}

/// The dump objects in the bucket under the backup prefix
/// (`<prefix>/<label>-*.sqlite3`), as bare names sorted so name order ==
/// creation order. None = listing failed — callers must never delete
/// blind.
pub(crate) fn list_objects(
    client: &Client,
    cfg: &DbBackupConfig,
    abort: &impl Fn() -> bool,
) -> Option<Vec<String>> {
    let keys = client.list(&cfg.prefix(), abort).ok()?;
    let bucket_prefix = cfg.prefix();
    let name_prefix = format!("{}-", cfg.db_label());
    let name_suffix = format!(".{}", cfg.db_ext());
    let mut names: Vec<String> = keys
        .into_iter()
        .map(|listed| listed.key)
        .filter_map(|key| {
            let name = key.strip_prefix(&bucket_prefix)?;
            (name.starts_with(&name_prefix) && name.ends_with(&name_suffix))
                .then(|| name.to_string())
        })
        .collect();
    names.sort();
    Some(names)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::config::SyncConfig;
    use crate::s3::Listed;

    #[test]
    fn listing_filters_to_dump_names_only() {
        // parse the strip/filter logic without a bucket: same closure
        // shape as list_objects, exercised on a synthetic listing
        let sync = SyncConfig::new(
            "r2:vw-state".into(),
            "id".into(),
            "s".into(),
            String::new(),
            Duration::from_secs(60),
        )
        .unwrap();
        let cfg = crate::runtime::backup::support::cfg_with_sync(sync);
        let bucket_prefix = cfg.prefix();
        let name_prefix = format!("{}-", cfg.db_label());
        let name_suffix = format!(".{}", cfg.db_ext());
        let listed = vec![
            format!("{}sqlite-1.sqlite3", bucket_prefix),
            "certs/x".to_string(),
            format!("{}sqlite-not-a-dump.txt", bucket_prefix),
            format!("{}sqlite-2.sqlite3", bucket_prefix),
        ];
        let mut names: Vec<String> = listed
            .into_iter()
            .map(|key| Listed { key, size: 0 })
            .filter_map(|l| {
                let name = l.key.strip_prefix(&bucket_prefix)?;
                (name.starts_with(&name_prefix) && name.ends_with(&name_suffix))
                    .then(|| name.to_string())
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "sqlite-1.sqlite3".to_string(),
                "sqlite-2.sqlite3".to_string()
            ]
        );
    }
}
