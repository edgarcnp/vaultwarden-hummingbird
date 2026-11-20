//! End-to-end backup tick: dump -> manifest v2 -> prune, and the
//! missing-newest repair, over a stateful fake bucket.

use std::time::Duration;

use crate::config::SyncConfig;
use crate::util::hash::sha256_bytes;

use super::manifest::Manifest;
use super::support::{self, FakeBucket};
use super::tick;

fn dump_keys(bucket: &FakeBucket) -> Vec<String> {
    bucket
        .objects
        .lock()
        .unwrap()
        .keys()
        .filter(|key| key.starts_with("db/sqlite-"))
        .cloned()
        .collect()
}

fn bucket_manifest(bucket: &FakeBucket) -> Manifest {
    let body = bucket.object("db/manifest").expect("manifest written");
    Manifest::parse(std::str::from_utf8(&body).expect("utf-8 manifest")).expect("v2 parses")
}

#[test]
fn tick_pushes_prunes_and_heals_a_deleted_newest() {
    let base = std::env::temp_dir().join(format!("vw-sup-tick-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("state")).unwrap();
    let db = base.join("db.sqlite3");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('one');")
        .unwrap();
    drop(conn);

    let bucket = FakeBucket::start("vw-state");
    let sync = SyncConfig::new(
        "r2:vw-state".into(),
        "id".into(),
        "secret".into(),
        bucket.endpoint.clone(),
        Duration::from_secs(60),
    )
    .expect("valid test remote");
    let mut cfg = support::cfg_with_sync(sync);
    cfg.db_path = db.to_string_lossy().into_owned();
    cfg.staging = base.join("staging").to_string_lossy().into_owned();
    cfg.state_dir = base.join("state").to_string_lossy().into_owned();
    cfg.keep = 1;

    // First tick: empty bucket -> one dump, a v2 manifest, both sidecars.
    tick(&cfg, || false);
    let keys = dump_keys(&bucket);
    assert_eq!(keys.len(), 1, "one dump: {keys:?}");
    let first = keys[0].strip_prefix("db/").unwrap().to_string();
    let manifest = bucket_manifest(&bucket);
    assert_eq!(manifest.latest(), 1);
    let entry = manifest.newest_first().next().expect("one entry");
    assert_eq!(entry.name, first);
    let body = bucket.object(&format!("db/{first}")).expect("dump object");
    assert_eq!(entry.size, body.len() as u64);
    assert_eq!(entry.sha256.as_deref(), Some(sha256_bytes(&body).as_str()));
    assert!(
        std::fs::read_dir(&cfg.staging).unwrap().next().is_none(),
        "staging is swept after the tick"
    );
    let sidecars = std::fs::read_dir(&cfg.state_dir).unwrap().count();
    assert!(sidecars >= 2, "lineage and hash sidecars: {sidecars}");

    // Second tick: the dump is identical and the newest object exists, so
    // the push is skipped (the HEAD check ran).
    tick(&cfg, || false);
    assert_eq!(dump_keys(&bucket).len(), 1, "no redundant object");
    assert_eq!(bucket_manifest(&bucket).latest(), 1);
    assert!(
        bucket
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(method, key)| method == "HEAD" && key == &format!("db/{first}")),
        "the existence check ran"
    );

    // Third tick: the newest object vanished externally; the unchanged
    // dump is re-uploaded, the generation advances, and keep=1 prunes the
    // old object only after the manifest that dropped it.
    bucket
        .objects
        .lock()
        .unwrap()
        .remove(&format!("db/{first}"));
    tick(&cfg, || false);
    let manifest = bucket_manifest(&bucket);
    assert_eq!(manifest.latest(), 2);
    assert_eq!(manifest.newest_first().count(), 1, "keep=1 evicts gen 1");
    let second = manifest.newest_first().next().unwrap().name.clone();
    assert_ne!(second, first);
    assert!(bucket.object(&format!("db/{second}")).is_some());
    let log = bucket.requests.lock().unwrap().clone();
    let manifest_put = log
        .iter()
        .rposition(|(method, key)| method == "PUT" && key == "db/manifest")
        .expect("manifest PUT");
    let delete = log
        .iter()
        .rposition(|(method, key)| method == "DELETE" && key == &format!("db/{first}"))
        .expect("evicted object deleted");
    assert!(
        manifest_put < delete,
        "prune must follow the manifest write: {log:?}"
    );

    let _ = std::fs::remove_dir_all(&base);
}
