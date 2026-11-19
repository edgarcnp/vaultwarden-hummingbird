//! Deletion lifecycle for the durable set. The vault never tells the
//! supervisor "I deleted this"; a missing file can be a user deletion, a
//! partially restored volume, or a failed mount. A single missing file is
//! therefore never enough:
//!
//! 1. every successful push records when a manifest file was first missing
//!    locally (a small sidecar on `/state`);
//! 2. after [`TOMBSTONE_GRACE`] consecutive absence, and only below a
//!    mass-deletion guard, the file becomes a tombstone: its manifest
//!    entry is removed and the tombstone is published to the bucket;
//! 3. pulls and reconciliation skip tombstoned paths, so a legacy key or a
//!    crash-left object cannot resurrect the file;
//! 4. a file that reappears locally clears its tombstone on the next push
//!    (an intentional restore wins).
//!
//! Objects for a tombstoned path are deleted by the bounded GC once the
//! tombstone is [`TOMBSTONE_GRACE`] old; the tombstone itself is pruned
//! after [`TOMBSTONE_RETENTION`]. The bucket stays the disaster-recovery
//! source: a deletion only wins after a day of consistent evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::util::fs::{read_capped, write_atomic};
use crate::util::log;

/// The bucket object holding the tombstone list (inside the sync prefix).
pub(super) const TOMBSTONES_NAME: &str = "tombstones";
pub(super) const MAX_TOMBSTONES_BYTES: u64 = 4 * 1024 * 1024;

/// A file missing from the local volumes becomes a tombstone after this
/// long. Long enough that a transient restore failure or a short-lived
/// fresh volume cannot delete bucket data.
pub(super) const TOMBSTONE_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// Tombstones are kept this long after creation, then pruned (the objects
/// are already gone by then).
pub(super) const TOMBSTONE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// A batch larger than this is treated as volume loss, not user intent.
pub(super) const MAX_TOMBSTONES_PER_RUN: usize = 32;

/// Bounded object deletions per GC pass; the next pass continues.
pub(super) const MAX_GC_DELETES: usize = 1000;

pub(super) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Tombstones {
    entries: BTreeMap<String, u64>,
}

impl Tombstones {
    pub(super) fn parse(text: &str) -> anyhow::Result<Self> {
        let mut lines = text.lines();
        anyhow::ensure!(lines.next() == Some("v1"), "missing v1 header");
        let mut entries = BTreeMap::new();
        for (i, line) in lines.enumerate() {
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, ' ');
            let (Some(stamp), Some(rel)) = (parts.next(), parts.next()) else {
                anyhow::bail!("line {}: want `<deleted_at> <rel>`", i + 2);
            };
            let stamp: u64 = stamp
                .parse()
                .map_err(|_| anyhow::anyhow!("line {}: bad timestamp", i + 2))?;
            anyhow::ensure!(!rel.is_empty(), "line {}: empty path", i + 2);
            anyhow::ensure!(
                !rel.chars().any(char::is_control),
                "line {}: control character",
                i + 2
            );
            entries.insert(rel.to_string(), stamp);
        }
        Ok(Self { entries })
    }

    pub(super) fn render(&self) -> String {
        let mut out = String::from("v1\n");
        for (rel, stamp) in &self.entries {
            out.push_str(&format!("{stamp} {rel}\n"));
        }
        out
    }

    pub(super) fn contains(&self, rel: &str) -> bool {
        self.entries.contains_key(rel)
    }

    pub(super) fn insert(&mut self, rel: String) {
        self.entries.insert(rel, now_unix());
    }

    pub(super) fn remove(&mut self, rel: &str) -> bool {
        self.entries.remove(rel).is_some()
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tombstones old enough for their objects to be deleted, and those
    /// old enough to prune entirely.
    pub(super) fn gc_candidates(&self, now: u64) -> (Vec<String>, Vec<String>) {
        let grace = TOMBSTONE_GRACE.as_secs();
        let retention = TOMBSTONE_RETENTION.as_secs();
        let mut deletable = Vec::new();
        let mut prunable = Vec::new();
        for (rel, stamp) in &self.entries {
            if now.saturating_sub(*stamp) >= grace {
                deletable.push(rel.clone());
            }
            if now.saturating_sub(*stamp) >= retention {
                prunable.push(rel.clone());
            }
        }
        (deletable, prunable)
    }
}

/// Local first-seen records for manifest files that are absent from the
/// current scan. A file that reappears is removed immediately.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Missing {
    entries: BTreeMap<String, u64>,
}

impl Missing {
    fn path(state_dir: &str) -> PathBuf {
        Path::new(state_dir).join(".sync-missing")
    }

    pub(super) fn load(state_dir: &str) -> Self {
        let text = read_capped(&Self::path(state_dir).to_string_lossy(), 16 * 1024 * 1024)
            .unwrap_or_default();
        let mut entries = BTreeMap::new();
        for line in text.lines() {
            let mut parts = line.splitn(2, ' ');
            let (Some(stamp), Some(rel)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(stamp) = stamp.parse::<u64>() else {
                continue;
            };
            if !rel.is_empty() && !rel.chars().any(char::is_control) {
                entries.insert(rel.to_string(), stamp);
            }
        }
        Self { entries }
    }

    pub(super) fn save(&self, state_dir: &str) {
        let path = Self::path(state_dir);
        if self.entries.is_empty() {
            let _ = std::fs::remove_file(&path);
            return;
        }
        let mut text = String::new();
        for (rel, stamp) in &self.entries {
            text.push_str(&format!("{stamp} {rel}\n"));
        }
        if let Err(e) = write_atomic(&path.to_string_lossy(), text.as_bytes(), 0o600) {
            log::err(&format!(
                "state sync: cannot record the pending-deletion list ({e})"
            ));
        }
    }

    /// Record first-seen for `missing`, and forget files that reappeared.
    pub(super) fn observe(&mut self, missing: &BTreeSet<String>, now: u64) {
        self.entries.retain(|rel, _| missing.contains(rel));
        for rel in missing {
            self.entries.entry(rel.clone()).or_insert(now);
        }
    }

    /// Files absent for at least `grace`.
    pub(super) fn expired(&self, now: u64) -> Vec<String> {
        let grace = TOMBSTONE_GRACE.as_secs();
        self.entries
            .iter()
            .filter(|(_, stamp)| now.saturating_sub(**stamp) >= grace)
            .map(|(rel, _)| rel.clone())
            .collect()
    }

    pub(super) fn remove(&mut self, rel: &str) {
        self.entries.remove(rel);
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tombstones_round_trip_including_spaces() {
        let mut list = Tombstones::default();
        list.insert("attachments/my file".into());
        list.insert("rsa_key.pem".into());
        let parsed = Tombstones::parse(&list.render()).expect("round trip");
        assert_eq!(parsed, list);
        assert!(parsed.contains("attachments/my file"));
        assert!(!parsed.contains("attachments/other"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn malformed_tombstones_are_rejected() {
        for bad in [
            "",
            "v2\n",
            "v1\nnonsense\n",
            "v1\nnotanumber rel\n",
            "v1\n1 \n",
            "v1\n1 bad\nname\n",
        ] {
            assert!(Tombstones::parse(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn missing_tracks_first_seen_and_forgets_reappearance() {
        let mut missing = Missing::default();
        let missing_now: BTreeSet<String> = ["a".into(), "b".into()].into_iter().collect();
        missing.observe(&missing_now, 100);
        assert_eq!(missing.expired(100), Vec::<String>::new());
        assert_eq!(
            missing.expired(100 + TOMBSTONE_GRACE.as_secs()),
            vec!["a", "b"]
        );
        let only_a: BTreeSet<String> = ["a".into()].into_iter().collect();
        missing.observe(&only_a, 200);
        assert!(!missing.entries.contains_key("b"));
        missing.remove("a");
        assert!(missing.is_empty());
    }

    #[test]
    fn missing_sidecar_is_owner_only_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("vw-sup-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.to_string_lossy().into_owned();
        let mut missing = Missing::default();
        missing.observe(&["a".into()].into_iter().collect(), 42);
        missing.save(&state);
        assert_eq!(Missing::load(&state), missing);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(Missing::path(&state))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gc_candidates_respect_grace_and_retention() {
        let mut list = Tombstones::default();
        let now = TOMBSTONE_RETENTION.as_secs() + 1;
        list.entries.insert("old".into(), 0);
        list.entries
            .insert("grace".into(), now - TOMBSTONE_GRACE.as_secs());
        list.entries
            .insert("recent".into(), now - TOMBSTONE_GRACE.as_secs() + 1);
        let (deletable, prunable) = list.gc_candidates(now);
        assert_eq!(deletable, vec!["grace", "old"]);
        assert_eq!(prunable, vec!["old"]);
    }
}
