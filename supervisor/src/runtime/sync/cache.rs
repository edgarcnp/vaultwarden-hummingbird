//! Local hash cache: remembers each synced file's SHA-256 keyed by
//! (size, mtime), so a quiet push does not re-hash gigabytes every tick.
//! Best-effort only: a missing or corrupt cache costs hashing, never
//! correctness — the remote manifest stays the authority for content.

use std::collections::BTreeMap;

use crate::util::make_private;

/// On the data volume, outside the synced set (the allowlist enumerates
/// concrete paths, and a dotfile is not one of them).
pub(super) const CACHE_PATH: &str = "/data/.sync-cache";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cached {
    size: u64,
    mtime: u64,
    sha256: String,
}

#[derive(Default)]
pub(super) struct Cache {
    entries: BTreeMap<String, Cached>,
    dirty: bool,
}

impl Cache {
    /// Load the cache; any problem (missing, unreadable, malformed) just
    /// yields an empty cache — the next push hashes and rewrites it.
    pub(super) fn load() -> Self {
        std::fs::read_to_string(CACHE_PATH)
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    fn parse(text: &str) -> Self {
        let mut cache = Self::default();
        let mut lines = text.lines();
        if lines.next() != Some("v1") {
            return cache;
        }
        for line in lines {
            let mut parts = line.splitn(4, ' ');
            let (Some(sha256), Some(size), Some(mtime), Some(rel)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let (Ok(size), Ok(mtime)) = (size.parse::<u64>(), mtime.parse::<u64>()) else {
                continue;
            };
            if sha256.len() != 64 || rel.is_empty() {
                continue;
            }
            cache.entries.insert(
                rel.to_string(),
                Cached {
                    size,
                    mtime,
                    sha256: sha256.to_string(),
                },
            );
        }
        cache
    }

    /// The remembered hash, only while (size, mtime) still match. `mtime 0`
    /// (an unavailable clock) never matches: hash instead of guessing.
    pub(super) fn hash_of(&self, rel: &str, size: u64, mtime: u64) -> Option<&str> {
        if mtime == 0 {
            return None;
        }
        self.entries
            .get(rel)
            .filter(|cached| cached.size == size && cached.mtime == mtime)
            .map(|cached| cached.sha256.as_str())
    }

    pub(super) fn record(&mut self, rel: &str, size: u64, mtime: u64, sha256: String) {
        let entry = Cached {
            size,
            mtime,
            sha256,
        };
        if self.entries.get(rel) != Some(&entry) {
            self.entries.insert(rel.to_string(), entry);
            self.dirty = true;
        }
    }

    /// Persist the cache. Best-effort: a failed write only means the next
    /// push re-hashes.
    pub(super) fn save(&self) {
        if !self.dirty {
            return;
        }
        let mut out = String::from("v1\n");
        for (rel, cached) in &self.entries {
            out.push_str(&format!(
                "{} {} {} {}\n",
                cached.sha256, cached.size, cached.mtime, rel
            ));
        }
        if std::fs::write(CACHE_PATH, out).is_ok() {
            let _ = make_private(CACHE_PATH);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_lookup_requires_an_exact_size_and_mtime_match() {
        let mut cache = Cache::default();
        cache.record("a", 10, 100, "a".repeat(64));
        assert_eq!(cache.hash_of("a", 10, 100), Some("a".repeat(64).as_str()));
        assert_eq!(cache.hash_of("a", 11, 100), None, "size changed");
        assert_eq!(cache.hash_of("a", 10, 101), None, "mtime changed");
        assert_eq!(cache.hash_of("b", 10, 100), None, "unknown file");
        assert_eq!(cache.hash_of("a", 10, 0), None, "no clock: always hash");
    }

    #[test]
    fn recording_is_idempotent_and_save_is_dirty_gated() {
        let mut cache = Cache::default();
        assert!(!cache.dirty);
        cache.record("a", 10, 100, "a".repeat(64));
        assert!(cache.dirty);
        cache.dirty = false;
        cache.record("a", 10, 100, "a".repeat(64));
        assert!(!cache.dirty, "identical entry records nothing");
        cache.record("a", 10, 100, "b".repeat(64));
        assert!(cache.dirty);
    }

    #[test]
    fn malformed_cache_loads_empty() {
        // The cache is never authority: a truncated file just costs hashing.
        for bad in ["", "v2\n", "v1\ngarbage\n", "v1\nshort 1 2 rel\n"] {
            let cache = Cache::parse(bad);
            assert!(
                cache.hash_of("rel", 1, 2).is_none(),
                "must not trust {bad:?}"
            );
        }
        // A valid entry round-trips.
        let sha = "a".repeat(64);
        let parsed = Cache::parse(&format!("v1\n{sha} 10 20 rel with spaces\n"));
        assert_eq!(
            parsed.hash_of("rel with spaces", 10, 20),
            Some(sha.as_str())
        );
    }
}
