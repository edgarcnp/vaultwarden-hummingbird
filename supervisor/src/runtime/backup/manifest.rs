//! The backup manifest: the bucket-side authority for the dump set.
//!
//! Object names still carry a timestamp for humans, but ordering comes
//! from a monotonic generation stored here, so a wall-clock step can
//! neither reorder dumps nor make prune delete one just pushed. Restore
//! walks generations newest-first, so a corrupt newest object falls back
//! to the next older one instead of blocking boot, and objects that are
//! not in the manifest (foreign, or orphans from a crash between the
//! object PUT and the manifest PUT) are never treated as backups.
//!
//! Format (line-oriented, no parser dependency):
//!
//! ```text
//! v1
//! 1 sqlite-20260901T010203Z-aabbccdd.sqlite3 983040
//! 2 sqlite-20260927T101112Z-11223344.sqlite3 983552
//! ```
//!
//! Header first, then `<generation> <name> <size>` in strictly ascending
//! generation order.

use anyhow::{bail, ensure};

/// Text cap for the manifest: thousands of entries fit with room to spare.
pub(super) const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub generation: u64,
    pub name: String,
    pub size: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Manifest {
    /// Ascending generation order; the last entry is the current backup.
    entries: Vec<Entry>,
}

impl Manifest {
    pub(super) fn parse(text: &str) -> anyhow::Result<Self> {
        let mut lines = text.lines();
        ensure!(lines.next() == Some("v1"), "missing v1 header");
        let mut entries: Vec<Entry> = Vec::new();
        for (i, line) in lines.enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let (Some(generation), Some(name), Some(size), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                bail!("line {}: want `<generation> <name> <size>`", i + 2);
            };
            let generation: u64 = generation
                .parse()
                .map_err(|_| anyhow::anyhow!("line {}: bad generation", i + 2))?;
            let size: u64 = size
                .parse()
                .map_err(|_| anyhow::anyhow!("line {}: bad size", i + 2))?;
            if entries
                .last()
                .is_some_and(|last| last.generation >= generation)
            {
                bail!("line {}: generations must strictly ascend", i + 2);
            }
            entries.push(Entry {
                generation,
                name: name.to_string(),
                size,
            });
        }
        Ok(Self { entries })
    }

    pub(super) fn render(&self) -> String {
        let mut out = String::from("v1\n");
        for entry in &self.entries {
            out.push_str(&format!(
                "{} {} {}\n",
                entry.generation, entry.name, entry.size
            ));
        }
        out
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The current generation; 0 for an empty manifest.
    pub(super) fn latest(&self) -> u64 {
        self.entries.last().map(|e| e.generation).unwrap_or(0)
    }

    pub(super) fn next_generation(&self) -> u64 {
        self.latest() + 1
    }

    /// Entries newest-first: the order restore tries candidates in.
    pub(super) fn newest_first(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().rev()
    }

    pub(super) fn find_name(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// Append the freshly pushed entry. The caller allocates the
    /// generation from [`Self::next_generation`].
    pub(super) fn push(&mut self, entry: Entry) {
        debug_assert!(entry.generation > self.latest());
        self.entries.push(entry);
    }

    /// Keep the newest `keep` entries, returning the evicted (oldest)
    /// ones so their objects can be deleted *after* the manifest write.
    pub(super) fn retain(&mut self, keep: usize) -> Vec<Entry> {
        if self.entries.len() <= keep {
            return Vec::new();
        }
        self.entries.drain(..self.entries.len() - keep).collect()
    }

    /// The legacy view: a name listing (sorted by name == time order for
    /// the pre-manifest layout), with generations assigned by position.
    /// Used only until the first push persists a real manifest.
    pub(super) fn from_listing(listed: &[(String, u64)]) -> Self {
        let entries = listed
            .iter()
            .enumerate()
            .map(|(i, (name, size))| Entry {
                generation: i as u64 + 1,
                name: name.clone(),
                size: *size,
            })
            .collect();
        Self { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(generation: u64, name: &str, size: u64) -> Entry {
        Entry {
            generation,
            name: name.into(),
            size,
        }
    }

    #[test]
    fn round_trips_through_the_text_format() {
        let mut manifest = Manifest::default();
        manifest.push(entry(1, "sqlite-a.sqlite3", 10));
        manifest.push(entry(2, "sqlite-b.sqlite3", 20));
        let parsed = Manifest::parse(&manifest.render()).expect("round trip");
        assert_eq!(parsed, manifest);
        assert_eq!(parsed.latest(), 2);
        assert_eq!(parsed.next_generation(), 3);
        assert_eq!(
            parsed
                .newest_first()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>(),
            vec!["sqlite-b.sqlite3", "sqlite-a.sqlite3"]
        );
        assert_eq!(parsed.find_name("sqlite-a.sqlite3").unwrap().generation, 1);
        assert!(parsed.find_name("missing").is_none());
    }

    #[test]
    fn rejects_malformed_manifests() {
        for bad in [
            "",
            "v2\n1 a 1\n",
            "v1\na b c\n",
            "v1\n1 a x\n",
            "v1\n1 a 1 2\n",
            "v1\n2 a 1\n1 b 1\n",
            "v1\n1 a 1\n1 b 1\n",
        ] {
            assert!(Manifest::parse(bad).is_err(), "must reject {bad:?}");
        }
        assert!(Manifest::parse("v1\n").unwrap().is_empty());
        assert!(Manifest::parse("v1\n1 a 1\n\n2 b 2\n").is_ok());
    }

    /// Eviction is by generation (oldest first) and happens only above
    /// keep; the returned entries are the objects to delete afterwards.
    #[test]
    fn retain_evicts_the_oldest_generations() {
        let mut manifest = Manifest::default();
        for generation in 1..=5 {
            manifest.push(entry(
                generation,
                &format!("sqlite-{generation}.sqlite3"),
                generation,
            ));
        }
        let evicted = manifest.retain(3);
        assert_eq!(
            evicted.iter().map(|e| e.generation).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(manifest.latest(), 5);
        assert_eq!(manifest.newest_first().count(), 3);
        assert!(
            manifest.retain(3).is_empty(),
            "retaining below keep is a no-op"
        );
    }

    #[test]
    fn from_listing_assigns_ascending_generations() {
        let listed = vec![
            ("sqlite-1.sqlite3".to_string(), 11),
            ("sqlite-2.sqlite3".to_string(), 22),
        ];
        let manifest = Manifest::from_listing(&listed);
        assert_eq!(manifest.latest(), 2);
        assert_eq!(
            manifest.find_name("sqlite-1.sqlite3").unwrap().generation,
            1
        );
        assert_eq!(manifest.find_name("sqlite-2.sqlite3").unwrap().size, 22);
        assert!(Manifest::from_listing(&[]).is_empty());
    }
}
