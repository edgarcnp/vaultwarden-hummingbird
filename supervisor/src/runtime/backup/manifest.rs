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
//! `v2` records the SHA-256 of each dump, so restore verifies the exact
//! bytes before importing; `v1` (size only) and legacy names remain
//! readable. A `-` hash marks an entry inherited from that older layout.
//!
//! Format (line-oriented, no parser dependency):
//!
//! ```text
//! v2
//! 1 sqlite-20260901T010203Z-aabbccdd.sqlite3 983040 <sha256>
//! 2 sqlite-20260927T101112Z-11223344.sqlite3 983552 -
//! ```
//!
//! Header first, then `<generation> <name> <size> <sha256|->` in strictly
//! ascending generation order.

use anyhow::{bail, ensure};

/// Text cap for the manifest: thousands of v2 entries fit with room to
/// spare.
pub(super) const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// One dump object recorded in the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    /// Monotonic generation: strictly ascending, never reused, never 0.
    pub generation: u64,
    /// Bare object name inside the backup prefix.
    pub name: String,
    /// Object size in bytes, checked against the download.
    pub size: u64,
    /// Lowercase hex SHA-256; `None` for a v1/legacy entry whose content
    /// hash was never recorded.
    pub sha256: Option<String>,
}

/// The parsed manifest: the authoritative set and order of the dumps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Manifest {
    /// Ascending generation order; the last entry is the current backup.
    entries: Vec<Entry>,
}

impl Manifest {
    /// Parse `v1`/`v2` text, rejecting a bad header, malformed fields, a
    /// duplicate name, or generations that do not strictly ascend.
    pub(super) fn parse(text: &str) -> anyhow::Result<Self> {
        let mut lines = text.lines();
        let version = match lines.next() {
            Some("v1") => 1,
            Some("v2") => 2,
            _ => bail!("missing v1/v2 header"),
        };
        let mut entries: Vec<Entry> = Vec::new();
        for (i, line) in lines.enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.splitn(if version == 2 { 4 } else { 3 }, ' ');
            let (Some(generation), Some(name), Some(size)) =
                (fields.next(), fields.next(), fields.next())
            else {
                bail!(
                    "line {}: want `<generation> <name> <size>{}`",
                    i + 2,
                    if version == 2 { " <sha256|->" } else { "" }
                );
            };
            let generation: u64 = generation
                .parse()
                .map_err(|_| anyhow::anyhow!("line {}: bad generation", i + 2))?;
            let size: u64 = size
                .parse()
                .map_err(|_| anyhow::anyhow!("line {}: bad size", i + 2))?;
            ensure!(generation > 0, "line {}: generation 0 is reserved", i + 2);
            ensure!(valid_name(name), "line {}: invalid object name", i + 2);
            let sha256 = if version == 2 {
                let Some(value) = fields.next() else {
                    bail!("line {}: missing sha256", i + 2);
                };
                if value == "-" {
                    None
                } else {
                    ensure!(
                        value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()),
                        "line {}: bad sha256",
                        i + 2
                    );
                    Some(value.to_ascii_lowercase())
                }
            } else {
                None
            };
            ensure!(fields.next().is_none(), "line {}: trailing fields", i + 2);
            if entries
                .last()
                .is_some_and(|last| last.generation >= generation)
            {
                bail!("line {}: generations must strictly ascend", i + 2);
            }
            ensure!(
                !entries.iter().any(|entry| entry.name == name),
                "line {}: duplicate name {name}",
                i + 2
            );
            entries.push(Entry {
                generation,
                name: name.to_string(),
                size,
                sha256,
            });
        }
        Ok(Self { entries })
    }

    /// Render as `v2` text; an unknown content hash prints as `-`.
    pub(super) fn render(&self) -> String {
        let mut out = String::from("v2\n");
        for entry in &self.entries {
            out.push_str(&format!(
                "{} {} {} {}\n",
                entry.generation,
                entry.name,
                entry.size,
                entry.sha256.as_deref().unwrap_or("-")
            ));
        }
        out
    }

    /// Whether no generation is recorded.
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The current generation; 0 for an empty manifest.
    pub(super) fn latest(&self) -> u64 {
        self.entries.last().map(|e| e.generation).unwrap_or(0)
    }

    /// The next generation, or `None` once the `u64` space is exhausted:
    /// wrapping to 0 would write a manifest that can never be parsed again,
    /// so the push refuses instead (fail closed; clear the bucket to
    /// recover).
    pub(super) fn next_generation(&self) -> Option<u64> {
        self.latest().checked_add(1)
    }

    /// Entries newest-first: the order restore tries candidates in.
    pub(super) fn newest_first(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().rev()
    }

    /// Look up an entry by its bare object name.
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
            .filter(|(name, _)| valid_name(name))
            .enumerate()
            .map(|(i, (name, size))| Entry {
                generation: i as u64 + 1,
                name: name.clone(),
                size: *size,
                sha256: None,
            })
            .collect();
        Self { entries }
    }
}

/// A dump object name generated by this process, or an older name that is
/// still safe to address as a bucket key and round-trip through the
/// line-oriented manifest: no separators, traversal, whitespace, control
/// characters, or surrounding spaces.
pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.trim() == name
        && !name.contains('/')
        && !name.contains("..")
        && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Parser, rendering, eviction, and legacy-listing rules.
#[cfg(test)]
mod tests {
    use super::*;

    /// Build an entry for the tests below.
    fn entry(generation: u64, name: &str, size: u64, sha256: Option<&str>) -> Entry {
        Entry {
            generation,
            name: name.into(),
            size,
            sha256: sha256.map(str::to_string),
        }
    }

    #[test]
    fn round_trips_v2_with_hashes_and_unknown_hashes() {
        let mut manifest = Manifest::default();
        manifest.push(entry(1, "sqlite-a.sqlite3", 10, Some(&"a".repeat(64))));
        manifest.push(entry(2, "sqlite-b.sqlite3", 20, None));
        let parsed = Manifest::parse(&manifest.render()).expect("round trip");
        assert_eq!(parsed, manifest);
        assert_eq!(parsed.latest(), 2);
        assert_eq!(parsed.next_generation(), Some(3));
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

    /// A v1 manifest remains readable; its entries carry no content hash.
    #[test]
    fn v1_entries_are_size_only() {
        let parsed = Manifest::parse("v1\n1 sqlite-a.sqlite3 10\n").expect("v1 parses");
        assert_eq!(parsed.latest(), 1);
        assert_eq!(parsed.newest_first().next().unwrap().sha256, None);
        // Rendering upgrades the format but keeps the unknown hash.
        assert!(parsed.render().starts_with("v2\n"));
        assert!(parsed.render().contains(" -"));
    }

    /// The generation space is never wrapped: an exhausted manifest loads
    /// but cannot be extended, so the push refuses instead of writing a
    /// manifest that strict ascending order would reject forever.
    #[test]
    fn generation_space_is_not_wrapped() {
        let manifest = Manifest::parse("v1\n18446744073709551615 a 1\n").expect("u64::MAX parses");
        assert_eq!(manifest.next_generation(), None);
        assert_eq!(Manifest::default().next_generation(), Some(1));
    }

    #[test]
    fn rejects_malformed_manifests() {
        for bad in [
            "",
            "v3\n1 a 1\n",
            "v2\n1 a 1\n",
            "v2\n1 a 1 not-a-hash\n",
            "v2\n1 a 1 {}\nmore\n",
            "v1\n1 a 1 2\n",
            "v1\n2 a 1\n1 b 1\n",
            "v1\n1 a 1\n1 b 1\n",
            "v1\n0 a 1\n",
            "v1\n1 a 1\n2 a 2\n",
            "v1\n1 ../a 1\n",
            "v1\n1 a/b 1\n",
            "v1\n1 a b 1\n",
            "v1\n1 a\tb 1\n",
        ] {
            let filled = bad.replace("{}", &"c".repeat(64));
            assert!(Manifest::parse(&filled).is_err(), "must reject {filled:?}");
        }
        assert!(Manifest::parse("v1\n").unwrap().is_empty());
        assert!(Manifest::parse("v2\n").unwrap().is_empty());
        assert!(Manifest::parse("v1\n1 a 1\n\n2 b 2\n").is_ok());
        assert!(
            Manifest::parse(&format!("v2\n1 a 1 {}\n", "A".repeat(64)))
                .unwrap()
                .newest_first()
                .next()
                .unwrap()
                .sha256
                .as_deref()
                == Some(&"a".repeat(64))
        );
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
                None,
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
            ("../bad".to_string(), 33),
        ];
        let manifest = Manifest::from_listing(&listed);
        assert_eq!(manifest.latest(), 2);
        assert_eq!(
            manifest.find_name("sqlite-1.sqlite3").unwrap().generation,
            1
        );
        assert_eq!(manifest.find_name("sqlite-1.sqlite3").unwrap().size, 11);
        assert_eq!(manifest.find_name("sqlite-2.sqlite3").unwrap().sha256, None);
        assert!(manifest.find_name("../bad").is_none());
        assert!(Manifest::from_listing(&[]).is_empty());
    }
}
