//! The sync manifest: the bucket-side record of the last pushed /data
//! state, one `<sha256> <size> <rel>` line per synced file. Pushes compare
//! content against it (not just size), and pulls use its hashes to verify
//! what they write. A missing manifest means the legacy layout (the
//! listing is authoritative); an unreadable one is treated as empty and
//! rebuilt by the next push, loudly.

use std::collections::BTreeMap;

use anyhow::{bail, ensure};

/// The manifest's object name inside the sync prefix. The pull path skips
/// this key: it is the manifest itself, not a synced file.
pub(super) const MANIFEST_NAME: &str = "manifest";

/// Text cap: ~40k entries fit with room to spare.
pub(super) const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Manifest {
    entries: BTreeMap<String, Entry>,
}

impl Manifest {
    pub(super) fn parse(text: &str) -> anyhow::Result<Self> {
        let mut lines = text.lines();
        ensure!(lines.next() == Some("v1"), "missing v1 header");
        let mut entries = BTreeMap::new();
        for (i, line) in lines.enumerate() {
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            // The path is the rest of the line: it may contain spaces.
            let mut parts = line.splitn(3, ' ');
            let (Some(sha256), Some(size), Some(rel)) = (parts.next(), parts.next(), parts.next())
            else {
                bail!("line {}: want `<sha256> <size> <rel>`", i + 2);
            };
            ensure!(
                sha256.len() == 64 && sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "line {}: bad sha256",
                i + 2
            );
            let size: u64 = size
                .parse()
                .map_err(|_| anyhow::anyhow!("line {}: bad size", i + 2))?;
            ensure!(!rel.is_empty(), "line {}: empty path", i + 2);
            entries.insert(
                rel.to_string(),
                Entry {
                    size,
                    sha256: sha256.to_ascii_lowercase(),
                },
            );
        }
        Ok(Self { entries })
    }

    pub(super) fn render(&self) -> String {
        let mut out = String::from("v1\n");
        for (rel, entry) in &self.entries {
            out.push_str(&format!("{} {} {}\n", entry.sha256, entry.size, rel));
        }
        out
    }

    /// Whether the manifest holds no entries (test-only helper).
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn get(&self, rel: &str) -> Option<&Entry> {
        self.entries.get(rel)
    }

    pub(super) fn insert(&mut self, rel: String, entry: Entry) {
        self.entries.insert(rel, entry);
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&String, &Entry)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_entries_including_paths_with_spaces() {
        let mut manifest = Manifest::default();
        manifest.insert(
            "attachments/uuid-1".into(),
            Entry {
                size: 11,
                sha256: "a".repeat(64),
            },
        );
        manifest.insert(
            "certs/my cert.pem".into(),
            Entry {
                size: 22,
                sha256: "b".repeat(64),
            },
        );
        let parsed = Manifest::parse(&manifest.render()).expect("round trip");
        assert_eq!(parsed, manifest);
        assert_eq!(parsed.get("certs/my cert.pem").unwrap().size, 22);
        assert!(parsed.get("missing").is_none());
        assert_eq!(parsed.iter().count(), 2);
        assert!(!parsed.is_empty());
    }

    #[test]
    fn rejects_malformed_manifests() {
        for bad in [
            "",
            "v2\n",
            "v1\nnonsense\n",
            "v1\nnothex 1 rel\n",
            "v1\nshort 1 rel\n",
            "v1\n{} x rel\n",
            "v1\n{} 1 \n",
        ] {
            let filled = bad.replace("{}", &"c".repeat(64));
            assert!(Manifest::parse(&filled).is_err(), "must reject {filled:?}");
        }
        assert!(Manifest::parse("v1\n").unwrap().is_empty());
        assert!(Manifest::parse("v1\n\n").unwrap().is_empty());
    }
}
