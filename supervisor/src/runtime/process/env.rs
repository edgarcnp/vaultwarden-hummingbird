//! Child-environment grants: one generic mechanism for "what environment
//! does this child get?" Every child spawn clears the inherited
//! environment and applies an explicit grant — a layered filter over the
//! ambient env plus hard pins (built last, so nothing overrides them).
//! Consumers:
//! bounded CLI runs (allow-listed plumbing only, see [`super::run`]) and
//! the vaultwarden child (default-deny `VAULTWARDEN_*` routing, see
//! `runtime::services::vaultwarden`).
//!
//! Layering rule: later layers override earlier ones, so the grant is
//! built weakest-first (file defaults, then ambient overrides, then
//! pins). Values stay raw `OsString`s: a non-UTF-8 value is the child's
//! business, not something to mangle here.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Command;

pub struct EnvGrant(BTreeMap<String, OsString>);

impl EnvGrant {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Add one layer of entries (later layers win over earlier ones).
    pub fn layer(mut self, vars: impl IntoIterator<Item = (String, OsString)>) -> Self {
        for (k, v) in vars {
            self.0.insert(k, v);
        }
        self
    }

    /// Pin a key, overriding everything layered before it. Grant
    /// builders apply pins last, so in practice nothing overrides them.
    pub fn pin(mut self, key: &str, value: &str) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// Apply to a command: clears its environment first, so the child
    /// receives exactly the granted keys and nothing else.
    pub fn apply(&self, cmd: &mut Command) {
        cmd.env_clear();
        for (k, v) in &self.0 {
            cmd.env(k, v);
        }
    }

    /// The granted entries (for pure tests of grant policies).
    #[cfg(test)]
    pub fn iter(&self) -> impl Iterator<Item = (&String, &OsString)> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_layers_override_earlier_pins_override_all() {
        let grant = EnvGrant::new()
            .layer([("A".into(), "file".into()), ("B".into(), "file".into())])
            .layer([("A".into(), "ambient".into())])
            .pin("A", "pinned");
        let env: std::collections::BTreeMap<String, String> = grant
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string_lossy().into_owned()))
            .collect();
        assert_eq!(env.get("A").map(String::as_str), Some("pinned"));
        assert_eq!(env.get("B").map(String::as_str), Some("file"));
    }

    /// Applying clears the command's environment: nothing inherited
    /// leaks through.
    #[test]
    fn apply_clears_then_grants() {
        let mut cmd = Command::new("unused");
        cmd.env("INHERITED", "leak");
        EnvGrant::new()
            .layer([("A".into(), "1".into())])
            .apply(&mut cmd);
        let envs: std::collections::BTreeMap<String, String> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.expect("set, not removed").to_string_lossy().into_owned(),
                )
            })
            .collect();
        assert_eq!(
            envs,
            std::collections::BTreeMap::from([("A".into(), "1".into())])
        );
    }

    /// Raw non-UTF-8 values survive the grant untouched.
    #[test]
    fn raw_values_survive() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let raw = OsString::from_vec(vec![0xff]);
        let grant = EnvGrant::new().layer([("K".into(), raw)]);
        let (_, v) = grant.iter().next().unwrap();
        assert_eq!(v.as_bytes(), &[0xff]);
    }
}
