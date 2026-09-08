//! Scalar knob parsers and validators shared by config resolution: env
//! namespacing, non-empty semantics, port validation, lenient booleans,
//! and the Tailscale Service reference.

use crate::util::log;

/// Supervisor-owned keys (localized to PID 1): filtered out of the
/// vaultwarden child's env.
pub fn is_supervisor_key(key: &str) -> bool {
    key.starts_with("TS_") || key.starts_with("SUPERVISOR_")
}

/// `Some(v)` only for non-empty: empty entries are treated as unset.
pub(super) fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|v| !v.is_empty())
}

/// `Some(v)` only for a valid 1-65535 port; invalid values warn and fall
/// back to the default instead of breaking listeners.
pub(super) fn valid_port(v: Option<String>) -> Option<String> {
    let v = non_empty(v)?;
    match v.parse::<u16>() {
        Ok(p) if p != 0 => Some(v),
        _ => {
            log::err(&format!(
                "config: invalid port '{}' (want 1-65535); using default",
                log::sanitize(&v)
            ));
            None
        }
    }
}

/// Lenient on/off knob parse; `None` = callers warn and use their default.
pub(crate) fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Tailscale Service reference from `TS_SERVICE`: a bare name or an already
/// prefixed `svc:<name>` becomes `svc:<name>`; anything else (empty, bare
/// `svc:`) warns and disables the advertisement.
pub(super) fn resolve_service(v: Option<String>) -> Option<String> {
    let v = non_empty(v)?;
    let name = v.strip_prefix("svc:").unwrap_or(&v);
    if name.is_empty() {
        log::err("config: invalid TS_SERVICE 'svc:' (want svc:<name>); not advertising a service");
        return None;
    }
    Some(format!("svc:{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_keys_are_namespaced() {
        for key in [
            "TS_AUTHKEY",
            "TS_SERVE",
            "SUPERVISOR_ENV_FILE",
            "SUPERVISOR_X",
        ] {
            assert!(is_supervisor_key(key), "{key} should be supervisor-owned");
        }
        for key in ["TS", "SUPERVISOR", "ts_authkey", "PORT", "DATABASE_URL"] {
            assert!(!is_supervisor_key(key), "{key} should reach the child");
        }
    }

    #[test]
    fn port_validation() {
        assert_eq!(valid_port(Some("8080".into())).as_deref(), Some("8080"));
        assert_eq!(valid_port(Some("1".into())).as_deref(), Some("1"));
        assert_eq!(valid_port(Some("65535".into())).as_deref(), Some("65535"));
        assert_eq!(valid_port(Some("0".into())), None);
        assert_eq!(valid_port(Some("65536".into())), None);
        assert_eq!(valid_port(Some("-1".into())), None);
        assert_eq!(valid_port(Some("8080\n".into())), None);
        assert_eq!(valid_port(Some("".into())), None);
        assert_eq!(valid_port(None), None);
        assert_eq!(valid_port(Some("abc".into())), None);
    }

    #[test]
    fn service_reference_resolution() {
        assert_eq!(
            resolve_service(Some("vaultwarden".into())),
            Some("svc:vaultwarden".into())
        );
        assert_eq!(
            resolve_service(Some("svc:vaultwarden".into())),
            Some("svc:vaultwarden".into())
        );
        // unset and empty mean the same: classic serve only
        assert_eq!(resolve_service(None), None);
        assert_eq!(resolve_service(Some(String::new())), None);
        // a bare prefix is a misconfiguration: warn, don't advertise
        assert_eq!(resolve_service(Some("svc:".into())), None);
    }
}
