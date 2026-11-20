//! State-volume path policy: identity file, LocalAPI socket, reserved
//! names, and the sync wiring for a custom identity.

use super::super::env_file_isolated;
use super::{env_dotenv, mk, mk_opt};
use crate::config::Config;
use crate::config::dotenv::FileConfig;

/// The dotenv file carries the auth key and S3 credentials; it must be on
/// the supervisor-only volume, not somewhere the vault can read it.
#[test]
fn the_dotenv_must_live_on_the_state_volume() {
    assert!(env_file_isolated("/state/.env"));
    assert!(env_file_isolated("/state/config/.env"));
    assert!(!env_file_isolated("/config/.env"));
    assert!(!env_file_isolated("state/.env"));
    assert!(!env_file_isolated("/state-evil/.env"));
    // A textual prefix is not enough: this resolves onto the vault volume.
    assert!(!env_file_isolated("/state/../data/.env"));
    // A `.` component is normalized away and stays under the state root.
    assert!(env_file_isolated("/state/./.env"));
}

/// The state file anchors the node identity and the `--statedir` derived
/// from it: it must stay in the group-writable `/state/tailscale` subtree,
/// directly under it, so neither the vault nor a path escape can reach it.
#[test]
fn state_file_must_live_directly_under_the_state_root() {
    let lookup = |key: &str| (key == "TAILSCALE_AUTHKEY").then(|| "test-key".to_string());
    let rejects = |contents: &str| {
        let file = FileConfig::load_from(Some(&env_dotenv(contents)));
        assert!(
            Config::build(file, lookup).is_none(),
            "{contents:?} must refuse the boot"
        );
    };
    rejects("TAILSCALE_STATE_FILE=state/tailscaled.state\n");
    rejects("TAILSCALE_STATE_FILE=/data/tailscaled.state\n");
    rejects("TAILSCALE_STATE_FILE=/custom/tailscaled.state\n");
    rejects("TAILSCALE_STATE_FILE=/state/../data/tailscaled.state\n");
    rejects("TAILSCALE_STATE_FILE=/state/tailscaled.state\n");
    rejects("TAILSCALE_STATE_FILE=/state/tailscale/sub/node.state\n");

    let file = FileConfig::load_from(Some(&env_dotenv(
        "TAILSCALE_STATE_FILE=/state/tailscale/node.state\n",
    )));
    let cfg = Config::build(file, lookup).expect("a direct subtree child resolves");
    assert_eq!(cfg.state, "/state/tailscale/node.state");

    // A direct environment value keeps its whitespace; a trailing space is
    // a different (and unsafe) identity name.
    assert!(
        mk_opt(&[("TAILSCALE_STATE_FILE", "/state/tailscale/node.state ")]).is_none(),
        "a trailing-space identity name must refuse"
    );

    // `mem:` is Tailscale's in-memory state: accepted, no path check
    let cfg = mk(&[("TAILSCALE_STATE_FILE", "mem:")]);
    assert_eq!(cfg.state, "mem:");
}

/// The LocalAPI socket is supervisor-only too: a socket on the vault's
/// volume could be deleted or impersonated by the vault uid.
#[test]
fn socket_must_live_under_the_state_root() {
    for socket in [
        "/data/tailscaled.sock",
        "/custom/tailscaled.sock",
        "/state/../data/tailscaled.sock",
        "tailscaled.sock",
        "/state/tailscaled.sock",
        "/state/tailscale/tailscaled.sock ",
    ] {
        assert!(
            mk_opt(&[("TAILSCALE_SOCKET", socket)]).is_none(),
            "{socket} must refuse the boot"
        );
    }
    for socket in [
        "/state/tailscale/tailscaled.sock",
        "/state/tailscale/run/tailscaled.sock",
    ] {
        let cfg = mk(&[("TAILSCALE_SOCKET", socket)]);
        assert_eq!(cfg.socket, socket);
    }
}

/// A custom state file must not collide with any supervisor-owned name or
/// namespace, even before state sync is enabled (it may be enabled later).
#[test]
fn reserved_state_names_refuse_the_boot() {
    for name in [
        "config.json",
        "manifest",
        "tombstones",
        ".layout-v2",
        ".sync-cache",
        ".sync-repair",
        ".sync-missing",
        "db",
        "db-backups",
        "db-backups.state",
        "objects",
        "attachments",
        "sends",
        "certs",
        "rsa_key.pem",
    ] {
        let path = format!("/state/tailscale/{name}");
        assert!(
            mk_opt(&[("TAILSCALE_STATE_FILE", path.as_str())]).is_none(),
            "{name} must be reserved"
        );
    }
    for name in ["node.state", "tailscaled.state", "identity"] {
        let path = format!("/state/tailscale/{name}");
        assert!(
            mk_opt(&[("TAILSCALE_STATE_FILE", path.as_str())]).is_some(),
            "{name} must be a usable identity name"
        );
    }
}

/// A custom state file under /state is wired into the sync set, so state
/// sync still carries the node identity; one outside /state cannot be
/// covered (the boot succeeds, loudly).
#[test]
fn custom_state_files_are_wired_into_sync() {
    const SYNC: &[(&str, &str)] = &[
        ("SUPERVISOR_S3_REMOTE", "r2:vw"),
        ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
        ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "sec"),
        ("SUPERVISOR_S3_ENDPOINT", "https://s3.example.invalid"),
    ];

    let mut vars = SYNC.to_vec();
    vars.push(("TAILSCALE_STATE_FILE", "/state/tailscale/node.state"));
    let cfg = mk(&vars);
    assert_eq!(cfg.state, "/state/tailscale/node.state");
    assert_eq!(
        cfg.sync
            .as_ref()
            .expect("sync configured")
            .state_file
            .as_deref(),
        Some("node.state")
    );

    // A state file that collides with a vault data key would shadow it in
    // the bucket: refuse the boot rather than merge two different files.
    let mut vars = SYNC.to_vec();
    vars.push(("TAILSCALE_STATE_FILE", "/state/tailscale/config.json"));
    assert!(
        mk_opt(&vars).is_none(),
        "a colliding state name must refuse"
    );

    // Outside /state cannot ride along and must refuse the boot, not
    // silently run the identity on a volume the vault can rewrite.
    let mut vars = SYNC.to_vec();
    vars.push(("TAILSCALE_STATE_FILE", "/state/tailscaled.state"));
    assert!(
        mk_opt(&vars).is_none(),
        "an identity outside the subtree must refuse"
    );

    // A deeper subdirectory would put tailscaled's cert cache outside the
    // synced cert tree; only a direct child is covered.
    let mut vars = SYNC.to_vec();
    vars.push(("TAILSCALE_STATE_FILE", "/state/tailscale/sub/node.state"));
    assert!(
        mk_opt(&vars).is_none(),
        "a state file in a subdirectory must refuse"
    );
}
