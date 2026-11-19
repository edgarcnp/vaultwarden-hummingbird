use std::collections::BTreeMap;
use std::fs;

use super::*;
use crate::config::env::knobs::is_supervisor_key;

/// Config from an explicit variable map + optional dotenv file layer
/// (never the process env — see [`Config::build`]). TAILSCALE_AUTHKEY
/// is required, so tests inject a default.
fn mk(vars: &[(&str, &str)]) -> Config {
    mk_with_file(vars, FileConfig::default())
}

/// Like [`mk`], but a refusal is the expected result rather than a panic.
fn mk_opt(vars: &[(&str, &str)]) -> Option<Config> {
    let map: BTreeMap<String, String> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Config::build(FileConfig::default(), move |k| match map.get(k) {
        Some(v) => Some(v.clone()),
        None if k == "TAILSCALE_AUTHKEY" => Some("test-key".to_string()),
        None => None,
    })
}

fn mk_with_file(vars: &[(&str, &str)], file: FileConfig) -> Config {
    let map: BTreeMap<String, String> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let file_has_key = file.knobs.contains_key("TAILSCALE_AUTHKEY");
    Config::build(file, move |k| match map.get(k) {
        Some(v) => Some(v.clone()),
        // TAILSCALE_AUTHKEY is required; tests without one (in env or
        // file) get a placeholder so unrelated knobs stay exercisable
        None if k == "TAILSCALE_AUTHKEY" && !file_has_key => Some("test-key".to_string()),
        None => None,
    })
    .expect("test config always resolves")
}

#[test]
fn authkey_required_unless_sync_can_restore_the_identity() {
    // no authkey from env or file, no state sync, no local state: fail closed
    let map: BTreeMap<String, String> = [(
        "TAILSCALE_STATE_FILE".to_string(),
        "/state/nonexistent-vw-sup.state".to_string(),
    )]
    .into_iter()
    .collect();
    assert!(
        Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none(),
        "missing TAILSCALE_AUTHKEY without state sync or a local state must refuse to start"
    );
    // empty is as good as missing
    let map: BTreeMap<String, String> = [
        ("TAILSCALE_AUTHKEY".to_string(), String::new()),
        (
            "TAILSCALE_STATE_FILE".to_string(),
            "/state/nonexistent-vw-sup.state".to_string(),
        ),
    ]
    .into_iter()
    .collect();
    assert!(Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none());
    // file layer satisfies the requirement too
    let file = FileConfig::load_from(Some(&env_dotenv("TAILSCALE_AUTHKEY=file-key\n")));
    let cfg = Config::build(file, |_| None).expect("file key satisfies the gate");
    assert_eq!(cfg.authkey.as_deref(), Some("file-key"));
    // no authkey, but state sync configured: the bucket supplies the
    // node identity, so the key is optional
    let map: BTreeMap<String, String> = [
        ("SUPERVISOR_S3_REMOTE".to_string(), "r2:vw".to_string()),
        ("SUPERVISOR_S3_ACCESS_KEY_ID".to_string(), "id".to_string()),
        (
            "SUPERVISOR_S3_SECRET_ACCESS_KEY".to_string(),
            "sec".to_string(),
        ),
        (
            "SUPERVISOR_S3_ENDPOINT".to_string(),
            "https://s3.example.invalid".to_string(),
        ),
    ]
    .into_iter()
    .collect();
    let cfg = Config::build(FileConfig::default(), move |k| map.get(k).cloned())
        .expect("state sync replaces the authkey requirement");
    assert_eq!(cfg.authkey, None);
    assert!(cfg.sync.is_some());
    // an explicit empty key with sync configured passes the same way
    let map: BTreeMap<String, String> = [
        ("TAILSCALE_AUTHKEY".to_string(), String::new()),
        ("SUPERVISOR_S3_REMOTE".to_string(), "r2:vw".to_string()),
        ("SUPERVISOR_S3_ACCESS_KEY_ID".to_string(), "id".to_string()),
        (
            "SUPERVISOR_S3_SECRET_ACCESS_KEY".to_string(),
            "sec".to_string(),
        ),
        (
            "SUPERVISOR_S3_ENDPOINT".to_string(),
            "https://s3.example.invalid".to_string(),
        ),
    ]
    .into_iter()
    .collect();
    let cfg = Config::build(FileConfig::default(), move |k| map.get(k).cloned())
        .expect("empty key with sync configured is fine");
    assert_eq!(cfg.authkey, None);
    // sync knobs WITHOUT the credentials are not state sync: still
    // fail closed
    let map: BTreeMap<String, String> = [
        ("SUPERVISOR_S3_REMOTE".to_string(), "r2:vw".to_string()),
        (
            "TAILSCALE_STATE_FILE".to_string(),
            "/state/nonexistent-vw-sup.state".to_string(),
        ),
    ]
    .into_iter()
    .collect();
    assert!(
        Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none(),
        "a remote without credentials is not an identity source"
    );
}

/// A local state file is a valid identity source on a persistent volume;
/// a `mem:` state or one outside the sync root cannot be supplied by S3.
#[test]
fn authkey_gate_considers_the_local_state_and_sync_coverage() {
    let root = std::env::temp_dir().join(format!("vw-sup-state-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let state = root.join("tailscaled.state");
    std::fs::write(&state, b"identity").unwrap();
    let socket = root.join("tailscaled.sock");

    let map: BTreeMap<String, String> = [
        (
            "TAILSCALE_STATE_FILE".to_string(),
            state.to_string_lossy().into_owned(),
        ),
        (
            "TAILSCALE_SOCKET".to_string(),
            socket.to_string_lossy().into_owned(),
        ),
    ]
    .into_iter()
    .collect();
    let cfg = Config::build_at(&root, FileConfig::default(), move |k| map.get(k).cloned())
        .expect("a valid local state is an identity source");
    assert_eq!(cfg.authkey, None);

    let sync: &[(&str, &str)] = &[
        ("SUPERVISOR_S3_REMOTE", "r2:vw"),
        ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
        ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
        ("SUPERVISOR_S3_ENDPOINT", "https://s3.example.invalid"),
    ];
    for state in ["mem:", "/state/sub/node.state"] {
        let mut map: BTreeMap<String, String> = sync
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        map.insert("TAILSCALE_STATE_FILE".into(), state.into());
        map.insert(
            "TAILSCALE_SOCKET".into(),
            socket.to_string_lossy().into_owned(),
        );
        assert!(
            Config::build_at(&root, FileConfig::default(), move |k| map.get(k).cloned()).is_none(),
            "{state}: sync cannot supply an identity it does not cover"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Temporary storage is strict: an explicitly configured S3/backup feature
/// that cannot work refuses the boot; with no such feature it warns and
/// continues.
#[test]
fn temporary_storage_strictness() {
    let base: &[(&str, &str)] = &[
        ("SUPERVISOR_EPHEMERAL", "true"),
        ("TAILSCALE_AUTHKEY", "test-key"),
    ];
    // Remote with no credentials: S3 requested, sync unusable.
    let mut vars = base.to_vec();
    vars.push(("SUPERVISOR_S3_REMOTE", "r2:vw"));
    assert!(
        Config::build(FileConfig::default(), move |k| vars
            .iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.to_string()))
        .is_none(),
        "temporary storage must refuse an unusable S3 config"
    );
    // Backup requested without a usable sync.
    let mut vars = base.to_vec();
    vars.push(("SUPERVISOR_DB_BACKUP", "true"));
    assert!(
        Config::build(FileConfig::default(), move |k| vars
            .iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.to_string()))
        .is_none(),
        "temporary storage must refuse an unusable backup config"
    );
    // No persistence feature: warn and boot.
    let vars = base.to_vec();
    assert!(
        Config::build(FileConfig::default(), move |k| vars
            .iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.to_string()))
        .is_some(),
        "temporary storage without S3/backup is allowed (with a warning)"
    );
}

#[test]
fn defaults_and_merge_order() {
    let cfg = mk(&[]);
    assert_eq!(cfg.port, "8080");
    assert_eq!(cfg.vault_port.as_deref(), Some("8081"));
    assert_eq!(cfg.socket, "/state/tailscaled.sock");
    assert_eq!(cfg.state, "/state/tailscaled.state");
    assert_eq!(cfg.hostname, "vaultwarden-hummingbird");
    assert_eq!(cfg.authkey.as_deref(), Some("test-key"));
    assert!(cfg.serve && cfg.userspace);
    assert_eq!(cfg.service, None);
    assert!(cfg.vw_env.is_empty());
    assert!(cfg.sync.is_none());

    let cfg = mk(&[("VAULTWARDEN_PORT", "3000")]);
    assert_eq!(cfg.port, "3000");
    assert_eq!(cfg.vault_port.as_deref(), Some("3001"));
    let cfg = mk(&[("VAULTWARDEN_PORT", "")]);
    assert_eq!(cfg.port, "8080");

    // 65535 leaves no room above the exposed port: fail closed.
    let cfg = mk(&[("VAULTWARDEN_PORT", "65535")]);
    assert_eq!(cfg.port, "65535");
    assert_eq!(cfg.vault_port, None);
}

#[test]
fn dotenv_file_merges_below_process_env() {
    let path = std::env::temp_dir().join(format!("vw-sup-cfg-{}.env", std::process::id()));
    fs::write(
            &path,
            "VAULTWARDEN_PORT=2222\nTAILSCALE_HOSTNAME=file-host\nTAILSCALE_AUTHKEY=file-key\nTAILSCALE_SERVE=false\nVAULTWARDEN_DOMAIN=https://f.example\n",
        )
        .unwrap();
    let path_str = path.to_str().unwrap();

    let cfg = mk_with_file(&[], FileConfig::load_from(Some(path_str)));
    assert_eq!(cfg.port, "2222");
    assert_eq!(cfg.hostname, "file-host");
    assert_eq!(cfg.authkey.as_deref(), Some("file-key"));
    assert!(!cfg.serve);
    assert!(cfg.userspace);
    assert_eq!(
        cfg.vw_env
            .iter()
            .find(|(k, _)| k == "DOMAIN")
            .map(|(_, v)| v.as_str()),
        Some("https://f.example")
    );
    assert!(cfg.vw_env.iter().any(|(k, _)| k == "DOMAIN"));
    assert!(!cfg.vw_env.iter().any(|(k, _)| is_supervisor_key(k)));
    // the port knob stays with the supervisor (the child's port is pinned)
    assert!(!cfg.vw_env.iter().any(|(k, _)| k == "ROCKET_PORT"));

    // process env wins over the file for supervisor knobs
    let cfg = mk_with_file(
        &[("TAILSCALE_HOSTNAME", "env-host")],
        FileConfig::load_from(Some(path_str)),
    );
    assert_eq!(cfg.hostname, "env-host");
    let _ = fs::remove_file(&path);
}

#[test]
fn lenient_bool_knobs() {
    let cfg = mk(&[("TAILSCALE_SERVE", "YES"), ("TAILSCALE_USERSPACE", "0")]);
    assert!(cfg.serve);
    assert!(!cfg.userspace);

    // misspelling warns and takes the default
    let cfg = mk(&[("TAILSCALE_SERVE", "definitely")]);
    assert!(cfg.serve);
}

/// The gatekeeper port has ONE spelling, `VAULTWARDEN_PORT`, in both
/// layers, env first. The file's VAULTWARDEN_PORT previously leaked
/// to the child as PORT instead of being consumed.
#[test]
fn port_resolves_from_env_then_file() {
    // file spelling (documented in .env.example)
    let cfg = mk_with_file(
        &[],
        FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_PORT=8443\n"))),
    );
    assert_eq!(cfg.port, "8443");
    assert_eq!(cfg.vault_port.as_deref(), Some("8444"));
    // env beats the file
    let cfg = mk_with_file(
        &[("VAULTWARDEN_PORT", "3000")],
        FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_PORT=8443\n"))),
    );
    assert_eq!(cfg.port, "3000");
    // an invalid env value warns and falls through to the file
    let cfg = mk_with_file(
        &[("VAULTWARDEN_PORT", "not-a-port")],
        FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_PORT=8443\n"))),
    );
    assert_eq!(cfg.port, "8443");
}

/// Legacy port spellings refuse the boot with a message naming the
/// one valid spelling — they once changed behavior, so silently
/// ignoring them would silently change the deployment.
#[test]
fn legacy_port_spellings_refuse_the_boot() {
    // env alias
    let map: BTreeMap<String, String> =
        [("VAULTWARDEN_ROCKET_PORT".to_string(), "3001".to_string())]
            .into_iter()
            .collect();
    assert!(Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none());
    // file alias (routed to knobs, refused at resolution)
    let cfg = Config::build(
        FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_ROCKET_PORT=8445\n"))),
        |_| None,
    );
    assert!(cfg.is_none());
    // file's bare ROCKET_PORT
    let cfg = Config::build(
        FileConfig::load_from(Some(&env_dotenv("ROCKET_PORT=8446\n"))),
        |_| None,
    );
    assert!(cfg.is_none());
}

/// Any other key outside the three namespaces in the dotenv file
/// refuses the boot, naming the keys (a typo or legacy spelling must
/// never be silently ignored).
#[test]
fn unrecognized_file_keys_refuse_the_boot() {
    let cfg = Config::build(
        FileConfig::load_from(Some(&env_dotenv(
            "DATABASE_URL=sqlite:///data/db.sqlite3\nDOMAIN=https://x.example\n",
        ))),
        |_| None,
    );
    assert!(cfg.is_none());
    // a VAULTWARDEN_ key stripping into the supervisor namespace too
    let cfg = Config::build(
        FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_TAILSCALE_AUTHKEY=x\n"))),
        |_| None,
    );
    assert!(cfg.is_none());
}

/// A configured-but-unreadable dotenv file refuses the boot: the
/// supervisor must not silently run on env-only defaults.
#[test]
fn unreadable_dotenv_file_refuses_the_boot() {
    let file = FileConfig {
        fatal: Some("config: cannot read /config/.env: no such file".to_string()),
        ..FileConfig::default()
    };
    assert!(Config::build(file, |_| None).is_none());
}

/// The vault's DB URL follows the same env > file precedence the child
/// env applies, so the supervisor's backup target is always the DB the
/// vault actually uses.
#[test]
fn db_url_env_wins_over_file() {
    let s3: &[(&str, &str)] = &[
        ("SUPERVISOR_S3_REMOTE", "r2:vw"),
        ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
        ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
        ("SUPERVISOR_S3_ENDPOINT", "https://s3.example.invalid"),
        ("SUPERVISOR_DB_BACKUP", "true"),
    ];
    let mut env: Vec<(&str, &str)> = s3.to_vec();
    env.push(("VAULTWARDEN_DATABASE_URL", "sqlite:///data/env.sqlite3"));
    let cfg = mk_with_file(
        &env,
        FileConfig::load_from(Some(&env_dotenv(
            "VAULTWARDEN_DATABASE_URL=sqlite:///data/file.sqlite3\n",
        ))),
    );
    assert_eq!(
        cfg.backup.as_ref().expect("backup enabled").db_path,
        "/data/env.sqlite3"
    );

    // file-only still resolves
    let cfg = mk_with_file(
        s3,
        FileConfig::load_from(Some(&env_dotenv(
            "VAULTWARDEN_DATABASE_URL=sqlite:///data/file.sqlite3\n",
        ))),
    );
    assert_eq!(
        cfg.backup.as_ref().expect("backup enabled").db_path,
        "/data/file.sqlite3"
    );
}

/// An empty ambient DB URL is unset, not an override: the file value
/// still wins (the same rule the child env applies).
#[test]
fn empty_env_db_url_falls_back_to_the_file() {
    let s3: &[(&str, &str)] = &[
        ("SUPERVISOR_S3_REMOTE", "r2:vw"),
        ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
        ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
        ("SUPERVISOR_S3_ENDPOINT", "https://s3.example.invalid"),
        ("SUPERVISOR_DB_BACKUP", "true"),
    ];
    let mut env: Vec<(&str, &str)> = s3.to_vec();
    env.push(("VAULTWARDEN_DATABASE_URL", ""));
    let cfg = mk_with_file(
        &env,
        FileConfig::load_from(Some(&env_dotenv(
            "VAULTWARDEN_DATABASE_URL=sqlite:///data/file.sqlite3\n",
        ))),
    );
    assert_eq!(
        cfg.backup.as_ref().expect("backup enabled").db_path,
        "/data/file.sqlite3"
    );
}

#[test]
fn service_knob_merges_over_the_file() {
    let cfg = mk_with_file(
        &[],
        FileConfig::load_from(Some(&env_dotenv("TAILSCALE_SERVICE=file-svc\n"))),
    );
    assert_eq!(cfg.service.as_deref(), Some("svc:file-svc"));

    let cfg = mk_with_file(
        &[("TAILSCALE_SERVICE", "env-svc")],
        FileConfig::load_from(Some(&env_dotenv("TAILSCALE_SERVICE=file-svc\n"))),
    );
    assert_eq!(cfg.service.as_deref(), Some("svc:env-svc"));
}

/// Empty = unset for the service knob too: an empty environment value
/// must fall back to the file instead of silently disabling the
/// advertisement.
#[test]
fn empty_env_service_falls_back_to_the_file() {
    let cfg = mk_with_file(
        &[("TAILSCALE_SERVICE", "")],
        FileConfig::load_from(Some(&env_dotenv("TAILSCALE_SERVICE=file-svc\n"))),
    );
    assert_eq!(cfg.service.as_deref(), Some("svc:file-svc"));
}

#[test]
fn s3_endpoint_defaults_to_https_and_options_apply() {
    let cfg = crate::config::SyncConfig::new(
        "r2:vw".into(),
        "id".into(),
        "sec".into(),
        "s3.example.com".into(),
        std::time::Duration::from_secs(60),
    )
    .expect("a bare host gets the safe scheme");
    assert_eq!(cfg.target.endpoint, "https://s3.example.com");
    assert!(!cfg.target.allow_http);
}

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
/// from it: it must stay on the supervisor-only volume, directly under
/// `/state`, so neither the vault nor a path escape can reach it.
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
    rejects("TAILSCALE_STATE_FILE=/state/sub/node.state\n");

    let file = FileConfig::load_from(Some(&env_dotenv(
        "TAILSCALE_STATE_FILE=/state/node.state\n",
    )));
    let cfg = Config::build(file, lookup).expect("a direct /state child resolves");
    assert_eq!(cfg.state, "/state/node.state");

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
    ] {
        assert!(
            mk_opt(&[("TAILSCALE_SOCKET", socket)]).is_none(),
            "{socket} must refuse the boot"
        );
    }
    for socket in ["/state/tailscaled.sock", "/state/run/tailscaled.sock"] {
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
        let path = format!("/state/{name}");
        assert!(
            mk_opt(&[("TAILSCALE_STATE_FILE", path.as_str())]).is_none(),
            "{name} must be reserved"
        );
    }
    for name in ["node.state", "tailscaled.state", "identity"] {
        let path = format!("/state/{name}");
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
    vars.push(("TAILSCALE_STATE_FILE", "/state/node.state"));
    let cfg = mk(&vars);
    assert_eq!(cfg.state, "/state/node.state");
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
    vars.push(("TAILSCALE_STATE_FILE", "/state/config.json"));
    assert!(
        mk_opt(&vars).is_none(),
        "a colliding state name must refuse"
    );

    // Outside /state cannot ride along and must refuse the boot, not
    // silently run the identity on a volume the vault can rewrite.
    let mut vars = SYNC.to_vec();
    vars.push(("TAILSCALE_STATE_FILE", "/state/sub/node.state"));
    assert!(
        mk_opt(&vars).is_none(),
        "an identity outside /state must refuse"
    );

    // A subdirectory would put tailscaled's cert cache outside the synced
    // cert tree; only a direct child is covered.
    let mut vars = SYNC.to_vec();
    vars.push(("TAILSCALE_STATE_FILE", "/state/sub/node.state"));
    assert!(
        mk_opt(&vars).is_none(),
        "a state file in a subdirectory must refuse"
    );
}

/// One-key dotenv file for the merge tests above. Unique per call:
/// tests run in parallel threads of one process, and a shared path
/// would let one test's write race another test's read.
fn env_dotenv(contents: &str) -> String {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("vw-sup-svc-{}-{n}.env", std::process::id()));
    fs::write(&path, contents).unwrap();
    path.to_str().unwrap().to_string()
}
