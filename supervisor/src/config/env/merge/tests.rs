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
    // no authkey from env or file, no state sync: fail closed
    let map: BTreeMap<String, String> = BTreeMap::new();
    assert!(
        Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none(),
        "missing TAILSCALE_AUTHKEY without state sync must refuse to start"
    );
    // empty is as good as missing
    let map: BTreeMap<String, String> = [("TAILSCALE_AUTHKEY".to_string(), String::new())]
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
    ]
    .into_iter()
    .collect();
    let cfg = Config::build(FileConfig::default(), move |k| map.get(k).cloned())
        .expect("empty key with sync configured is fine");
    assert_eq!(cfg.authkey, None);
    // sync knobs WITHOUT the credentials are not state sync: still
    // fail closed
    let map: BTreeMap<String, String> = [("SUPERVISOR_S3_REMOTE".to_string(), "r2:vw".to_string())]
        .into_iter()
        .collect();
    assert!(
        Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none(),
        "a remote without credentials is not an identity source"
    );
}

#[test]
fn defaults_and_merge_order() {
    let cfg = mk(&[]);
    assert_eq!(cfg.port, "8080");
    assert_eq!(cfg.vault_port.as_deref(), Some("8081"));
    assert_eq!(cfg.socket, "/tmp/tailscaled.sock");
    assert_eq!(cfg.state, "/data/tailscaled.state");
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

/// The vault's DB URL follows the same env > file precedence the child
/// env applies, so the supervisor's backup target is always the DB the
/// vault actually uses.
#[test]
fn db_url_env_wins_over_file() {
    let s3: &[(&str, &str)] = &[
        ("SUPERVISOR_S3_REMOTE", "r2:vw"),
        ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
        ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
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
