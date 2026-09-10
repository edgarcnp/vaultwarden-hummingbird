//! Shared postgres client plumbing (used by the keepalive ping and the DB
//! backup/restore): bounded connection built from the parsed [`DbSpec`]
//! (one URL parse for the whole supervisor), with the same relaxed TLS
//! posture vaultwarden negotiates with a given database URL. rustls + ring
//! (no system CA dependency), relaxed to libpq's `sslmode=require` for
//! every TLS mode: encryption mandatory, cert chaining not verified —
//! typical for managed providers, the same posture vaultwarden itself
//! accepts (`verify-ca`/`verify-full` in the URL are NOT honored).
//!
//! Deliberate tradeoff, not an oversight: this connection carries the same
//! trust vaultwarden itself places in the URL. Strict modes fail closed —
//! the sslmode mapping below rejects `verify-ca`/`verify-full` before any
//! connection is attempted, so no silent downgrade exists. Residual risk,
//! accepted: with auto-restore enabled, the emptiness check and backup
//! download run over this connection, so a MITM on the DB path can pose as
//! an empty database and receive the backup dump.

use std::sync::Arc;
use std::time::Duration;

use postgres::Config as PgConfig;
use postgres::NoTls;
use postgres::config::SslMode;
use rustls::client::danger::ServerCertVerifier;

use crate::config::DbSpec;
use crate::util::log;

/// Connect to a postgres [`DbSpec`], bounded by `timeout`; TLS per the
/// spec's sslmode. Returns None on an unusable spec (logged, secret-free).
pub fn connect(db: &DbSpec, timeout: Duration) -> Option<postgres::Client> {
    let DbSpec::Postgres {
        host,
        port,
        user,
        password,
        db,
        sslmode,
    } = db
    else {
        log::err("postgres: the supervisor's native client only speaks postgres");
        return None;
    };
    // No host means the libpq default local socket. The native client has
    // no such default (tokio-postgres errors on a missing host), so this
    // fails closed — the dump/restore tools still cover that deployment.
    let Some(host) = host else {
        log::err("postgres: URL has no host (default-socket form); native client unsupported");
        return None;
    };
    let ssl_mode = match sslmode.as_deref() {
        None => SslMode::Prefer, // libpq's default
        Some("disable") => SslMode::Disable,
        Some("prefer") => SslMode::Prefer,
        Some("require") => SslMode::Require,
        // verify-ca/verify-full cannot be honored here (no root-of-trust
        // plumbing; see the connector below) — same fail-closed parse the
        // URL parser applied.
        Some(other) => {
            log::err(&format!(
                "postgres: unsupported sslmode '{}' (want disable/prefer/require)",
                log::sanitize(other)
            ));
            return None;
        }
    };
    let mut pg = PgConfig::new();
    pg.host(host).port(*port).ssl_mode(ssl_mode);
    if let Some(u) = user {
        pg.user(u);
    }
    if let Some(p) = password {
        pg.password(p);
    }
    if let Some(d) = db {
        pg.dbname(d);
    }
    pg.connect_timeout(timeout);
    let connect = match ssl_mode {
        SslMode::Disable => pg.connect(NoTls),
        // prefer/require ride the TLS connector; verification stays
        // relaxed (see tls())
        _ => pg.connect(tls()),
    };
    match connect {
        Ok(client) => Some(client),
        Err(e) => {
            log::err(&format!("postgres: connect failed: {e}"));
            None
        }
    }
}

/// TLS connector: encryption, no root-of-trust check (libpq's
/// `sslmode=require`). The ping and the empty-check only need the provider
/// to answer; strict verification would break the typical managed
/// deployment that vaultwarden itself accepts.
fn tls() -> postgres_rustls::MakeTlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|_| unreachable!("TLS 1.3 is supported by the ring provider"))
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    postgres_rustls::MakeTlsConnector::new(Arc::new(config).into())
}

/// Accepts any server certificate; the connection is still fully encrypted.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A spec builder mirroring what dburl::parse produces (tests construct
    /// DbSpec directly; parsing is specced in config::dburl).
    fn spec(sslmode: Option<&str>) -> DbSpec {
        DbSpec::Postgres {
            host: Some("127.0.0.1".into()),
            port: 1,
            user: Some("u".into()),
            password: Some("p".into()),
            db: Some("db".into()),
            sslmode: sslmode.map(String::from),
        }
    }

    /// An unreachable (connection-refused) Postgres must fail fast and
    /// cleanly, not hang the caller.
    #[test]
    fn connect_fails_fast_on_refused_connection() {
        assert!(connect(&spec(Some("disable")), Duration::from_secs(2)).is_none());
        assert!(connect(&spec(Some("require")), Duration::from_secs(2)).is_none());
    }

    /// An absent sslmode defaults to libpq's prefer (TLS attempted): the
    /// refused connection proves the code path ran and failed cleanly.
    #[test]
    fn connect_defaults_to_prefer_without_sslmode() {
        assert!(connect(&spec(None), Duration::from_secs(2)).is_none());
    }

    /// Strict sslmodes cannot be honored by the native client: fail closed.
    #[test]
    fn connect_fails_closed_on_unsupported_sslmode() {
        for mode in ["verify-ca", "verify-full", "allow", "bogus"] {
            assert!(
                connect(&spec(Some(mode)), Duration::from_secs(2)).is_none(),
                "{mode}"
            );
        }
    }

    /// A hostless (default-socket) spec fails closed: the native client has
    /// no libpq default socket.
    #[test]
    fn connect_fails_closed_without_a_host() {
        let db = DbSpec::Postgres {
            host: None,
            port: 5432,
            user: None,
            password: None,
            db: None,
            sslmode: None,
        };
        assert!(connect(&db, Duration::from_secs(2)).is_none());
    }

    /// Only the postgres backend connects; anything else is refused.
    #[test]
    fn connect_refuses_non_postgres_specs() {
        assert!(
            connect(
                &DbSpec::Sqlite {
                    path: "/data/db.sqlite3".into()
                },
                Duration::from_secs(2)
            )
            .is_none()
        );
    }
}
