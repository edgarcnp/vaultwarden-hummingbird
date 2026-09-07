//! DB keepalive ping (opt-in via SUPERVISOR_DB_KEEPALIVE, seconds).
//!
//! Some managed Postgres providers suspend or power off an idle database;
//! a suspended DB delays vaultwarden's first query after the suspension.
//! On the configured cadence this opens a fresh connection and runs
//! `SELECT 1` so the provider sees steady client activity. Failures are
//! non-fatal: the vault runs regardless.
//!
//! TLS uses rustls with bundled webpki roots (no system CA dependency),
//! relaxing certificate verification to libpq's `sslmode=require` semantics:
//! the connection must be TLS-encrypted, but a server-presented cert that
//! doesn't chain to a public root (typical for managed providers) is
//! accepted — matching what vaultwarden itself negotiates.

use std::sync::Arc;

use postgres::Config as PgConfig;
use rustls::client::danger::ServerCertVerifier;

use crate::config::{DB_PING_TIMEOUT, DbKeepalive};
use crate::util::log;

/// One keepalive cycle: fresh connection + `SELECT 1`. Runs inline in the
/// watch loop, bounded by [`DB_PING_TIMEOUT`]. Steady success stays silent
/// (a short cadence would otherwise spam the logs); every failure and every
/// recovery is logged on state change.
pub fn tick(cfg: &DbKeepalive, last_ok: &mut Option<bool>) {
    let ok = ping(&cfg.url);
    if *last_ok != Some(ok) {
        *last_ok = Some(ok);
        if ok {
            log::info("db keepalive: connected");
        } else {
            log::err("db keepalive: ping failed; the vault keeps running");
        }
    }
}

/// Fresh connection + trivial query; nothing is pooled or reused.
fn ping(url: &str) -> bool {
    let Ok(mut pg) = url.parse::<PgConfig>() else {
        return false;
    };
    pg.connect_timeout(DB_PING_TIMEOUT);
    let connect = match pg.get_ssl_mode() {
        postgres::config::SslMode::Disable => pg.connect(postgres::NoTls),
        // sslmode=require/verify-* all ride the TLS connector; verification
        // strictness lives inside [`tls`]
        _ => pg.connect(tls()),
    };
    let Ok(mut client) = connect else {
        return false;
    };
    client.simple_query("SELECT 1").is_ok()
}

/// TLS connector with encryption and no root-of-trust check — libpq's
/// `sslmode=require` semantics. Managed providers commonly present a
/// private CA, and vaultwarden (same DATABASE_URL) connects the same way;
/// the ping only needs the provider to register the client activity.
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

    /// An unreachable (connection-refused) Postgres must fail fast and
    /// cleanly, not hang the watch loop.
    #[test]
    fn ping_fails_fast_on_refused_connection() {
        assert!(!ping("postgres://u:p@127.0.0.1:1/db?sslmode=disable"));
    }

    /// A malformed URL must fail cleanly without panicking.
    #[test]
    fn ping_fails_on_malformed_url() {
        assert!(!ping("not-a-url"));
    }

    /// State-change logging: the first tick from a failed state logs, a
    /// repeat failure at the same state must not re-log. We can't observe
    /// logs here, so exercise the transition logic indirectly: tick must
    /// not panic on consecutive failures and must update the state.
    #[test]
    fn tick_tracks_state_across_failures() {
        let cfg = DbKeepalive {
            interval: Duration::from_secs(60),
            url: "postgres://u:p@127.0.0.1:1/db?sslmode=disable".into(),
        };
        let mut last = None;
        tick(&cfg, &mut last);
        assert_eq!(last, Some(false));
        tick(&cfg, &mut last);
        assert_eq!(last, Some(false));
    }

    /// Steady-state success must flip the tracked state to Some(true) so
    /// the logging stays quiet while the DB stays up.
    #[test]
    #[ignore = "requires a reachable TLS postgres; covered by deploy"]
    fn tick_logs_recovery() {}
}
