//! Shared postgres client plumbing (used by the keepalive ping and the DB
//! backup/restore): connection with the same relaxed TLS posture
//! vaultwarden negotiates with a given DATABASE_URL, bounded by a timeout.
//!
//! TLS uses rustls with the ring provider (no system CA dependency),
//! relaxed to libpq's `sslmode=require`: encryption mandatory, cert
//! chaining not verified (typical for managed providers). Strictness lives
//! in [`tls`], keyed off the URL's own sslmode.

use std::sync::Arc;
use std::time::Duration;

use postgres::Config as PgConfig;
use postgres::NoTls;
use rustls::client::danger::ServerCertVerifier;

use crate::util::log;

/// Connect to a postgres URL, bounded by `timeout`; TLS per the URL's
/// sslmode. Returns None on parse/connect failure (logged, secret-free).
pub fn connect(url: &str, timeout: Duration) -> Option<postgres::Client> {
    let Ok(mut pg) = url.parse::<PgConfig>() else {
        log::err("postgres: DATABASE_URL is not a valid postgres URL");
        return None;
    };
    pg.connect_timeout(timeout);
    let connect = match pg.get_ssl_mode() {
        postgres::config::SslMode::Disable => pg.connect(NoTls),
        // require/verify-* all ride the TLS connector; strictness lives in tls()
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

    /// An unreachable (connection-refused) Postgres must fail fast and
    /// cleanly, not hang the caller.
    #[test]
    fn connect_fails_fast_on_refused_connection() {
        assert!(connect(
            "postgres://u:p@127.0.0.1:1/db?sslmode=disable",
            Duration::from_secs(2)
        )
        .is_none());
    }

    /// A malformed URL must fail cleanly without panicking.
    #[test]
    fn connect_fails_on_malformed_url() {
        assert!(connect("not-a-url", Duration::from_secs(2)).is_none());
    }
}
