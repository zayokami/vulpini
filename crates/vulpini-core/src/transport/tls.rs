//! TLS transport over rustls (ring provider only, webpki roots).

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::common::{BoxedStream, CoreError};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    /// SNI override; defaults to the server host.
    #[serde(default)]
    pub sni: Option<String>,
    /// ALPN protocol ids, e.g. ["h2", "http/1.1"]. Empty = no ALPN.
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Skip certificate verification. Required for self-signed nodes;
    /// the UI must surface this as a warning.
    #[serde(default)]
    pub allow_insecure: bool,
}

pub async fn wrap(
    tcp: TcpStream,
    server_host: &str,
    cfg: &TlsConfig,
) -> Result<BoxedStream, CoreError> {
    crate::ensure_crypto_provider();

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    if !cfg.alpn.is_empty() {
        config.alpn_protocols = cfg.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    if cfg.allow_insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = server_name(cfg.sni.as_deref().unwrap_or(server_host))?;
    let tls =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp)).await??;
    Ok(Box::pin(tls))
}

fn server_name(host: &str) -> Result<ServerName<'static>, CoreError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string())
        .map_err(|_| CoreError::Protocol(format!("invalid tls server name '{host}'")))
}

/// Accepts any certificate. Only used when the node config explicitly
/// sets allow_insecure — never the default.
#[derive(Debug)]
pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
