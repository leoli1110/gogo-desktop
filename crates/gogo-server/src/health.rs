//! `gogo healthcheck`: asks the local server for `/api/health`.

use crate::config::Config;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Accepts any certificate: only used to talk to our own process on loopback.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn loopback(addr: SocketAddr) -> SocketAddr {
    let ip = if addr.ip().is_unspecified() || !addr.ip().is_loopback() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        addr.ip()
    };
    SocketAddr::new(ip, addr.port())
}

async fn ask<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) -> bool {
    let req = "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if s.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; 512];
    let n = s.read(&mut buf).await.unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    head.starts_with("HTTP/1.1 200")
}

pub async fn check(cfg: &Config) -> bool {
    let fut = async {
        if let Some(a) = cfg.http_bind {
            return match tokio::net::TcpStream::connect(loopback(a)).await {
                Ok(s) => ask(s).await,
                Err(_) => false,
            };
        }
        if let Some(a) = cfg.https_bind {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let Ok(builder) =
                rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()
            else {
                return false;
            };
            let cc =
                builder.dangerous().with_custom_certificate_verifier(Arc::new(AnyCert(provider))).with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
            let Ok(tcp) = tokio::net::TcpStream::connect(loopback(a)).await else { return false };
            let name = rustls::pki_types::ServerName::try_from("localhost").expect("valid name");
            return match connector.connect(name, tcp).await {
                Ok(tls) => ask(tls).await,
                Err(_) => false,
            };
        }
        false
    };
    tokio::time::timeout(Duration::from_secs(5), fut).await.unwrap_or(false)
}
