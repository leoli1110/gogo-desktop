//! HTTPS certificates: use the one provided, or create a self-signed one on
//! first run and print its fingerprint so users can check it.

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct TlsMaterial {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub fingerprint: String,
    pub self_signed: bool,
}

fn fingerprint(cert: &CertificateDer<'_>) -> String {
    Sha256::digest(cert.as_ref()).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

fn load(cert_path: &Path, key_path: &Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = std::fs::read(cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("{} contains no certificate", cert_path.display()));
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or_else(|| anyhow!("{} contains no private key", key_path.display()))?;
    Ok((certs, key))
}

#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict(_path: &Path) {}

/// Loads the configured certificate, or a self-signed one from `dir`
/// (created if missing).
pub fn material(cert: Option<&PathBuf>, key: Option<&PathBuf>, dir: &Path, names: &[String]) -> Result<TlsMaterial> {
    if let (Some(c), Some(k)) = (cert, key) {
        let (certs, key) = load(c, k)?;
        let fp = fingerprint(&certs[0]);
        return Ok(TlsMaterial { certs, key, fingerprint: fp, self_signed: false });
    }
    if cert.is_some() != key.is_some() {
        return Err(anyhow!("set both GOGO_TLS_CERT_FILE and GOGO_TLS_KEY_FILE, or neither"));
    }
    let cert_path = dir.join("self-signed.crt");
    let key_path = dir.join("self-signed.key");
    if !cert_path.exists() || !key_path.exists() {
        std::fs::create_dir_all(dir)?;
        let mut sans: Vec<String> = names.iter().map(|n| n.trim_matches(['[', ']']).to_string()).collect();
        sans.retain(|n| !n.is_empty());
        let generated = rcgen::generate_simple_self_signed(sans).context("creating a self-signed certificate")?;
        std::fs::write(&cert_path, generated.cert.pem())?;
        std::fs::write(&key_path, generated.key_pair.serialize_pem())?;
        restrict(&key_path);
        tracing::info!("created a self-signed HTTPS certificate in {}", dir.display());
    }
    let (certs, key) = load(&cert_path, &key_path)?;
    let fp = fingerprint(&certs[0]);
    Ok(TlsMaterial { certs, key, fingerprint: fp, self_signed: true })
}
