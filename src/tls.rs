//! TLS configuration (rustls).
//!
//! rustls is a sans-I/O state machine: the worker feeds it ciphertext read
//! from the socket and sends the ciphertext it produces, so it composes
//! naturally with io_uring (no `AsyncRead`/`AsyncWrite` adapters).
//!
//! Each worker builds **its own** `ServerConfig`, so nothing TLS-related is
//! shared across cores. The trade-off: session tickets and the session cache
//! are per core, so a reconnecting client lands on a random core and usually
//! does a full handshake. Sharing ticket keys by message passing is a later
//! optimisation.

use rustls::crypto::ring as provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// ALPN protocols offered, in preference order.
pub const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

fn load_pems(cert: &Path, key: &Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_file = File::open(cert).map_err(|e| format!("tls.cert {}: {e}", cert.display()))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| format!("tls.cert {}: {e}", cert.display()))?;
    if certs.is_empty() {
        return Err(format!("tls.cert {}: no certificates found", cert.display()));
    }

    let key_file = File::open(key).map_err(|e| format!("tls.key {}: {e}", key.display()))?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("tls.key {}: {e}", key.display()))?
        .ok_or_else(|| format!("tls.key {}: no private key found", key.display()))?;
    Ok((certs, key))
}

/// TLS 1.3 only, ALPN `h3`: the configuration QUIC requires (RFC 9001).
/// Wrapped into a QUIC server configuration by [`crate::quic`].
pub fn build_quic_tls(cert: &Path, key: &Path) -> Result<ServerConfig, String> {
    let (certs, key) = load_pems(cert, key)?;
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls: {e}"))?;
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    // 0-RTT stays disabled (max_early_data_size = 0): replayable requests are not safe by default.
    Ok(cfg)
}

pub fn build_server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let (certs, key) = load_pems(cert, key)?;
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls: {e}"))?;

    cfg.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    // Stateless session tickets (per-worker keys, see module docs).
    cfg.ticketer = provider::Ticketer::new().map_err(|e| format!("tls ticketer: {e}"))?;
    Ok(Arc::new(cfg))
}
