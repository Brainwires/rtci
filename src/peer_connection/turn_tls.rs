//! TLS for TURN over TLS (`turns:`, RFC 8656 section 3.1, RFC 7350 for the URI), as a
//! [`StreamLayer`] around rustls used sans-I/O: `rustls::ClientConnection` reads and writes
//! byte buffers, never a socket.
//!
//! The ALPN identifier is `stun.turn` (RFC 7443). Certificates are verified against the roots
//! or the verifier the application gives ([`TurnTlsConfig`]), or, with the `turn-tls-webpki-roots`
//! feature, the Mozilla roots of `webpki-roots`; without one of them no `turns:` server is
//! contacted (an unverifiable TLS server is no better than none).

use shared::error::{Error, Result};
use shared::stream::StreamLayer;
use std::io::{Read, Write};
use std::sync::Arc;

/// The ALPN protocol id of TURN (RFC 7443 section 3).
pub const ALPN_STUN_TURN: &[u8] = b"stun.turn";

/// How the engine's TURN-over-TLS connections verify the server
/// (`SettingEngineBuilder::with_turn_tls`).
#[derive(Clone, Default)]
pub struct TurnTlsConfig {
    /// Trusted roots.
    pub roots: Option<Arc<rustls::RootCertStore>>,
    /// A verifier of the application's, used instead of the roots.
    pub verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
    /// Use the `webpki-roots` (Mozilla) roots when neither of the above is given. Needs the
    /// `turn-tls-webpki-roots` feature.
    pub webpki_roots: bool,
    /// TLS 1.2 is offered besides TLS 1.3 (RFC 8656 section 3.1 allows both). On by default:
    /// deployed servers still need it, such as coturn 4.6.1 (what Ubuntu 24.04 and Debian 13
    /// ship), which refuses a ClientHello that offers TLS 1.3 alone and settles on TLS 1.2 when
    /// both are offered (fixed in coturn 4.6.2).
    pub disable_tls12: bool,
}

impl std::fmt::Debug for TurnTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnTlsConfig")
            .field("roots", &self.roots.as_ref().map(|r| r.len()))
            .field("verifier", &self.verifier.is_some())
            .field("webpki_roots", &self.webpki_roots)
            .field("disable_tls12", &self.disable_tls12)
            .finish()
    }
}

/// The rustls provider of the engine's crypto backend (ring first when both are built, as
/// elsewhere in the engine), else the process default.
pub(crate) fn rustls_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    #[cfg(feature = "crypto-ring")]
    {
        Some(Arc::new(rustls::crypto::ring::default_provider()))
    }
    #[cfg(all(feature = "crypto-aws-lc-rs", not(feature = "crypto-ring")))]
    {
        Some(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    }
    #[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
    {
        rustls::crypto::CryptoProvider::get_default().cloned()
    }
}

impl TurnTlsConfig {
    /// The rustls client configuration, or `None` when nothing could verify a server.
    pub(crate) fn client_config(&self) -> Result<Option<Arc<rustls::ClientConfig>>> {
        let Some(provider) = rustls_provider() else {
            return Ok(None);
        };
        let versions: &[&'static rustls::SupportedProtocolVersion] = if self.disable_tls12 {
            &[&rustls::version::TLS13]
        } else {
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        };
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| Error::Other(format!("TURN TLS versions: {e}")))?;
        let mut config = if let Some(verifier) = &self.verifier {
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth()
        } else if let Some(roots) = &self.roots {
            builder
                .with_root_certificates(roots.clone())
                .with_no_client_auth()
        } else if self.webpki_roots {
            #[cfg(feature = "turn-tls-webpki-roots")]
            {
                let roots = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            #[cfg(not(feature = "turn-tls-webpki-roots"))]
            {
                return Ok(None);
            }
        } else {
            return Ok(None);
        };
        config.alpn_protocols = vec![ALPN_STUN_TURN.to_vec()];
        Ok(Some(Arc::new(config)))
    }
}

/// rustls's client connection as a stream layer.
pub(crate) struct TlsLayer {
    conn: rustls::ClientConnection,
    peer_closed: bool,
}

impl TlsLayer {
    pub(crate) fn new(config: Arc<rustls::ClientConfig>, server_name: &str) -> Result<Self> {
        let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
            .map_err(|e| Error::Other(format!("TURN TLS server name {server_name}: {e}")))?;
        let conn = rustls::ClientConnection::new(config, name)
            .map_err(|e| Error::Other(format!("TURN TLS: {e}")))?;
        Ok(Self {
            conn,
            peer_closed: false,
        })
    }
}

fn tls_error(e: impl std::fmt::Display) -> Error {
    Error::Other(format!("TURN TLS: {e}"))
}

impl StreamLayer for TlsLayer {
    fn receive(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let n = self.conn.read_tls(&mut data).map_err(tls_error)?;
            if n == 0 {
                break;
            }
            let state = self.conn.process_new_packets().map_err(tls_error)?;
            if state.peer_has_closed() {
                self.peer_closed = true;
            }
        }
        Ok(())
    }

    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> Result<()> {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match self.conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // An end of stream without close_notify: the connection closes anyway.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    self.peer_closed = true;
                    break;
                }
                Err(e) => return Err(tls_error(e)),
            }
        }
        Ok(())
    }

    fn is_established(&self) -> bool {
        !self.conn.is_handshaking()
    }

    fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        self.conn.writer().write_all(plaintext).map_err(tls_error)
    }

    fn write_wire(&mut self, out: &mut Vec<u8>) -> Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(out).map_err(tls_error)?;
        }
        Ok(())
    }

    fn close(&mut self) {
        self.conn.send_close_notify();
    }

    fn peer_closed(&self) -> bool {
        self.peer_closed
    }
}

#[cfg(test)]
mod turn_tls_test;
