//! X.509 certificate management for WebRTC DTLS authentication.
//!
//! This module provides certificate generation, serialization, and management functionality
//! required for securing WebRTC peer-to-peer connections via DTLS (Datagram Transport Layer Security).
//!
//! # Overview
//!
//! WebRTC uses DTLS to encrypt media and data channels. Each peer must have an X.509 certificate
//! to establish secure connections. This module handles:
//!
//! - **Certificate Generation** - Create self-signed certificates with various key types
//! - **Certificate Persistence** - Serialize/deserialize certificates in PEM format
//! - **Fingerprint Calculation** - Generate SHA-256 fingerprints for SDP signaling
//! - **Identity Management** - Maintain consistent identity across sessions
//!
//! # Certificate Types
//!
//! Three cryptographic algorithms are supported:
//!
//! | Algorithm | Performance | Security | Recommendation |
//! |-----------|-------------|----------|----------------|
//! | **ECDSA P-256** | Fast | Strong | ✅ Recommended for most cases |
//! | **Ed25519** | Fastest | Strongest | ✅ Best for security-critical apps |
//! | **RSA-2048** | Slow | Strong | ⚠️ Generation not available |
//!
//! # Examples
//!
//! ## Quick Start - Generate and Use Certificate
//!
//! ```
//! # use std::time::Instant;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::RTCConfigurationBuilder;
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rtc::crypto::{self, SignatureScheme};
//! use rtc::peer_connection::certificate::CertificateParams;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let provider = crypto::default_provider()?;
//! // Generate ECDSA certificate (recommended)
//! let certificate = RTCCertificate::generate(
//!     provider.crypto(),
//!     SignatureScheme::EcdsaP256Sha256,
//!     CertificateParams::new(vec!["localhost".to_owned()])?,
//! )?;
//!
//! // Use in peer connection
//! let peer_connection = RTCPeerConnectionBuilder::new()
//!     .with_configuration(
//!         RTCConfigurationBuilder::new()
//!             .with_certificates(vec![certificate])
//!             .build()
//!     )
//!     .build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Generate Certificate with Ed25519 (Highest Security)
//!
//! ```
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rtc::crypto::{self, SignatureScheme};
//! use rtc::peer_connection::certificate::CertificateParams;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let provider = crypto::default_provider()?;
//! // Ed25519 provides the best security with excellent performance
//! let certificate = RTCCertificate::generate(
//!     provider.crypto(),
//!     SignatureScheme::Ed25519,
//!     CertificateParams::new(vec!["localhost".to_owned()])?,
//! )?;
//!
//! // Get fingerprint for SDP signaling
//! let fingerprints = certificate.get_fingerprints(provider.crypto())?;
//! println!("Fingerprint: {}", fingerprints[0].value);
//! # Ok(())
//! # }
//! ```
//!
//! ## Persist Certificate Across Sessions
//!
//! ```no_run
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let provider = crypto::default_provider()?;
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rtc::crypto::{self, SignatureScheme};
//! use rtc::peer_connection::certificate::CertificateParams;
//! use std::fs;
//!
//! // First run: Generate and save certificate
//! let certificate = RTCCertificate::generate(
//!     provider.crypto(),
//!     SignatureScheme::EcdsaP256Sha256,
//!     CertificateParams::new(vec!["localhost".to_owned()])?,
//! )?;
//! let pem_data = certificate.serialize_pem()?;
//! fs::write("my_cert.pem", pem_data)?;
//!
//! // Later runs: Load existing certificate
//! let pem_data = fs::read_to_string("my_cert.pem")?;
//! let certificate = RTCCertificate::from_pem(&pem_data, provider.crypto())?;
//! // Same identity maintained across restarts!
//! # Ok(())
//! # }
//! ```
//!
//! ## Extract Fingerprints for SDP Signaling
//!
//! ```
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rtc::crypto::{self, SignatureScheme};
//! use rtc::peer_connection::certificate::CertificateParams;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let provider = crypto::default_provider()?;
//! let certificate = RTCCertificate::generate(
//!     provider.crypto(),
//!     SignatureScheme::EcdsaP256Sha256,
//!     CertificateParams::new(vec!["localhost".to_owned()])?,
//! )?;
//!
//! // Get fingerprints for SDP offer/answer
//! let fingerprints = certificate.get_fingerprints(provider.crypto())?;
//! for fp in fingerprints {
//!     // Format for SDP: a=fingerprint:sha-256 XX:XX:XX:...
//!     println!("a=fingerprint:{} {}", fp.algorithm, fp.value);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Compare Certificate Algorithms
//!
//! ```
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rtc::crypto::{self, SignatureScheme};
//! use rtc::peer_connection::certificate::CertificateParams;
//! use std::time::Instant;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let provider = crypto::default_provider()?;
//! // ECDSA P-256: Good balance of speed and security
//! let start = Instant::now();
//! let _ecdsa_cert = RTCCertificate::generate(
//!     provider.crypto(),
//!     SignatureScheme::EcdsaP256Sha256,
//!     CertificateParams::new(vec!["localhost".to_owned()])?,
//! )?;
//! println!("ECDSA generation: {:?}", start.elapsed());
//!
//! // Ed25519: Fastest and most secure
//! let start = Instant::now();
//! let _ed_cert = RTCCertificate::generate(
//!     provider.crypto(),
//!     SignatureScheme::Ed25519,
//!     CertificateParams::new(vec!["localhost".to_owned()])?,
//! )?;
//! println!("Ed25519 generation: {:?}", start.elapsed());
//! # Ok(())
//! # }
//! ```
//!
//! ## Using External Certificate
//!
//! ```no_run
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use std::time::{SystemTime, Duration};
//!
//! # fn example(dtls_cert: dtls::crypto::Certificate) -> Result<(), Box<dyn std::error::Error>> {
//! // Use certificate from hardware security module or external source
//! let expires = SystemTime::now() + Duration::from_secs(365 * 86400); // Exemption: usage in #doctest code
//! let certificate = RTCCertificate::from_existing(dtls_cert, expires);
//!
//! // Certificate is ready to use in WebRTC connections
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! ## Private Key Protection
//!
//! - **Never** transmit private keys over the network
//! - Store serialized certificates securely (encrypted storage recommended)
//! - Use appropriate file permissions when saving to disk (0600 on Unix)
//! - Consider using platform keystores for production applications
//!
//! ## Certificate Expiration
//!
//! - Default expiration is platform-dependent
//! - On ARM platforms, certificates expire after 48 hours (workaround for overflow bug)
//! - Check certificate validity before each connection
//! - Regenerate certificates before they expire
//!
//! ## Fingerprint Verification
//!
//! - Always verify remote fingerprints via trusted signaling channel
//! - Mismatched fingerprints indicate MITM attack - abort connection
//! - Use out-of-band verification for high-security scenarios
//!
//! # Specification
//!
//! * [W3C RTCCertificate](https://www.w3.org/TR/webrtc/#dom-rtccertificate)
//! * [MDN RTCCertificate](https://developer.mozilla.org/en-US/docs/Web/API/RTCCertificate)
//! * [RFC 5763 - DTLS-SRTP](https://datatracker.ietf.org/doc/html/rfc5763)
//! * [RFC 8122 - WebRTC Security Architecture](https://datatracker.ietf.org/doc/html/rfc8122)

use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crypto::{HashAlgorithm, PublicKeyEncoding, RTCCrypto, SignatureScheme, SigningKey};
/// X.509 certificate parameters — subject alt names, validity window, distinguished name.
///
/// Re-exported from `rcgen` because it appears in [`RTCCertificate::generate`]'s signature and
/// must therefore be nameable without adding a direct `rcgen` dependency. Certificate *format*
/// is deliberately not a crypto-provider concern (see `docs/crypto-provider-decisions.md`), so
/// this type stays an rcgen type rather than being wrapped.
pub use rcgen::CertificateParams;
use rustls::pki_types::CertificateDer;

use crate::peer_connection::transport::dtls::fingerprint::{
    FINGERPRINT_HASHES, RTCDtlsFingerprint, format_fingerprint,
};
use shared::error::{Error, Result};

/// X.509 certificate used to authenticate WebRTC peer-to-peer communications.
///
/// RTCCertificate encapsulates a DTLS certificate and its associated private key,
/// providing secure identity verification during the WebRTC connection establishment
/// process. Certificates can be generated on-demand or loaded from persistent storage.
///
/// # Certificate Lifetime
///
/// Each certificate has an expiration time after which it becomes invalid for use
/// in WebRTC connections. The default lifetime depends on the platform.
///
/// # Supported Key Types
///
/// - **ECDSA P-256** with SHA-256 (recommended for performance)
/// - **Ed25519** (recommended for security)
/// - **RSA** with SHA-256 (key generation not available in this implementation)
///
/// # Examples
///
/// ## Generating a new certificate
///
/// ```
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rtc::crypto::{self, SignatureScheme};
/// # use rtc::peer_connection::certificate::CertificateParams;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let provider = crypto::default_provider()?;
/// // Generate ECDSA P-256 key pair and certificate
/// let certificate = RTCCertificate::generate(
///     provider.crypto(),
///     SignatureScheme::EcdsaP256Sha256,
///     CertificateParams::new(vec!["localhost".to_owned()])?,
/// )?;
///
/// // Certificate is ready to use
/// let fingerprints = certificate.get_fingerprints(provider.crypto())?;
/// println!("Certificate has {} fingerprint(s)", fingerprints.len());
/// # Ok(())
/// # }
/// ```
///
/// ## Generating with Ed25519
///
/// ```
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rtc::crypto::{self, SignatureScheme};
/// # use rtc::peer_connection::certificate::CertificateParams;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let provider = crypto::default_provider()?;
/// // Generate Ed25519 key pair and certificate
/// let certificate = RTCCertificate::generate(
///     provider.crypto(),
///     SignatureScheme::Ed25519,
///     CertificateParams::new(vec!["localhost".to_owned()])?,
/// )?;
///
/// // Get fingerprints for SDP signaling
/// let fingerprints = certificate.get_fingerprints(provider.crypto())?;
/// for fp in fingerprints {
///     println!("Fingerprint ({}):\n{}", fp.algorithm, fp.value);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Persisting and loading certificates
///
/// ```
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rtc::crypto::{self, SignatureScheme};
/// # use rtc::peer_connection::certificate::CertificateParams;
/// # let params = CertificateParams::new(vec!["localhost".to_owned()])?;
/// # let provider = crypto::default_provider()?;
/// # let certificate = RTCCertificate::generate(
/// #     provider.crypto(),
/// #     SignatureScheme::EcdsaP256Sha256,
/// #     params,
/// # )?;
/// // Serialize certificate to PEM format (includes private key)
/// let pem_string = certificate.serialize_pem()?;
///
/// // Save to file or database...
/// // std::fs::write("cert.pem", &pem_string)?;
///
/// // Later, load the certificate back
/// let loaded_cert = RTCCertificate::from_pem(&pem_string, provider.crypto())?;
/// assert_eq!(loaded_cert, certificate);
/// # Ok(())
/// # }
/// ```
///
/// ## Using with RTCConfiguration
///
/// ```no_run
/// # use std::time::Instant;
/// # use rtc::peer_connection::RTCPeerConnectionBuilder;
/// # use rtc::peer_connection::configuration::RTCConfigurationBuilder;
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rtc::crypto::{self, SignatureScheme};
/// # use rtc::peer_connection::certificate::CertificateParams;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let provider = crypto::default_provider()?;
/// // Generate certificate
/// let certificate = RTCCertificate::generate(
///     provider.crypto(),
///     SignatureScheme::EcdsaP256Sha256,
///     CertificateParams::new(vec!["localhost".to_owned()])?,
/// )?;
///
/// // Configure peer connection with custom certificate
/// let peer_connection = RTCPeerConnectionBuilder::new()
///     .with_configuration(
///         RTCConfigurationBuilder::new()
///             .with_certificates(vec![certificate])
///             .build()
///     )
///     .build(Instant::now())?;
/// # Ok(())
/// # }
/// ```
///
/// ## Specifications
///
/// * [MDN RTCCertificate](https://developer.mozilla.org/en-US/docs/Web/API/RTCCertificate)
/// * [W3C RTCCertificate](https://www.w3.org/TR/webrtc/#dom-rtccertificate)
#[derive(Clone, Debug)]
pub struct RTCCertificate {
    /// DTLS certificate containing X.509 certificate chain and private key
    pub dtls_certificate: dtls::crypto::Certificate,

    /// Timestamp after which this certificate is no longer valid
    pub expires: SystemTime,
}

impl PartialEq for RTCCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.dtls_certificate == other.dtls_certificate
    }
}

impl RTCCertificate {
    /// Generates a self-signed certificate with a provider-owned signing key.
    ///
    /// `params` controls X.509 formatting and validity while `provider` owns key generation and
    /// signing. This keeps certificate formatting independent from the primitive backend.
    ///
    /// # Errors
    ///
    /// Returns an error if `scheme` is not supported by `crypto`, if key generation fails, or if
    /// `params` cannot be encoded into a self-signed certificate.
    pub fn generate(
        crypto: &dyn RTCCrypto,
        scheme: SignatureScheme,
        params: CertificateParams,
    ) -> Result<Self> {
        let signing_key = crypto.generate_signing_key(scheme).map_err(crypto_error)?;
        Self::generate_from_signing_key(params, scheme, signing_key)
    }

    /// Imports a PKCS#8 private key through `provider` and associates it with an existing chain.
    ///
    /// # Errors
    ///
    /// Returns an error if `private_key_der` is not a valid PKCS#8 key for `scheme`, or if
    /// `crypto` does not support `scheme`.
    pub fn from_pkcs8(
        crypto: &dyn RTCCrypto,
        scheme: SignatureScheme,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key_der: &[u8],
        expires: SystemTime,
    ) -> Result<Self> {
        let signing_key = crypto
            .import_signing_key(scheme, private_key_der)
            .map_err(crypto_error)?;
        Ok(Self::from_signing_key(
            certificate_chain,
            signing_key,
            expires,
        ))
    }

    /// Builds a certificate around an application-owned signing key, including HSM/KMS keys.
    #[must_use]
    pub fn from_signing_key(
        certificate_chain: Vec<CertificateDer<'static>>,
        signing_key: Arc<dyn SigningKey>,
        expires: SystemTime,
    ) -> Self {
        Self {
            dtls_certificate: dtls::crypto::Certificate::from_signing_key(
                certificate_chain,
                signing_key,
            ),
            expires,
        }
    }

    /// Builds a self-signed certificate around an existing provider-owned signing key.
    ///
    /// Use this when the key already exists — imported from PKCS#8 with
    /// [`RTCCrypto::import_signing_key`], or held by an
    /// HSM/KMS — and a fresh self-signed X.509 wrapper is needed. Use
    /// [`generate`](Self::generate) instead when the provider should create the key too.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not match `scheme`, or if `params` cannot be encoded
    /// into a self-signed certificate.
    ///
    /// This is the provider-neutral replacement for the removed `from_key_pair`.
    pub fn generate_from_signing_key(
        params: CertificateParams,
        scheme: SignatureScheme,
        signing_key: Arc<dyn SigningKey>,
    ) -> Result<Self> {
        let not_after = params.not_after;
        let adapter = RcgenSigningKey::new(scheme, signing_key.clone())?;
        let x509_cert = params
            .self_signed(&adapter)
            .map_err(|error| Error::Other(error.to_string()))?;
        let expires = certificate_expiration(not_after);
        Ok(Self::from_signing_key(
            vec![x509_cert.der().to_owned()],
            signing_key,
            expires,
        ))
    }

    /// Builds a self-signed certificate from an rcgen key pair, using the built-in crypto
    /// provider.
    ///
    /// Kept by the Brainwires fork: upstream removed it in favour of the provider-neutral
    /// [`generate_from_signing_key`](Self::generate_from_signing_key), which this now wraps.
    /// Only Ed25519, ECDSA P-256/SHA-256 and RSA/SHA-256 key pairs are accepted, as before.
    ///
    /// # Errors
    ///
    /// Returns an error for any other key type, if no built-in crypto provider is enabled, or
    /// if the provider cannot import the key.
    pub fn from_key_pair(key_pair: rcgen::KeyPair) -> Result<Self> {
        let scheme = if key_pair.is_compatible(&rcgen::PKCS_ED25519) {
            SignatureScheme::Ed25519
        } else if key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256) {
            SignatureScheme::EcdsaP256Sha256
        } else if key_pair.is_compatible(&rcgen::PKCS_RSA_SHA256) {
            SignatureScheme::RsaPkcs1Sha256
        } else {
            return Err(Error::Other("Unsupported key_pair".to_owned()));
        };
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let signing_key = provider
            .crypto()
            .import_signing_key(scheme, &key_pair.serialize_der())
            .map_err(crypto_error)?;
        let params = CertificateParams::new(vec![shared::util::math_rand_alpha(16)])
            .map_err(|error| Error::Other(error.to_string()))?;
        Self::generate_from_signing_key(params, scheme, signing_key)
    }

    /// Parses a certificate from PEM format string.
    ///
    /// Reconstructs an RTCCertificate from its PEM serialization, including the
    /// private key. The PEM format must match the output of [`serialize_pem`](Self::serialize_pem).
    ///
    /// # Format
    ///
    /// The PEM string must contain two parts:
    /// 1. An "EXPIRES" block containing the expiration timestamp
    /// 2. The certificate and private key blocks
    ///
    /// # Parameters
    ///
    /// * `pem_str` - PEM-encoded certificate string
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The PEM string is malformed or empty
    /// - The EXPIRES block is missing or invalid
    /// - The certificate data cannot be parsed
    ///
    /// # Examples
    ///
    /// ```
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rtc::crypto::{self, SignatureScheme};
    /// # use rtc::peer_connection::certificate::CertificateParams;
    /// # let params = CertificateParams::new(vec!["localhost".to_owned()])?;
    /// # let provider = crypto::default_provider()?;
    /// # let original = RTCCertificate::generate(
    /// #     provider.crypto(),
    /// #     SignatureScheme::EcdsaP256Sha256,
    /// #     params,
    /// # )?;
    /// // Load certificate from PEM string
    /// # let pem_str = original.serialize_pem()?;
    /// let certificate = RTCCertificate::from_pem(&pem_str, provider.crypto())?;
    ///
    /// // Certificate is ready to use
    /// let fingerprints = certificate.get_fingerprints(provider.crypto())?;
    /// println!("Loaded certificate with {} fingerprint(s)", fingerprints.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pem(pem_str: &str, crypto: &dyn RTCCrypto) -> Result<Self> {
        let mut pem_blocks = pem_str.split("\n\n");
        let first_block = if let Some(b) = pem_blocks.next() {
            b
        } else {
            return Err(Error::InvalidPEM("empty PEM".into()));
        };
        let expires_pem =
            pem::parse(first_block).map_err(|e| Error::Other(format!("can't parse PEM: {e}")))?;
        if expires_pem.tag() != "EXPIRES" {
            return Err(Error::InvalidPEM(format!(
                "invalid tag (expected: 'EXPIRES', got '{}')",
                expires_pem.tag()
            )));
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&expires_pem.contents()[..8]);
        let expires = if let Some(e) =
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(u64::from_le_bytes(bytes)))
        {
            e
        } else {
            return Err(Error::InvalidPEM("failed to calculate SystemTime".into()));
        };
        let dtls_certificate = dtls::crypto::Certificate::from_pem(
            &pem_blocks.collect::<Vec<&str>>().join("\n\n"),
            crypto,
        )?;
        Ok(RTCCertificate::from_existing(dtls_certificate, expires))
    }

    /// Creates an RTCCertificate from an existing DTLS certificate.
    ///
    /// Use this method when you have a pre-existing certificate (e.g., loaded from
    /// external storage) that you want to use in WebRTC connections. This is useful
    /// for maintaining persistent identity across application restarts.
    ///
    /// # Parameters
    ///
    /// * `dtls_certificate` - The DTLS certificate with private key
    /// * `expires` - When this certificate expires
    ///
    /// # Note
    ///
    /// The statistics ID will be newly generated and will differ from the original
    /// certificate if it was previously serialized. Statistics IDs are not persisted
    /// during serialization.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rtc::crypto;
    /// # use rtc::dtls;
    /// # use std::time::{SystemTime, Duration};
    /// # fn example(
    /// #     dtls_cert: dtls::crypto::Certificate
    /// # ) -> Result<(), Box<dyn std::error::Error>> {
    /// # let provider = crypto::default_provider()?;
    /// // Use an externally managed certificate
    /// let expires = SystemTime::now() + Duration::from_secs(86400 * 30); // Exemption: usage in #doctest code
    /// let certificate = RTCCertificate::from_existing(dtls_cert, expires);
    ///
    /// // Certificate is ready to use
    /// let fingerprints = certificate.get_fingerprints(provider.crypto())?;
    /// println!("Certificate has {} fingerprint(s)", fingerprints.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_existing(dtls_certificate: dtls::crypto::Certificate, expires: SystemTime) -> Self {
        Self {
            dtls_certificate,
            expires,
        }
    }

    /// Serializes the certificate to PEM format including the private key.
    ///
    /// Produces a PEM-encoded string containing both the certificate and its private
    /// key in PKCS#8 format. The output can be safely stored and later loaded with
    /// `from_pem`.
    ///
    /// # Security Warning
    ///
    /// The serialized output contains the private key in plain text. Store it securely
    /// and never transmit it over insecure channels or include it in client-side code.
    ///
    /// # Format
    ///
    /// The output contains:
    /// 1. EXPIRES block - Certificate expiration timestamp
    /// 2. CERTIFICATE block - X.509 certificate in DER format
    /// 3. PRIVATE KEY block - Private key in PKCS#8 format
    ///
    /// # Examples
    ///
    /// ```
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rtc::crypto::{self, SignatureScheme};
    /// # use rtc::peer_connection::certificate::CertificateParams;
    /// # let params = CertificateParams::new(vec!["localhost".to_owned()])?;
    /// # let provider = crypto::default_provider()?;
    /// # let certificate = RTCCertificate::generate(
    /// #     provider.crypto(),
    /// #     SignatureScheme::EcdsaP256Sha256,
    /// #     params,
    /// # )?;
    /// // Serialize for storage
    /// let pem_string = certificate.serialize_pem()?;
    ///
    /// // Save to secure storage
    /// // std::fs::write("private/cert.pem", &pem_string)?;
    ///
    /// // Later, reload it
    /// let reloaded = RTCCertificate::from_pem(&pem_string, provider.crypto())?;
    /// assert_eq!(certificate, reloaded);
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    ///
    /// Returns an error if the certificate's private key is not exportable — a key held in an
    /// HSM or KMS has no PKCS#8 bytes to serialize.
    pub fn serialize_pem(&self) -> Result<String> {
        // Encode `expires` as a PEM block.
        //
        // TODO: serialize as nanos when https://github.com/rust-lang/rust/issues/103332 is fixed.
        let expires_pem = pem::Pem::new(
            "EXPIRES".to_string(),
            self.expires
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("expires to be valid")
                .as_secs()
                .to_le_bytes()
                .to_vec(),
        );
        Ok(format!(
            "{}\n{}",
            pem::encode(&expires_pem),
            self.dtls_certificate.serialize_pem()?
        ))
    }

    /// Returns SHA-256 fingerprints of the certificate chain.
    ///
    /// Computes cryptographic fingerprints that uniquely identify this certificate.
    /// These fingerprints are used during the WebRTC handshake to verify the remote
    /// peer's identity and are typically exchanged via SDP signaling.
    ///
    /// # Format
    ///
    /// Each fingerprint is a colon-separated string of hexadecimal byte pairs:
    /// `"12:34:56:78:9A:BC:DE:F0:..."`
    ///
    /// # Returns
    ///
    /// The fingerprints of the certificate DTLS presents (the end-entity certificate, the
    /// first of a chain): SHA-256 first, then, when the certificate is signed with SHA-384,
    /// SHA-512 or SHA-224, the fingerprint with that hash function too (RFC 8122 section 5.1).
    /// The other certificates of a chain have no fingerprint: the peer checks the one
    /// presented.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rtc::crypto::{self, SignatureScheme};
    /// # use rtc::peer_connection::certificate::CertificateParams;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let provider = crypto::default_provider()?;
    /// let certificate = RTCCertificate::generate(
    ///     provider.crypto(),
    ///     SignatureScheme::EcdsaP256Sha256,
    ///     CertificateParams::new(vec!["localhost".to_owned()])?,
    /// )?;
    ///
    /// // Get fingerprints for SDP
    /// let fingerprints = certificate.get_fingerprints(provider.crypto())?;
    /// for fp in fingerprints {
    ///     println!("a=fingerprint:{} {}", fp.algorithm, fp.value);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    /// # Errors
    ///
    /// Returns an error if `crypto` cannot compute the digest used for the DTLS fingerprint.
    pub fn get_fingerprints(&self, crypto: &dyn RTCCrypto) -> Result<Vec<RTCDtlsFingerprint>> {
        // RFC 8122 section 5.1: SHA-256, and the hash function of the certificate's own
        // signature when it is another one. A SHA-1 fingerprint is never produced: for a
        // certificate signed with SHA-1 the stronger SHA-256 one is the only fingerprint, as
        // that section allows.
        let mut algorithms = vec![HashAlgorithm::Sha256];
        if let Some(signature_hash) = self.signature_hash()
            && !matches!(signature_hash, HashAlgorithm::Sha256 | HashAlgorithm::Sha1)
            && crypto.supports(crypto::CryptoAlgorithm::Hash(signature_hash))
        {
            algorithms.push(signature_hash);
        }
        algorithms
            .into_iter()
            .map(|algorithm| self.fingerprint(crypto, algorithm))
            .collect()
    }

    /// The fingerprint of this certificate with one hash function of RFC 8122 section 5: the
    /// hash of the DER form of the certificate DTLS presents (the end-entity certificate; a
    /// certificate chain's other certificates have no fingerprint in SDP).
    ///
    /// For out-of-band verification, or for a peer known to want a hash function other than
    /// the ones [`get_fingerprints`](Self::get_fingerprints) writes.
    ///
    /// # Errors
    ///
    /// Returns an error if `algorithm` is not a fingerprint hash function (MD5 is refused, RFC
    /// 8122 section 5), if `crypto` cannot compute it, or if the certificate is empty.
    pub fn fingerprint(
        &self,
        crypto: &dyn RTCCrypto,
        algorithm: HashAlgorithm,
    ) -> Result<RTCDtlsFingerprint> {
        let Some(&(name, _, _)) = FINGERPRINT_HASHES
            .iter()
            .find(|(_, known, _)| *known == algorithm)
        else {
            return Err(Error::ErrUnsupportedFingerprintAlgorithm);
        };
        let der = self
            .dtls_certificate
            .certificate
            .first()
            .ok_or(Error::ErrNonCertificate)?;
        let hashed = crypto.hash(algorithm, der.as_ref()).map_err(crypto_error)?;
        Ok(RTCDtlsFingerprint {
            algorithm: name.to_owned(),
            value: format_fingerprint(&hashed),
        })
    }

    /// The hash function of the signature on the end-entity certificate, when it is one
    /// fingerprints use (RFC 3279 and RFC 4055 RSA PKCS #1 v1.5 and ECDSA signatures). `None`
    /// for the others (Ed25519 and RSASSA-PSS name no separate hash function this way).
    fn signature_hash(&self) -> Option<HashAlgorithm> {
        use x509_parser::prelude::FromDer;
        let der = self.dtls_certificate.certificate.first()?;
        let (_, certificate) =
            x509_parser::certificate::X509Certificate::from_der(der.as_ref()).ok()?;
        match certificate
            .signature_algorithm
            .algorithm
            .to_id_string()
            .as_str()
        {
            // sha1WithRSAEncryption, ecdsa-with-SHA1
            "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" => Some(HashAlgorithm::Sha1),
            // sha224WithRSAEncryption, ecdsa-with-SHA224
            "1.2.840.113549.1.1.14" | "1.2.840.10045.4.3.1" => Some(HashAlgorithm::Sha224),
            // sha256WithRSAEncryption, ecdsa-with-SHA256
            "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => Some(HashAlgorithm::Sha256),
            // sha384WithRSAEncryption, ecdsa-with-SHA384
            "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => Some(HashAlgorithm::Sha384),
            // sha512WithRSAEncryption, ecdsa-with-SHA512
            "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => Some(HashAlgorithm::Sha512),
            _ => None,
        }
    }
}

fn crypto_error(error: crypto::CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

fn certificate_expiration(not_after: impl Into<SystemTime>) -> SystemTime {
    if cfg!(target_arch = "arm") {
        SystemTime::now().add(Duration::from_secs(172800)) // Exemption: wall-clock is correct here to workaround for overflow issue when adding duration to instant on armv7.
    } else {
        not_after.into()
    }
}

struct RcgenSigningKey {
    scheme: SignatureScheme,
    algorithm: &'static rcgen::SignatureAlgorithm,
    signing_key: Arc<dyn SigningKey>,
    public_key: Vec<u8>,
}

impl RcgenSigningKey {
    fn new(scheme: SignatureScheme, signing_key: Arc<dyn SigningKey>) -> Result<Self> {
        let algorithm = match scheme {
            SignatureScheme::Ed25519 => &rcgen::PKCS_ED25519,
            SignatureScheme::EcdsaP256Sha256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            SignatureScheme::EcdsaP384Sha384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            SignatureScheme::RsaPkcs1Sha256 => &rcgen::PKCS_RSA_SHA256,
            SignatureScheme::RsaPkcs1Sha384 => &rcgen::PKCS_RSA_SHA384,
            SignatureScheme::RsaPkcs1Sha512 => &rcgen::PKCS_RSA_SHA512,
            _ => {
                return Err(Error::Crypto(format!(
                    "certificate generation does not support {scheme:?}"
                )));
            }
        };
        if !signing_key.supports(scheme) {
            return Err(Error::Crypto(format!(
                "signing key does not support {scheme:?}"
            )));
        }
        let public_key = signing_key.public_key();
        let public_key = match public_key.encoding {
            PublicKeyEncoding::SubjectPublicKeyInfoDer => {
                use x509_parser::prelude::FromDer;
                let (remaining, subject_public_key_info) =
                    x509_parser::x509::SubjectPublicKeyInfo::from_der(public_key.bytes)
                        .map_err(|error| Error::Other(error.to_string()))?;
                if !remaining.is_empty() {
                    return Err(Error::Other(
                        "trailing bytes in SubjectPublicKeyInfo".to_owned(),
                    ));
                }
                subject_public_key_info.subject_public_key.data.to_vec()
            }
            PublicKeyEncoding::EcUncompressedPoint
            | PublicKeyEncoding::Ed25519Raw
            | PublicKeyEncoding::RsaPkcs1Der => public_key.bytes.to_vec(),
            _ => {
                return Err(Error::Crypto(format!(
                    "certificate generation does not support public-key encoding {:?}",
                    public_key.encoding
                )));
            }
        };
        Ok(Self {
            scheme,
            algorithm,
            signing_key,
            public_key,
        })
    }
}

impl rcgen::PublicKeyData for RcgenSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
}

impl rcgen::SigningKey for RcgenSigningKey {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        self.signing_key
            .sign(self.scheme, message)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

#[cfg(all(test, any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
mod test {
    use super::*;
    use crypto::RTCCryptoProvider;

    struct NonExportableSigningKey(Arc<dyn SigningKey>);

    impl SigningKey for NonExportableSigningKey {
        fn supports(&self, scheme: SignatureScheme) -> bool {
            self.0.supports(scheme)
        }

        fn public_key(&self) -> crypto::PublicKey<'_> {
            self.0.public_key()
        }

        fn sign(
            &self,
            scheme: SignatureScheme,
            message: &[u8],
        ) -> std::result::Result<Vec<u8>, crypto::CryptoError> {
            self.0.sign(scheme, message)
        }
    }

    fn default_test_provider() -> Result<Arc<dyn RTCCryptoProvider>> {
        crypto::default_provider().map_err(crypto_error)
    }

    fn provider_certificate(crypto: &dyn RTCCrypto) -> Result<RTCCertificate> {
        RTCCertificate::generate(
            crypto,
            SignatureScheme::EcdsaP256Sha256,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )
    }

    #[test]
    fn test_generate_certificate_rsa() -> Result<()> {
        let provider = default_test_provider()?;

        // Neither built-in provider generates RSA keys, mirroring rcgen's
        // `KeyGenerationUnavailable` under `ring`. The certificate path must still work for any
        // provider that does support it, so this asserts success or an explicit
        // unsupported-algorithm error, never a silent failure. `tests/dtls_rsa_certificate.rs`
        // covers RSA end to end using an imported fixture key.
        if !provider
            .crypto()
            .supports(crypto::CryptoAlgorithm::SigningKeyGeneration(
                SignatureScheme::RsaPkcs1Sha256,
            ))
        {
            return Ok(());
        }

        let _certificate = RTCCertificate::generate(
            provider.crypto(),
            SignatureScheme::RsaPkcs1Sha256,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )?;

        Ok(())
    }

    #[test]
    fn test_generate_certificate_ecdsa() -> Result<()> {
        let _cert = RTCCertificate::generate(
            default_test_provider()?.crypto(),
            SignatureScheme::EcdsaP256Sha256,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )?;

        Ok(())
    }

    #[test]
    fn test_generate_certificate_eddsa() -> Result<()> {
        let _cert = RTCCertificate::generate(
            default_test_provider()?.crypto(),
            SignatureScheme::Ed25519,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )?;

        Ok(())
    }

    #[test]
    fn test_certificate_equal() -> Result<()> {
        let cert1 = RTCCertificate::generate(
            default_test_provider()?.crypto(),
            SignatureScheme::EcdsaP256Sha256,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )?;

        let cert2 = RTCCertificate::generate(
            default_test_provider()?.crypto(),
            SignatureScheme::EcdsaP256Sha256,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )?;

        assert_ne!(cert1, cert2);

        Ok(())
    }

    #[test]
    fn test_generate_certificate_expires() -> Result<()> {
        let cert = RTCCertificate::generate(
            default_test_provider()?.crypto(),
            SignatureScheme::EcdsaP256Sha256,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )?;

        let now = SystemTime::now(); // Exemption: usage in #test code
        assert!(cert.expires.duration_since(now).is_ok());

        Ok(())
    }

    #[test]
    fn test_certificate_serialize_pem_and_from_pem() -> Result<()> {
        let cert = RTCCertificate::generate(
            default_test_provider()?.crypto(),
            SignatureScheme::EcdsaP256Sha256,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])
                .map_err(|e| Error::Other(e.to_string()))?,
        )?;

        let pem = cert.serialize_pem()?;
        let loaded_cert = RTCCertificate::from_pem(&pem, default_test_provider()?.crypto())?;

        assert_eq!(loaded_cert, cert);

        Ok(())
    }

    #[cfg(feature = "crypto-ring")]
    #[test]
    fn ring_provider_generates_imports_and_fingerprints_certificates() -> Result<()> {
        provider_certificate_round_trip(Arc::new(crypto::providers::RingProvider::new()).crypto())
    }

    #[cfg(feature = "crypto-aws-lc-rs")]
    #[test]
    fn aws_provider_generates_imports_and_fingerprints_certificates() -> Result<()> {
        provider_certificate_round_trip(
            Arc::new(crypto::providers::AwsLcRsProvider::new()).crypto(),
        )
    }

    fn provider_certificate_round_trip(crypto: &dyn RTCCrypto) -> Result<()> {
        let certificate = provider_certificate(crypto)?;
        let fingerprints = certificate.get_fingerprints(crypto)?;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].algorithm, "sha-256");

        let pem = certificate.serialize_pem()?;
        let imported = RTCCertificate::from_pem(&pem, crypto)?;
        assert_eq!(imported, certificate);

        let private_key = certificate
            .dtls_certificate
            .private_key
            .signing_key
            .to_pkcs8_der()
            .map_err(crypto_error)?
            .expect("built-in generated keys are exportable");
        let imported = RTCCertificate::from_pkcs8(
            crypto,
            SignatureScheme::EcdsaP256Sha256,
            certificate.dtls_certificate.certificate.clone(),
            private_key.as_ref(),
            certificate.expires,
        )?;
        assert_eq!(imported, certificate);
        Ok(())
    }

    #[test]
    fn non_exportable_signing_key_returns_an_explicit_pem_error() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let certificate = provider_certificate(provider.crypto())?;
        let signing_key = certificate.dtls_certificate.private_key.signing_key.clone();
        let certificate = RTCCertificate::from_signing_key(
            certificate.dtls_certificate.certificate,
            Arc::new(NonExportableSigningKey(signing_key)),
            certificate.expires,
        );

        let error = certificate.serialize_pem().unwrap_err();
        assert!(error.to_string().contains("not exportable"));
        Ok(())
    }

    /// `from_key_pair` (kept by the Brainwires fork) with Ed25519 produces a usable
    /// certificate with a sha-256 fingerprint.
    #[test]
    fn test_from_key_pair_ed25519_produces_fingerprints() -> Result<()> {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| Error::Other(e.to_string()))?;
        let cert = RTCCertificate::from_key_pair(kp)?;
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let fps = cert.get_fingerprints(provider.crypto())?;
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].algorithm, "sha-256");
        Ok(())
    }

    /// `from_key_pair` with ECDSA P-256, then `from_existing` with a custom expiry.
    #[test]
    fn test_from_existing_with_custom_expiry() -> Result<()> {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Other(e.to_string()))?;
        let cert = RTCCertificate::from_key_pair(kp)?;
        let custom_expires = SystemTime::now() + Duration::from_secs(3600);
        let cert2 = RTCCertificate::from_existing(cert.dtls_certificate.clone(), custom_expires);
        assert_eq!(cert2.expires, custom_expires);
        assert_eq!(cert, cert2); // PartialEq ignores expires
        Ok(())
    }

    /// `from_key_pair` rejects key types outside its supported list.
    #[test]
    fn test_from_key_pair_unsupported_rejects() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        assert!(RTCCertificate::from_key_pair(kp).is_err());
    }

    // Certificates made with OpenSSL (`openssl req -x509 -newkey ec ... -sha384`), and their
    // fingerprints as `openssl x509 -fingerprint -<hash>` prints them: reference values this
    // crate did not compute.
    const CERT_ECDSA_SHA384: &str = "-----BEGIN CERTIFICATE-----
MIIBrTCCATOgAwIBAgIUCMBw3Md0YA56C88fCOacMMjgCxUwCgYIKoZIzj0EAwMw
HTEbMBkGA1UEAwwSZmluZ2VycHJpbnQtc2hhMzg0MCAXDTI2MTEyMjEzMTYzOFoY
DzIxMjYxMDI5MTMxNjM4WjAdMRswGQYDVQQDDBJmaW5nZXJwcmludC1zaGEzODQw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAASCEunEK9ms53hgfegOVH0kN6PFj3KJTmQY
2DRkLyqPjMQXyaXUu4ZqW61NasGpkFvMYebw8V0gWI78UTYjTrdMg5CSubwnjbCM
SoJtDXqTKYF9ysAzpN09eDkwyTaPvoujMjAwMB0GA1UdDgQWBBSecbBDGMQy6S4s
iCM4BkO3Llg9EzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMDA2gAMGUCME6B
QXihO54JAWAKgiGCvdo1HffSDd86idMzxt0e9OrK+3HEOOZD2glNq7W4ktMBKwIx
AM27leWJvqDi9irlVvBkoBmBgg9oJ5HIexcssuTT10nXXchXHGveNYAqvIVX3D6c
dw==
-----END CERTIFICATE-----
";
    const CERT_ECDSA_SHA384_FINGERPRINTS: [(HashAlgorithm, &str); 5] = [
        (
            HashAlgorithm::Sha1,
            "3E:A2:8A:A0:85:DA:94:D3:29:4E:99:6C:19:83:8A:CE:EE:78:3B:CD",
        ),
        (
            HashAlgorithm::Sha224,
            "64:9E:10:69:9C:96:01:49:86:E1:DD:CC:EA:92:94:1C:9E:B8:FA:DF:7A:6C:A6:52:EC:38:5F:9B",
        ),
        (
            HashAlgorithm::Sha256,
            "D8:FD:6F:9D:DA:08:B6:47:FE:1C:35:71:BC:5A:B8:04:26:3E:2C:51:E2:E3:E0:96:5C:F3:F9:A8:\
             17:E0:EF:F8",
        ),
        (
            HashAlgorithm::Sha384,
            "22:D9:4C:AD:E4:15:2E:4E:16:9D:FF:F6:9C:FA:91:04:04:4E:07:85:3E:84:88:80:18:C7:14:2E:\
             FF:7A:8B:50:16:78:0B:32:5D:47:DE:F5:07:0D:14:93:D9:91:E1:E8",
        ),
        (
            HashAlgorithm::Sha512,
            "6F:F5:FF:7D:78:E1:69:FB:E7:90:25:2C:5A:CD:C1:EF:FF:2B:45:E6:C9:BC:DB:1D:D7:F3:F0:66:\
             6A:8D:EA:7F:9C:9E:1B:CA:42:7F:E0:F8:50:6C:69:8F:4A:A9:64:EF:E2:E4:C6:D3:C5:6B:7D:A6:\
             15:06:50:64:2A:B6:F1:A9",
        ),
    ];
    const CERT_ECDSA_SHA512: &str = "-----BEGIN CERTIFICATE-----
MIIBcDCCARagAwIBAgIUV5HWUoNIaiUPzHmFIIKHvPwxTaMwCgYIKoZIzj0EAwQw
HTEbMBkGA1UEAwwSZmluZ2VycHJpbnQtc2hhNTEyMCAXDTI2MTEyMjEzMTYzOFoY
DzIxMjYxMDI5MTMxNjM4WjAdMRswGQYDVQQDDBJmaW5nZXJwcmludC1zaGE1MTIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATlIxEaJFwF/tS6hvajK1ObUVkTSDb0
LaLP3qprg2acHwsPBBp8VtQzr/IJip2ySBDVatsqa5/k13KttsdA2mXHozIwMDAd
BgNVHQ4EFgQUkQ3kOZxm2YT4qFwTO7e4LxUZUKowDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDBANIADBFAiAmZAjGyJL+LEEesHd6j+8tukFsN45lXVIAsGv2qv2S
wAIhALlwsNm6fNrP8U3N282VQ714UJNcoHLGIZ3GVnRxx0KL
-----END CERTIFICATE-----
";
    const CERT_ECDSA_SHA512_SHA256: &str = "D0:8C:93:40:32:95:52:08:BB:D8:A5:59:B1:4A:AC:2E:\
        90:8A:71:D8:74:AF:E2:40:6E:87:70:84:42:50:66:94";
    const CERT_ECDSA_SHA512_SHA512: &str = "6C:BB:35:B3:58:77:A8:DE:51:B3:3E:BC:A6:0C:C5:DF:\
        5A:EC:03:B1:40:FA:44:C6:A4:BC:30:6C:8E:65:CA:52:8F:82:D6:30:A2:1C:20:AD:4B:35:32:AC:\
        45:DF:A6:08:63:74:42:6F:81:28:4D:E8:17:BD:4D:60:AB:E7:E5:00";
    const CERT_ECDSA_SHA1: &str = "-----BEGIN CERTIFICATE-----
MIIBajCCARGgAwIBAgIUGYHumsbQdLlZdQQJcLVuvEu99KkwCQYHKoZIzj0EATAb
MRkwFwYDVQQDDBBmaW5nZXJwcmludC1zaGExMCAXDTI2MTEyMjEzMTYzOFoYDzIx
MjYxMDI5MTMxNjM4WjAbMRkwFwYDVQQDDBBmaW5nZXJwcmludC1zaGExMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEHbHZnBDLrnC8+LVHaMyeFWEd9BEBVkFl1Q5t
Q4T0utjX6y5U6dq8V8L1rueK8/IAo9X6rL/5fIw79t5gw4lanaMyMDAwHQYDVR0O
BBYEFDwBuNvfpXLOTl6Vo25SeyfL1HlEMA8GA1UdEwEB/wQFMAMBAf8wCQYHKoZI
zj0EAQNIADBFAiEAix6bYOROXuhdGaXjT+viSaHtUBynCKIP3iVZS71mQ0sCIA1c
8cQDIXnqz24vuzRqKnmRmYZ5F0UoRFzQSycWFUhz
-----END CERTIFICATE-----
";
    const CERT_ECDSA_SHA1_SHA256: &str = "09:19:0E:CD:EA:3F:A3:C2:EC:2F:B0:B5:80:87:22:29:\
        FE:D6:59:2F:CF:12:6C:A8:30:FA:B1:B0:4C:22:B2:27";

    /// An `RTCCertificate` whose chain is the given PEM certificates. The key is any key: a
    /// fingerprint is a hash of the certificate alone.
    fn certificate_from_pem_chain(chain: &[&str]) -> Result<RTCCertificate> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let signing_key = provider
            .crypto()
            .generate_signing_key(SignatureScheme::EcdsaP256Sha256)
            .map_err(crypto_error)?;
        let chain = chain
            .iter()
            .map(|certificate| {
                let der = pem::parse(certificate).map_err(|e| Error::Other(e.to_string()))?;
                Ok(CertificateDer::from(der.into_contents()))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RTCCertificate::from_signing_key(
            chain,
            signing_key,
            // 2096: a fixed instant, the fingerprint tests do not look at the clock.
            SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        ))
    }

    fn written(fingerprints: &[RTCDtlsFingerprint]) -> Vec<(String, String)> {
        fingerprints
            .iter()
            .map(|fp| (fp.algorithm.clone(), fp.value.to_uppercase()))
            .collect()
    }

    /// RFC 8122 section 5: the fingerprint is the hash of the certificate's DER form, for
    /// each of the hash functions the RFC defines (MD5 and MD2 are never computed).
    #[test]
    fn fingerprints_match_openssl_for_every_hash_function() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let certificate = certificate_from_pem_chain(&[CERT_ECDSA_SHA384])?;
        for (algorithm, expected) in CERT_ECDSA_SHA384_FINGERPRINTS {
            let fingerprint = certificate.fingerprint(provider.crypto(), algorithm)?;
            assert_eq!(fingerprint.value.to_uppercase(), expected, "{algorithm:?}");
        }
        assert_eq!(
            certificate
                .fingerprint(provider.crypto(), HashAlgorithm::Sha384)?
                .algorithm,
            "sha-384"
        );
        assert_eq!(
            certificate.fingerprint(provider.crypto(), HashAlgorithm::Md5),
            Err(Error::ErrUnsupportedFingerprintAlgorithm)
        );
        Ok(())
    }

    /// RFC 8122 section 5.1: "An endpoint MUST, as a minimum, calculate a fingerprint using
    /// both the 'SHA-256' hash function algorithm and the hash function used to generate the
    /// signature on the certificate". A certificate signed with SHA-384 or SHA-512 gets both;
    /// one signed with SHA-256 gets the one; for one signed with SHA-1 the SHA-1 fingerprint
    /// is left out (the same section allows it: a stronger hash is included).
    #[test]
    fn fingerprints_are_sha256_and_the_signature_hash() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let crypto = provider.crypto();

        let sha384 = certificate_from_pem_chain(&[CERT_ECDSA_SHA384])?;
        assert_eq!(
            written(&sha384.get_fingerprints(crypto)?),
            [
                (
                    "sha-256".to_owned(),
                    CERT_ECDSA_SHA384_FINGERPRINTS[2].1.to_owned()
                ),
                (
                    "sha-384".to_owned(),
                    CERT_ECDSA_SHA384_FINGERPRINTS[3].1.to_owned()
                ),
            ]
        );

        let sha512 = certificate_from_pem_chain(&[CERT_ECDSA_SHA512])?;
        assert_eq!(
            written(&sha512.get_fingerprints(crypto)?),
            [
                ("sha-256".to_owned(), CERT_ECDSA_SHA512_SHA256.to_owned()),
                ("sha-512".to_owned(), CERT_ECDSA_SHA512_SHA512.to_owned()),
            ]
        );

        let sha1 = certificate_from_pem_chain(&[CERT_ECDSA_SHA1])?;
        assert_eq!(
            written(&sha1.get_fingerprints(crypto)?),
            [("sha-256".to_owned(), CERT_ECDSA_SHA1_SHA256.to_owned())]
        );

        let sha256 = provider_certificate(crypto)?;
        let fingerprints = sha256.get_fingerprints(crypto)?;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].algorithm, "sha-256");
        Ok(())
    }

    /// A certificate chain has the fingerprints of its end-entity certificate only: that is
    /// the certificate the peer hashes (RFC 8122 section 5), and a fingerprint of the issuer
    /// would let a certificate that is not this endpoint's pass the check.
    #[test]
    fn a_certificate_chain_has_the_fingerprints_of_its_end_entity_certificate() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let chain = certificate_from_pem_chain(&[CERT_ECDSA_SHA512, CERT_ECDSA_SHA384])?;
        assert_eq!(chain.dtls_certificate.certificate.len(), 2);
        assert_eq!(
            written(&chain.get_fingerprints(provider.crypto())?),
            [
                ("sha-256".to_owned(), CERT_ECDSA_SHA512_SHA256.to_owned()),
                ("sha-512".to_owned(), CERT_ECDSA_SHA512_SHA512.to_owned()),
            ]
        );
        Ok(())
    }
}
