//! The hellos of DTLS 1.3: what a client offers, what a server makes of it, and the
//! HelloRetryRequest with its stateless cookie (RFC 8446 sections 4.1 and 4.2, RFC 9147
//! sections 5.1 and 5.3).

use super::codec::*;
use super::messages::*;
use super::suite::Suite13;
use super::{DTLS1_2_WIRE_VERSION, DTLS1_3_WIRE_VERSION};
use crate::cipher_suite::CipherSuiteId;
use crate::config::{DtlsVersion, HandshakeConfig};
use crate::crypto::Certificate;
use crate::curve::named_curve::{NamedCurve, NamedCurveKeypair};
use crate::extension::Extension;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::signature_hash_algorithm::SignatureHashAlgorithm;
use crypto::{HmacAlgorithm, RTCCryptoProvider};
use shared::error::{Error, Result};
use std::net::{IpAddr, SocketAddr};

/// How many of its groups a client sends a key share for: the first two it prefers, so that
/// a server which supports either answers without a HelloRetryRequest.
const KEY_SHARES_OFFERED: usize = 2;

/// What a client that offers DTLS 1.3 keeps from its ClientHello until the server answers.
pub(crate) struct ClientOffer {
    /// The key shares offered, in order of preference.
    pub(crate) key_shares: Vec<NamedCurveKeypair>,
    /// The connection id this client asks the server to put in its records, if it asks for
    /// connection ids at all (empty: it offers the extension and wants none itself).
    pub(crate) connection_id: Option<Vec<u8>>,
}

impl ClientOffer {
    /// Makes the key shares of a ClientHello.
    pub(crate) fn new(cfg: &HandshakeConfig) -> Result<Self> {
        let mut key_shares = vec![];
        for curve in cfg.local_named_curves.iter().take(KEY_SHARES_OFFERED) {
            key_shares.push(curve.generate_keypair_with_crypto(cfg.provider().crypto())?);
        }
        if key_shares.is_empty() {
            return Err(Error::ErrNoSupportedEllipticCurves);
        }
        Ok(Self {
            key_shares,
            connection_id: cfg.connection_id_offer(),
        })
    }

    /// The extensions a DTLS 1.3 offer adds to the ClientHello: supported_versions,
    /// key_share and, if configured, connection_id.
    pub(crate) fn extensions(&self, cfg: &HandshakeConfig) -> Vec<Extension> {
        let mut versions = vec![];
        put_vec8(&mut versions, |list| {
            put_u16(list, DTLS1_3_WIRE_VERSION);
            if cfg.min_version == DtlsVersion::Dtls1_2 {
                put_u16(list, DTLS1_2_WIRE_VERSION);
            }
        });
        let shares: Vec<(u16, &[u8])> = self
            .key_shares
            .iter()
            .map(|keypair| (keypair.curve as u16, keypair.public_key.as_slice()))
            .collect();
        let mut extensions = vec![
            Extension::Unknown {
                extension_type: EXT_SUPPORTED_VERSIONS,
                data: versions,
            },
            Extension::Unknown {
                extension_type: EXT_KEY_SHARE,
                data: client_key_share_data(&shares),
            },
        ];
        if let Some(connection_id) = &self.connection_id {
            let mut data = vec![];
            put_vec8(&mut data, |out| out.extend_from_slice(connection_id));
            extensions.push(Extension::Unknown {
                extension_type: EXT_CONNECTION_ID,
                data,
            });
        }
        extensions
    }
}

/// Rewrites a first ClientHello into the one that answers a HelloRetryRequest (RFC 8446
/// section 4.1.2): the same message, with the key_share replaced when the server named a
/// group, early_data removed, and the cookie added.
pub(crate) fn second_client_hello(
    first: &ClientHello<'_>,
    key_share: Option<(u16, &[u8])>,
    cookie: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(512);
    put_u16(&mut body, first.legacy_version);
    body.extend_from_slice(first.random);
    put_vec8(&mut body, |out| {
        out.extend_from_slice(first.legacy_session_id)
    });
    put_vec8(&mut body, |out| out.extend_from_slice(first.legacy_cookie));
    put_vec16(&mut body, |out| {
        for suite in &first.cipher_suites {
            put_u16(out, *suite);
        }
    });
    put_vec8(&mut body, |out| {
        out.extend_from_slice(first.legacy_compression_methods)
    });
    put_vec16(&mut body, |out| {
        for (extension_type, data) in &first.extensions {
            match *extension_type {
                EXT_EARLY_DATA | EXT_COOKIE => {}
                EXT_KEY_SHARE => match key_share {
                    Some(share) => put_extension(out, EXT_KEY_SHARE, |data| {
                        data.extend_from_slice(&client_key_share_data(&[share]))
                    }),
                    None => put_extension(out, EXT_KEY_SHARE, |out| out.extend_from_slice(data)),
                },
                other => put_extension(out, other, |out| out.extend_from_slice(data)),
            }
        }
        if let Some(cookie) = cookie {
            put_extension(out, EXT_COOKIE, |data| {
                put_vec16(data, |out| out.extend_from_slice(cookie))
            });
        }
    });
    body
}

/// What a server settles from a ClientHello.
pub(crate) struct Negotiated {
    pub(crate) suite: Suite13,
    pub(crate) group: NamedCurve,
    /// The client's key share for `group`; `None` when it sent none and has to be asked for
    /// one with a HelloRetryRequest.
    pub(crate) client_share: Option<Vec<u8>>,
    pub(crate) certificate: Certificate,
    pub(crate) signature_scheme: SignatureHashAlgorithm,
    pub(crate) srtp_profile: SrtpProtectionProfile,
    pub(crate) server_name: String,
    /// The connection id the client asks for in records sent to it, if it offered the
    /// extension.
    pub(crate) client_connection_id: Option<Vec<u8>>,
    /// The extension types the ClientHello carried: what EncryptedExtensions may answer.
    pub(crate) offered_extensions: Vec<u16>,
}

fn illegal(error: Error) -> Refusal {
    refuse(alert::ILLEGAL_PARAMETER, error)
}

/// Negotiates a DTLS 1.3 handshake from a ClientHello that offers it (RFC 8446 sections
/// 4.1.1, 4.1.2 and 4.2, RFC 9147 section 5.3).
///
/// # Errors
///
/// The alert RFC 8446 names for each way the ClientHello cannot be served.
pub(crate) fn negotiate(
    cfg: &HandshakeConfig,
    hello: &ClientHello<'_>,
) -> std::result::Result<Negotiated, Refusal> {
    // RFC 9147 section 5.3: a legacy_cookie in a DTLS 1.3 ClientHello is an
    // illegal_parameter. RFC 8446 section 4.1.2: so is any compression but null.
    if !hello.legacy_cookie.is_empty() {
        return Err(illegal(Error::ErrCookieMismatch));
    }
    if hello.legacy_compression_methods != [0] {
        return Err(illegal(Error::ErrNoNullCompressionMethod));
    }
    // RFC 8446 section 4.2.11: pre_shared_key is the last extension, and comes with
    // psk_key_exchange_modes. No PSK is accepted here; the handshake is a full one.
    if let Some(position) = hello
        .extensions
        .iter()
        .position(|(extension_type, _)| *extension_type == EXT_PRE_SHARED_KEY)
    {
        if position + 1 != hello.extensions.len() {
            return Err(illegal(Error::ErrInvalidExtensionType));
        }
        if hello.extension(EXT_PSK_KEY_EXCHANGE_MODES).is_none() {
            return Err(refuse(
                alert::MISSING_EXTENSION,
                Error::ErrInvalidExtensionType,
            ));
        }
    }

    // The first suite of the client's list that this server has.
    let suite = hello
        .cipher_suites
        .iter()
        .map(|suite| CipherSuiteId::from(*suite))
        .find(|suite| cfg.local_tls13_cipher_suites.contains(suite))
        .and_then(Suite13::for_id)
        .ok_or_else(|| {
            refuse(
                alert::HANDSHAKE_FAILURE,
                Error::ErrCipherSuiteNoIntersection,
            )
        })?;

    // RFC 8446 section 9.2: a ClientHello for (EC)DHE without supported_groups, key_share
    // or signature_algorithms is answered with missing_extension.
    let missing = |error| refuse(alert::MISSING_EXTENSION, error);
    let groups = hello
        .extension(EXT_SUPPORTED_GROUPS)
        .ok_or_else(|| missing(Error::ErrNoSupportedEllipticCurves))?;
    let groups = parse_u16_list(groups).map_err(decode_error)?;
    let shares = hello
        .extension(EXT_KEY_SHARE)
        .ok_or_else(|| missing(Error::ErrNoSupportedEllipticCurves))?;
    let shares = parse_client_key_shares(shares).map_err(decode_error)?;
    let schemes = hello
        .extension(EXT_SIGNATURE_ALGORITHMS)
        .ok_or_else(|| missing(Error::ErrNoAvailableSignatureSchemes))?;
    let schemes = parse_u16_list(schemes).map_err(decode_error)?;

    // RFC 8446 section 4.2.8: each share is for a group of supported_groups, in the same
    // order, and no group has two.
    let mut share_positions = vec![];
    for (index, (group, _)) in shares.iter().enumerate() {
        let Some(position) = groups.iter().position(|listed| listed == group) else {
            return Err(illegal(Error::ErrInvalidNamedCurve));
        };
        if shares[..index].iter().any(|(earlier, _)| earlier == group)
            || share_positions.last().is_some_and(|last| position < *last)
        {
            return Err(illegal(Error::ErrInvalidNamedCurve));
        }
        share_positions.push(position);
    }
    // The group: the first of the client's that this server has and the client sent a share
    // for; failing that, the first this server has, which costs a HelloRetryRequest.
    let supported = |group: &u16| cfg.local_named_curves.contains(&NamedCurve::from(*group));
    let with_share = groups
        .iter()
        .filter(|group| supported(group))
        .find_map(|group| {
            shares
                .iter()
                .find(|(share_group, _)| share_group == group)
                .map(|(_, key)| (*group, Some(key.to_vec())))
        });
    let (group, client_share) = with_share
        .or_else(|| {
            groups
                .iter()
                .find(|group| supported(group))
                .map(|g| (*g, None))
        })
        .ok_or_else(|| {
            refuse(
                alert::HANDSHAKE_FAILURE,
                Error::ErrNoSupportedEllipticCurves,
            )
        })?;

    let server_name = match hello.extension(EXT_SERVER_NAME) {
        Some(data) => parse_server_name(data)
            .map_err(decode_error)?
            .unwrap_or_default(),
        None => String::new(),
    };

    // RFC 8446 section 4.4.3: a scheme the client lists, valid for TLS 1.3, that the
    // certificate's key can sign with. In this server's order of preference.
    let certificate = cfg
        .get_certificate(&server_name)
        .map_err(|error| refuse(alert::HANDSHAKE_FAILURE, error))?;
    let signature_scheme = cfg
        .local_signature_schemes
        .iter()
        .find(|scheme| {
            scheme.is_tls13_signature()
                && schemes.contains(&scheme.scheme_code())
                && scheme.is_compatible(&certificate.private_key)
        })
        .copied()
        .ok_or_else(|| {
            refuse(
                alert::HANDSHAKE_FAILURE,
                Error::ErrNoAvailableSignatureSchemes,
            )
        })?;

    // RFC 5764 section 4.1.1: a server that does DTLS-SRTP and shares no profile with the
    // client refuses; one that does not do it ignores the extension.
    let mut srtp_profile = SrtpProtectionProfile::Unsupported;
    if let Some(data) = hello.extension(EXT_USE_SRTP)
        && !cfg.local_srtp_protection_profiles.is_empty()
    {
        let (profiles, _mki) = parse_use_srtp(data).map_err(decode_error)?;
        srtp_profile = profiles
            .iter()
            .map(|profile| SrtpProtectionProfile::from(*profile))
            .find(|profile| cfg.local_srtp_protection_profiles.contains(profile))
            .ok_or_else(|| {
                refuse(
                    alert::INSUFFICIENT_SECURITY,
                    Error::ErrServerNoMatchingSrtpProfile,
                )
            })?;
    }

    let client_connection_id = match hello.extension(EXT_CONNECTION_ID) {
        Some(data) => Some(parse_connection_id(data).map_err(decode_error)?.to_vec()),
        None => None,
    };

    Ok(Negotiated {
        suite,
        group: NamedCurve::from(group),
        client_share,
        certificate,
        signature_scheme,
        srtp_profile,
        server_name,
        client_connection_id,
        offered_extensions: hello.extensions.iter().map(|(t, _)| *t).collect(),
    })
}

/// What a HelloRetryRequest cookie carries, so that the server needs no state between the
/// two ClientHellos (RFC 9147 section 5.1): the hash of the first ClientHello, which the
/// transcript continues from, and what the HelloRetryRequest said, from which it is written
/// again byte for byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetryCookie {
    pub(crate) suite: u16,
    /// The group of the HelloRetryRequest's key_share, or zero when it had none.
    pub(crate) group: u16,
    pub(crate) client_hello_hash: Vec<u8>,
}

const COOKIE_MAC_LENGTH: usize = 32;

impl RetryCookie {
    fn mac(
        provider: &dyn RTCCryptoProvider,
        secret: &[u8],
        remote: Option<SocketAddr>,
        content: &[u8],
    ) -> Result<[u8; COOKIE_MAC_LENGTH]> {
        let (address, port) = match remote {
            Some(remote) => (
                match remote.ip() {
                    IpAddr::V4(ip) => ip.octets().to_vec(),
                    IpAddr::V6(ip) => ip.octets().to_vec(),
                },
                remote.port(),
            ),
            None => (vec![], 0),
        };
        let crypto_error = |error: crypto::CryptoError| Error::Crypto(error.to_string());
        let mut mac = provider
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, secret)
            .map_err(crypto_error)?;
        let mut tag = [0u8; COOKIE_MAC_LENGTH];
        mac.sign(
            &[
                b"dtls13 hrr cookie",
                &[address.len() as u8],
                &address,
                &port.to_be_bytes(),
                content,
            ],
            &mut tag,
        )
        .map_err(crypto_error)?;
        Ok(tag)
    }

    /// The cookie bytes: the contents and their HMAC-SHA-256 under `secret`, bound to the
    /// client's address when the server knows it.
    pub(crate) fn seal(
        &self,
        provider: &dyn RTCCryptoProvider,
        secret: &[u8],
        remote: Option<SocketAddr>,
    ) -> Result<Vec<u8>> {
        let mut cookie = Vec::with_capacity(5 + self.client_hello_hash.len() + COOKIE_MAC_LENGTH);
        put_u16(&mut cookie, self.suite);
        put_u16(&mut cookie, self.group);
        put_vec8(&mut cookie, |out| {
            out.extend_from_slice(&self.client_hello_hash)
        });
        let tag = Self::mac(provider, secret, remote, &cookie)?;
        cookie.extend_from_slice(&tag);
        Ok(cookie)
    }

    /// Reads a cookie this server made for `remote` under one of `secrets`. `None` for any
    /// other: the MAC is compared in constant time.
    pub(crate) fn open(
        provider: &dyn RTCCryptoProvider,
        secrets: &[&[u8]],
        remote: Option<SocketAddr>,
        cookie: &[u8],
    ) -> Result<Option<Self>> {
        if cookie.len() <= COOKIE_MAC_LENGTH {
            return Ok(None);
        }
        let (content, tag) = cookie.split_at(cookie.len() - COOKIE_MAC_LENGTH);
        let mut valid = false;
        for secret in secrets {
            let expected = Self::mac(provider, secret, remote, content)?;
            valid |= crypto::constant_time_eq(&expected, tag);
        }
        if !valid {
            return Ok(None);
        }
        let mut reader = Reader::new(content);
        let parsed = (|| -> Result<Self> {
            let suite = reader.u16()?;
            let group = reader.u16()?;
            let client_hello_hash = reader.vec8()?.to_vec();
            reader.finish()?;
            Ok(Self {
                suite,
                group,
                client_hello_hash,
            })
        })();
        Ok(parsed.ok())
    }

    /// The HelloRetryRequest this cookie stands for.
    pub(crate) fn hello_retry_request(&self, cookie: &[u8]) -> Vec<u8> {
        server_hello(&HELLO_RETRY_REQUEST_RANDOM, self.suite, |extensions| {
            if self.group != 0 {
                put_extension(extensions, EXT_KEY_SHARE, |data| put_u16(data, self.group));
            }
            put_extension(extensions, EXT_COOKIE, |data| {
                put_vec16(data, |out| out.extend_from_slice(cookie))
            });
        })
    }
}

/// The cookie of a ClientHello's cookie extension (RFC 8446 section 4.2.2).
pub(crate) fn parse_cookie(data: &[u8]) -> Result<&[u8]> {
    let mut reader = Reader::new(data);
    let cookie = reader.vec16()?;
    reader.finish()?;
    if cookie.is_empty() {
        return Err(Error::ErrLengthMismatch);
    }
    Ok(cookie)
}

/// The body of the ClientHello that is the whole of `datagram`'s first record, if the
/// datagram starts with one that is not fragmented, with its record sequence number and
/// message_seq. A server reads it before it keeps any state for the client.
pub(crate) fn whole_client_hello(datagram: &[u8]) -> Option<(&[u8], u64, u16)> {
    let header = datagram.get(..13)?;
    if header[0] != 22 || header[3..5] != [0, 0] {
        return None;
    }
    let mut sequence = [0u8; 8];
    sequence[2..].copy_from_slice(&header[5..11]);
    let length = usize::from(u16::from_be_bytes([header[11], header[12]]));
    let record = datagram.get(13..13 + length)?;
    let fragments = HandshakeFragment::parse_all(record).ok()?;
    let first = fragments.first()?;
    (first.handshake_type == CLIENT_HELLO
        && first.fragment_offset == 0
        && first.fragment.len() == first.length)
        .then_some((
            first.fragment,
            u64::from_be_bytes(sequence),
            first.message_seq,
        ))
}
