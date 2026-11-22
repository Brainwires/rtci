//! The TLS 1.3 handshake messages DTLS 1.3 carries (RFC 8446 section 4, RFC 9147 sections 5.2
//! to 5.4 and 9), as bodies: what follows the handshake header.

use super::codec::*;
use super::{DTLS1_2_WIRE_VERSION, DTLS1_3_WIRE_VERSION};
use shared::error::{Error, Result};

pub(crate) const CLIENT_HELLO: u8 = 1;
pub(crate) const SERVER_HELLO: u8 = 2;
pub(crate) const NEW_SESSION_TICKET: u8 = 4;
pub(crate) const END_OF_EARLY_DATA: u8 = 5;
pub(crate) const ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const REQUEST_CONNECTION_ID: u8 = 9;
pub(crate) const NEW_CONNECTION_ID: u8 = 10;
pub(crate) const CERTIFICATE: u8 = 11;
pub(crate) const CERTIFICATE_REQUEST: u8 = 13;
pub(crate) const CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const FINISHED: u8 = 20;
pub(crate) const KEY_UPDATE: u8 = 24;

pub(crate) const EXT_SERVER_NAME: u16 = 0;
pub(crate) const EXT_SUPPORTED_GROUPS: u16 = 10;
pub(crate) const EXT_EC_POINT_FORMATS: u16 = 11;
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub(crate) const EXT_USE_SRTP: u16 = 14;
pub(crate) const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
pub(crate) const EXT_PRE_SHARED_KEY: u16 = 41;
pub(crate) const EXT_EARLY_DATA: u16 = 42;
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub(crate) const EXT_COOKIE: u16 = 44;
pub(crate) const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub(crate) const EXT_CERTIFICATE_AUTHORITIES: u16 = 47;
pub(crate) const EXT_OID_FILTERS: u16 = 48;
pub(crate) const EXT_POST_HANDSHAKE_AUTH: u16 = 49;
pub(crate) const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
pub(crate) const EXT_KEY_SHARE: u16 = 51;
pub(crate) const EXT_CONNECTION_ID: u16 = 54;
pub(crate) const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The ServerHello.random that marks a HelloRetryRequest: the SHA-256 of "HelloRetryRequest"
/// (RFC 8446 section 4.1.3).
pub(crate) const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The last eight bytes of the random of a server that speaks (D)TLS 1.3 and negotiates
/// (D)TLS 1.2: "DOWNGRD" and 1 (RFC 8446 section 4.1.3, RFC 9147 section 5.3).
pub(crate) const DOWNGRADE_TO_1_2: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];
/// The same for (D)TLS 1.1 / DTLS 1.0 and below.
pub(crate) const DOWNGRADE_TO_1_0: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];

/// What a handshake message that does not conform costs: the alert RFC 8446 names for it and
/// the error reported locally.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) alert: u8,
    pub(crate) error: Error,
}

pub(crate) mod alert {
    pub(crate) const CLOSE_NOTIFY: u8 = 0;
    pub(crate) const UNEXPECTED_MESSAGE: u8 = 10;
    pub(crate) const BAD_RECORD_MAC: u8 = 20;
    pub(crate) const RECORD_OVERFLOW: u8 = 22;
    pub(crate) const HANDSHAKE_FAILURE: u8 = 40;
    pub(crate) const BAD_CERTIFICATE: u8 = 42;
    pub(crate) const ILLEGAL_PARAMETER: u8 = 47;
    pub(crate) const DECODE_ERROR: u8 = 50;
    pub(crate) const DECRYPT_ERROR: u8 = 51;
    pub(crate) const TOO_MANY_CIDS_REQUESTED: u8 = 52;
    pub(crate) const PROTOCOL_VERSION: u8 = 70;
    pub(crate) const INSUFFICIENT_SECURITY: u8 = 71;
    pub(crate) const INTERNAL_ERROR: u8 = 80;
    pub(crate) const USER_CANCELED: u8 = 90;
    pub(crate) const MISSING_EXTENSION: u8 = 109;
    pub(crate) const UNSUPPORTED_EXTENSION: u8 = 110;
    pub(crate) const CERTIFICATE_REQUIRED: u8 = 116;
}

pub(crate) fn refuse(alert: u8, error: Error) -> Refusal {
    Refusal { alert, error }
}

/// A message that does not parse: decode_error (RFC 8446 section 6.2).
pub(crate) fn decode_error(error: Error) -> Refusal {
    refuse(alert::DECODE_ERROR, error)
}

/// A ClientHello as received (RFC 9147 section 5.3), borrowed from its body.
#[derive(Clone, Debug)]
pub(crate) struct ClientHello<'a> {
    pub(crate) legacy_version: u16,
    pub(crate) random: &'a [u8],
    pub(crate) legacy_session_id: &'a [u8],
    pub(crate) legacy_cookie: &'a [u8],
    pub(crate) cipher_suites: Vec<u16>,
    pub(crate) legacy_compression_methods: &'a [u8],
    pub(crate) extensions: Vec<(u16, &'a [u8])>,
}

impl<'a> ClientHello<'a> {
    /// Reads a ClientHello body.
    ///
    /// # Errors
    ///
    /// Fails if a field is truncated or of a length its definition forbids, if bytes follow
    /// the extensions, or if an extension appears twice.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(body);
        let legacy_version = reader.u16()?;
        let random = reader.bytes(32)?;
        let legacy_session_id = reader.vec8()?;
        if legacy_session_id.len() > 32 {
            return Err(Error::ErrLengthMismatch);
        }
        let legacy_cookie = reader.vec8()?;
        let suites = reader.vec16()?;
        if suites.is_empty() || suites.len() % 2 != 0 {
            return Err(Error::ErrLengthMismatch);
        }
        let cipher_suites = suites
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        let legacy_compression_methods = reader.vec8()?;
        if legacy_compression_methods.is_empty() {
            return Err(Error::ErrLengthMismatch);
        }
        let extensions = if reader.is_empty() {
            vec![]
        } else {
            let block = reader.vec16()?;
            reader.finish()?;
            read_extensions(block)?
        };
        Ok(Self {
            legacy_version,
            random,
            legacy_session_id,
            legacy_cookie,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }

    pub(crate) fn extension(&self, extension_type: u16) -> Option<&'a [u8]> {
        find_extension(&self.extensions, extension_type)
    }

    /// The versions of the supported_versions extension (RFC 8446 section 4.2.1), most
    /// preferred first, if the ClientHello has one that parses.
    pub(crate) fn supported_versions(&self) -> Option<Vec<u16>> {
        let data = self.extension(EXT_SUPPORTED_VERSIONS)?;
        let mut reader = Reader::new(data);
        let versions = reader.vec8().ok()?;
        if reader.finish().is_err() || versions.is_empty() || versions.len() % 2 != 0 {
            return None;
        }
        Some(
            versions
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect(),
        )
    }

    /// Whether the ClientHello offers DTLS 1.3.
    pub(crate) fn offers_dtls13(&self) -> bool {
        self.supported_versions()
            .is_some_and(|versions| versions.contains(&DTLS1_3_WIRE_VERSION))
    }
}

/// A `u16` list with a two-byte length that fills `data`: supported_groups and
/// signature_algorithms.
pub(crate) fn parse_u16_list(data: &[u8]) -> Result<Vec<u16>> {
    let mut reader = Reader::new(data);
    let list = reader.vec16()?;
    reader.finish()?;
    if list.is_empty() || list.len() % 2 != 0 {
        return Err(Error::ErrLengthMismatch);
    }
    Ok(list
        .chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect())
}

/// The key shares of a ClientHello's key_share extension (RFC 8446 section 4.2.8): each a
/// group and its key_exchange. The list may be empty.
pub(crate) fn parse_client_key_shares(data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut reader = Reader::new(data);
    let mut shares_reader = Reader::new(reader.vec16()?);
    reader.finish()?;
    let mut shares = vec![];
    while !shares_reader.is_empty() {
        let group = shares_reader.u16()?;
        let key_exchange = shares_reader.vec16()?;
        if key_exchange.is_empty() {
            return Err(Error::ErrLengthMismatch);
        }
        shares.push((group, key_exchange));
    }
    Ok(shares)
}

/// The use_srtp extension (RFC 5764 section 4.1.1): the protection profiles and the MKI.
pub(crate) fn parse_use_srtp(data: &[u8]) -> Result<(Vec<u16>, &[u8])> {
    let mut reader = Reader::new(data);
    let profiles = reader.vec16()?;
    let mki = reader.vec8()?;
    reader.finish()?;
    if profiles.is_empty() || profiles.len() % 2 != 0 {
        return Err(Error::ErrLengthMismatch);
    }
    Ok((
        profiles
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect(),
        mki,
    ))
}

/// The connection_id extension (RFC 9146 section 3): `opaque cid<0..2^8-1>`.
pub(crate) fn parse_connection_id(data: &[u8]) -> Result<&[u8]> {
    let mut reader = Reader::new(data);
    let connection_id = reader.vec8()?;
    reader.finish()?;
    Ok(connection_id)
}

/// The host_name of a server_name extension (RFC 6066 section 3), if it lists one.
pub(crate) fn parse_server_name(data: &[u8]) -> Result<Option<String>> {
    let mut reader = Reader::new(data);
    let mut list = Reader::new(reader.vec16()?);
    reader.finish()?;
    let mut host_name = None;
    while !list.is_empty() {
        let name_type = list.u8()?;
        let name = list.vec16()?;
        if name_type == 0 && host_name.is_none() {
            host_name =
                Some(String::from_utf8(name.to_vec()).map_err(|_| Error::ErrInvalidSniFormat)?);
        }
    }
    Ok(host_name)
}

/// A ServerHello or HelloRetryRequest as received (RFC 8446 section 4.1.3).
#[derive(Clone, Debug)]
pub(crate) struct ServerHello<'a> {
    pub(crate) legacy_version: u16,
    pub(crate) random: &'a [u8],
    pub(crate) legacy_session_id_echo: &'a [u8],
    pub(crate) cipher_suite: u16,
    pub(crate) legacy_compression_method: u8,
    pub(crate) extensions: Vec<(u16, &'a [u8])>,
}

impl<'a> ServerHello<'a> {
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(body);
        let legacy_version = reader.u16()?;
        let random = reader.bytes(32)?;
        let legacy_session_id_echo = reader.vec8()?;
        if legacy_session_id_echo.len() > 32 {
            return Err(Error::ErrLengthMismatch);
        }
        let cipher_suite = reader.u16()?;
        let legacy_compression_method = reader.u8()?;
        let extensions = if reader.is_empty() {
            vec![]
        } else {
            let block = reader.vec16()?;
            reader.finish()?;
            read_extensions(block)?
        };
        Ok(Self {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        })
    }

    pub(crate) fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }

    pub(crate) fn extension(&self, extension_type: u16) -> Option<&'a [u8]> {
        find_extension(&self.extensions, extension_type)
    }

    /// The selected_version of supported_versions, if the extension is there and well formed.
    pub(crate) fn selected_version(&self) -> Option<u16> {
        match self.extension(EXT_SUPPORTED_VERSIONS)? {
            [high, low] => Some(u16::from_be_bytes([*high, *low])),
            _ => None,
        }
    }
}

/// Writes a ServerHello body: `random` and the server's key share for a real one, or the
/// HelloRetryRequest random with the group to retry with and the cookie.
pub(crate) fn server_hello(
    random: &[u8; 32],
    cipher_suite: u16,
    extensions: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);
    put_u16(&mut body, DTLS1_2_WIRE_VERSION);
    body.extend_from_slice(random);
    // RFC 9147 section 5: the legacy_session_id is not echoed.
    body.push(0);
    put_u16(&mut body, cipher_suite);
    body.push(0);
    put_vec16(&mut body, |body| {
        put_extension(body, EXT_SUPPORTED_VERSIONS, |data| {
            put_u16(data, DTLS1_3_WIRE_VERSION)
        });
        extensions(body);
    });
    body
}

/// Writes the supported_versions extension of a ClientHello.
pub(crate) fn put_client_supported_versions(out: &mut Vec<u8>, versions: &[u16]) {
    put_extension(out, EXT_SUPPORTED_VERSIONS, |data| {
        put_vec8(data, |list| {
            for version in versions {
                put_u16(list, *version);
            }
        })
    });
}

/// The extension_data of a ClientHello key_share: the shares, each a group and its key.
pub(crate) fn client_key_share_data(shares: &[(u16, &[u8])]) -> Vec<u8> {
    let mut data = vec![];
    put_vec16(&mut data, |list| {
        for (group, key_exchange) in shares {
            put_u16(list, *group);
            put_vec16(list, |key| key.extend_from_slice(key_exchange));
        }
    });
    data
}

/// A Certificate message (RFC 8446 section 4.4.2): the request context and the chain, the
/// end-entity certificate first. No certificate entry carries extensions.
pub(crate) fn certificate(context: &[u8], chain: &[&[u8]]) -> Vec<u8> {
    let mut body = vec![];
    put_vec8(&mut body, |out| out.extend_from_slice(context));
    put_vec24(&mut body, |list| {
        for der in chain {
            put_vec24(list, |out| out.extend_from_slice(der));
            put_vec16(list, |_| {});
        }
    });
    body
}

/// Reads a Certificate message: its request context and the DER certificates.
///
/// # Errors
///
/// decode_error for a malformed message or an empty certificate; unsupported_extension for an
/// extension in a certificate entry, since this side asks for none (RFC 8446 section 4.4.2).
pub(crate) fn parse_certificate(
    body: &[u8],
) -> std::result::Result<(&[u8], Vec<Vec<u8>>), Refusal> {
    let mut reader = Reader::new(body);
    let context = reader.vec8().map_err(decode_error)?;
    let mut list = Reader::new(reader.vec24().map_err(decode_error)?);
    reader.finish().map_err(decode_error)?;
    let mut chain = vec![];
    while !list.is_empty() {
        let der = list.vec24().map_err(decode_error)?;
        if der.is_empty() {
            return Err(decode_error(Error::ErrLengthMismatch));
        }
        let extensions = list.vec16().map_err(decode_error)?;
        if !read_extensions(extensions)
            .map_err(decode_error)?
            .is_empty()
        {
            return Err(refuse(
                alert::UNSUPPORTED_EXTENSION,
                Error::ErrInvalidExtensionType,
            ));
        }
        chain.push(der.to_vec());
    }
    Ok((context, chain))
}

/// A CertificateVerify message (RFC 8446 section 4.4.3).
pub(crate) fn certificate_verify(scheme: u16, signature: &[u8]) -> Vec<u8> {
    let mut body = vec![];
    put_u16(&mut body, scheme);
    put_vec16(&mut body, |out| out.extend_from_slice(signature));
    body
}

pub(crate) fn parse_certificate_verify(body: &[u8]) -> Result<(u16, &[u8])> {
    let mut reader = Reader::new(body);
    let scheme = reader.u16()?;
    let signature = reader.vec16()?;
    reader.finish()?;
    Ok((scheme, signature))
}

/// A CertificateRequest message (RFC 8446 section 4.3.2) with the signature_algorithms
/// extension, which is mandatory.
pub(crate) fn certificate_request(context: &[u8], signature_schemes: &[u16]) -> Vec<u8> {
    let mut body = vec![];
    put_vec8(&mut body, |out| out.extend_from_slice(context));
    put_vec16(&mut body, |extensions| {
        put_extension(extensions, EXT_SIGNATURE_ALGORITHMS, |data| {
            put_vec16(data, |list| {
                for scheme in signature_schemes {
                    put_u16(list, *scheme);
                }
            })
        })
    });
    body
}

/// Reads a CertificateRequest: its context and the signature schemes it lists.
///
/// # Errors
///
/// decode_error when malformed, missing_extension without signature_algorithms.
pub(crate) fn parse_certificate_request(
    body: &[u8],
) -> std::result::Result<(&[u8], Vec<u16>), Refusal> {
    let mut reader = Reader::new(body);
    let context = reader.vec8().map_err(decode_error)?;
    let block = reader.vec16().map_err(decode_error)?;
    reader.finish().map_err(decode_error)?;
    let extensions = read_extensions(block).map_err(decode_error)?;
    let Some(schemes) = find_extension(&extensions, EXT_SIGNATURE_ALGORITHMS) else {
        return Err(refuse(
            alert::MISSING_EXTENSION,
            Error::ErrNoAvailableSignatureSchemes,
        ));
    };
    Ok((context, parse_u16_list(schemes).map_err(decode_error)?))
}

/// A KeyUpdate message (RFC 8446 section 4.6.3).
pub(crate) fn key_update(request_update: bool) -> Vec<u8> {
    vec![u8::from(request_update)]
}

/// Reads a KeyUpdate: whether it asks for one in return.
///
/// # Errors
///
/// illegal_parameter for a request_update that is neither value, decode_error for a body of
/// another length.
pub(crate) fn parse_key_update(body: &[u8]) -> std::result::Result<bool, Refusal> {
    match body {
        [0] => Ok(false),
        [1] => Ok(true),
        [_] => Err(refuse(
            alert::ILLEGAL_PARAMETER,
            Error::Other("KeyUpdate.request_update is neither 0 nor 1".to_owned()),
        )),
        _ => Err(decode_error(Error::ErrLengthMismatch)),
    }
}

/// `usage` of a NewConnectionId (RFC 9147 section 9).
pub(crate) const CID_IMMEDIATE: u8 = 0;
pub(crate) const CID_SPARE: u8 = 1;

/// A NewConnectionId message (RFC 9147 section 9).
pub(crate) fn new_connection_id(connection_ids: &[Vec<u8>], usage: u8) -> Vec<u8> {
    let mut body = vec![];
    put_vec16(&mut body, |list| {
        for connection_id in connection_ids {
            put_vec8(list, |out| out.extend_from_slice(connection_id));
        }
    });
    body.push(usage);
    body
}

/// Reads a NewConnectionId: the connection ids and the usage.
///
/// # Errors
///
/// decode_error when malformed, illegal_parameter for a usage that is neither value.
pub(crate) fn parse_new_connection_id(
    body: &[u8],
) -> std::result::Result<(Vec<Vec<u8>>, u8), Refusal> {
    let mut reader = Reader::new(body);
    let mut list = Reader::new(reader.vec16().map_err(decode_error)?);
    let usage = reader.u8().map_err(decode_error)?;
    reader.finish().map_err(decode_error)?;
    let mut connection_ids = vec![];
    while !list.is_empty() {
        connection_ids.push(list.vec8().map_err(decode_error)?.to_vec());
    }
    if usage != CID_IMMEDIATE && usage != CID_SPARE {
        return Err(refuse(
            alert::ILLEGAL_PARAMETER,
            Error::Other("NewConnectionId.usage is neither value".to_owned()),
        ));
    }
    Ok((connection_ids, usage))
}

/// A RequestConnectionId message (RFC 9147 section 9).
pub(crate) fn request_connection_id(count: u8) -> Vec<u8> {
    vec![count]
}

pub(crate) fn parse_request_connection_id(body: &[u8]) -> std::result::Result<u8, Refusal> {
    match body {
        [count] => Ok(*count),
        _ => Err(decode_error(Error::ErrLengthMismatch)),
    }
}

/// Checks a NewSessionTicket (RFC 8446 section 4.6.1) for form.
pub(crate) fn parse_new_session_ticket(body: &[u8]) -> std::result::Result<(), Refusal> {
    super::psk::parse_new_session_ticket(body)
        .map(|_| ())
        .map_err(decode_error)
}

/// The 12-byte header of a DTLSHandshake message (RFC 9147 section 5.2).
pub(crate) const HANDSHAKE_HEADER_LEN: usize = 12;

/// One DTLSHandshake fragment as read from a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HandshakeFragment<'a> {
    pub(crate) handshake_type: u8,
    /// The length of the whole message.
    pub(crate) length: usize,
    pub(crate) message_seq: u16,
    pub(crate) fragment_offset: usize,
    pub(crate) fragment: &'a [u8],
}

impl<'a> HandshakeFragment<'a> {
    /// Reads the DTLSHandshake fragments a handshake record holds: one, or several of one
    /// flight (RFC 9147 section 5.5).
    ///
    /// # Errors
    ///
    /// Fails if a header is truncated, a fragment runs past the record, or past the message
    /// it says it is part of.
    pub(crate) fn parse_all(mut record: &'a [u8]) -> Result<Vec<Self>> {
        let mut fragments = vec![];
        while !record.is_empty() {
            let mut reader = Reader::new(record);
            let handshake_type = reader.u8()?;
            let length = reader.u24()?;
            let message_seq = reader.u16()?;
            let fragment_offset = reader.u24()?;
            let fragment_length = reader.u24()?;
            let fragment = reader.bytes(fragment_length)?;
            if fragment_offset + fragment_length > length {
                return Err(Error::ErrLengthMismatch);
            }
            fragments.push(Self {
                handshake_type,
                length,
                message_seq,
                fragment_offset,
                fragment,
            });
            record = &record[HANDSHAKE_HEADER_LEN + fragment_length..];
        }
        if fragments.is_empty() {
            return Err(Error::ErrBufferTooSmall);
        }
        Ok(fragments)
    }
}

/// Writes one DTLSHandshake fragment: the header and `fragment`, bytes `fragment_offset..`
/// of a message `length` long.
pub(crate) fn handshake_fragment(
    handshake_type: u8,
    length: usize,
    message_seq: u16,
    fragment_offset: usize,
    fragment: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDSHAKE_HEADER_LEN + fragment.len());
    out.push(handshake_type);
    put_u24(&mut out, length);
    put_u16(&mut out, message_seq);
    put_u24(&mut out, fragment_offset);
    put_u24(&mut out, fragment.len());
    out.extend_from_slice(fragment);
    out
}
