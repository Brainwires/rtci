/// Server Name Indication (SNI).
pub mod extension_server_name;
/// The curves a client will accept for ECDHE.
pub mod extension_supported_elliptic_curves;
/// The EC point formats a client will accept; WebRTC uses uncompressed.
pub mod extension_supported_point_formats;
/// The signature and hash algorithm pairs a client will accept.
pub mod extension_supported_signature_algorithms;
/// The extended master secret extension ([RFC 7627]), which binds the master secret to the
/// whole handshake.
pub mod extension_use_extended_master_secret;
/// The `use_srtp` extension, which negotiates SRTP protection profiles during the DTLS
/// handshake ([RFC 5764]).
pub mod extension_use_srtp;
/// The renegotiation info extension, sent empty to signal renegotiation is not supported.
pub mod renegotiation_info;

use extension_server_name::*;
use extension_supported_elliptic_curves::*;
use extension_supported_point_formats::*;
use extension_supported_signature_algorithms::*;
use extension_use_extended_master_secret::*;
use extension_use_srtp::*;

use shared::error::*;

use crate::extension::renegotiation_info::ExtensionRenegotiationInfo;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
#[derive(Clone, Debug, PartialEq, Eq)]
/// The extension type code points this crate understands.
#[non_exhaustive]
pub enum ExtensionValue {
    /// `SERVER_NAME` (`0`).
    ServerName = 0,
    /// `SUPPORTED_ELLIPTIC_CURVES` (`10`).
    SupportedEllipticCurves = 10,
    /// `SUPPORTED_POINT_FORMATS` (`11`).
    SupportedPointFormats = 11,
    /// `SUPPORTED_SIGNATURE_ALGORITHMS` (`13`).
    SupportedSignatureAlgorithms = 13,
    /// `USE_SRTP` (`14`).
    UseSrtp = 14,
    /// `USE_EXTENDED_MASTER_SECRET` (`23`).
    UseExtendedMasterSecret = 23,
    /// `RENEGOTIATION_INFO` (`65281`).
    RenegotiationInfo = 65281,
    /// An extension this crate does not implement, which is ignored.
    Unsupported,
}

impl From<u16> for ExtensionValue {
    fn from(val: u16) -> Self {
        match val {
            0 => ExtensionValue::ServerName,
            10 => ExtensionValue::SupportedEllipticCurves,
            11 => ExtensionValue::SupportedPointFormats,
            13 => ExtensionValue::SupportedSignatureAlgorithms,
            14 => ExtensionValue::UseSrtp,
            23 => ExtensionValue::UseExtendedMasterSecret,
            65281 => ExtensionValue::RenegotiationInfo,
            _ => ExtensionValue::Unsupported,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// A parsed hello extension.
#[non_exhaustive]
pub enum Extension {
    /// Server Name Indication.
    ServerName(ExtensionServerName),
    /// The curves the sender accepts for ECDHE.
    SupportedEllipticCurves(ExtensionSupportedEllipticCurves),
    /// The EC point formats the sender accepts.
    SupportedPointFormats(ExtensionSupportedPointFormats),
    /// The signature and hash pairs the sender accepts.
    SupportedSignatureAlgorithms(ExtensionSupportedSignatureAlgorithms),
    /// The SRTP protection profiles offered or selected.
    UseSrtp(ExtensionUseSrtp),
    /// The extended master secret extension.
    UseExtendedMasterSecret(ExtensionUseExtendedMasterSecret),
    /// The renegotiation info extension.
    RenegotiationInfo(ExtensionRenegotiationInfo),
    /// An extension this crate does not implement, or one of a known type whose contents did
    /// not parse: kept with its type, so a hello can be checked for extensions that were not
    /// offered (RFC 5246 7.4.1.4), and otherwise ignored.
    Unknown {
        /// The extension type code point.
        extension_type: u16,
        /// The extension_data, as received.
        data: Vec<u8>,
    },
}

/// The `connection_id` extension type (RFC 9146 section 3, RFC 9147 section 9).
pub(crate) const EXTENSION_CONNECTION_ID: u16 = 54;

impl Extension {
    /// A `connection_id` extension (RFC 9146 section 3): `opaque cid<0..2^8-1>`, the
    /// connection id the sender wants in the records it receives.
    pub(crate) fn connection_id(connection_id: &[u8]) -> Self {
        let mut data = vec![connection_id.len() as u8];
        data.extend_from_slice(connection_id);
        Extension::Unknown {
            extension_type: EXTENSION_CONNECTION_ID,
            data,
        }
    }

    /// The connection id of a `connection_id` extension: `None` for another extension,
    /// an error when its contents are not one length-prefixed connection id.
    pub(crate) fn as_connection_id(&self) -> Option<Result<&[u8]>> {
        match self {
            Extension::Unknown {
                extension_type: EXTENSION_CONNECTION_ID,
                data,
            } => Some(match data.split_first() {
                Some((length, connection_id)) if usize::from(*length) == connection_id.len() => {
                    Ok(connection_id)
                }
                _ => Err(Error::Other("malformed connection_id extension".to_owned())),
            }),
            _ => None,
        }
    }

    /// The extension type code point this value is carried under.
    pub fn extension_type(&self) -> u16 {
        match self {
            Extension::Unknown { extension_type, .. } => *extension_type,
            known => known.extension_value() as u16,
        }
    }

    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        match self {
            Extension::Unknown { .. } => ExtensionValue::Unsupported,
            Extension::ServerName(ext) => ext.extension_value(),
            Extension::SupportedEllipticCurves(ext) => ext.extension_value(),
            Extension::SupportedPointFormats(ext) => ext.extension_value(),
            Extension::SupportedSignatureAlgorithms(ext) => ext.extension_value(),
            Extension::UseSrtp(ext) => ext.extension_value(),
            Extension::UseExtendedMasterSecret(ext) => ext.extension_value(),
            Extension::RenegotiationInfo(ext) => ext.extension_value(),
        }
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        let mut len = 2;

        len += match self {
            Extension::ServerName(ext) => ext.size(),
            Extension::SupportedEllipticCurves(ext) => ext.size(),
            Extension::SupportedPointFormats(ext) => ext.size(),
            Extension::SupportedSignatureAlgorithms(ext) => ext.size(),
            Extension::UseSrtp(ext) => ext.size(),
            Extension::UseExtendedMasterSecret(ext) => ext.size(),
            Extension::RenegotiationInfo(ext) => ext.size(),
            Extension::Unknown { data, .. } => 2 + data.len(),
        };

        len
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.extension_type())?;
        match self {
            Extension::Unknown { data, .. } => {
                writer.write_u16::<BigEndian>(data.len() as u16)?;
                writer.write_all(data)?;
                Ok(writer.flush()?)
            }
            Extension::ServerName(ext) => ext.marshal(writer),
            Extension::SupportedEllipticCurves(ext) => ext.marshal(writer),
            Extension::SupportedPointFormats(ext) => ext.marshal(writer),
            Extension::SupportedSignatureAlgorithms(ext) => ext.marshal(writer),
            Extension::UseSrtp(ext) => ext.marshal(writer),
            Extension::UseExtendedMasterSecret(ext) => ext.marshal(writer),
            Extension::RenegotiationInfo(ext) => ext.marshal(writer),
        }
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated or its contents are not a valid encoding.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let extension_value: ExtensionValue = reader.read_u16::<BigEndian>()?.into();
        match extension_value {
            ExtensionValue::ServerName => Ok(Extension::ServerName(
                ExtensionServerName::unmarshal(reader)?,
            )),
            ExtensionValue::SupportedEllipticCurves => Ok(Extension::SupportedEllipticCurves(
                ExtensionSupportedEllipticCurves::unmarshal(reader)?,
            )),
            ExtensionValue::SupportedPointFormats => Ok(Extension::SupportedPointFormats(
                ExtensionSupportedPointFormats::unmarshal(reader)?,
            )),
            ExtensionValue::SupportedSignatureAlgorithms => {
                Ok(Extension::SupportedSignatureAlgorithms(
                    ExtensionSupportedSignatureAlgorithms::unmarshal(reader)?,
                ))
            }
            ExtensionValue::UseSrtp => Ok(Extension::UseSrtp(ExtensionUseSrtp::unmarshal(reader)?)),
            ExtensionValue::UseExtendedMasterSecret => Ok(Extension::UseExtendedMasterSecret(
                ExtensionUseExtendedMasterSecret::unmarshal(reader)?,
            )),
            ExtensionValue::RenegotiationInfo => Ok(Extension::RenegotiationInfo(
                ExtensionRenegotiationInfo::unmarshal(reader)?,
            )),
            _ => Err(Error::ErrInvalidExtensionType),
        }
    }
}

/// Decodes the extensions that may end a ClientHello or ServerHello (RFC 5246 7.4.1.2,
/// 7.4.1.3): either nothing at all (the hello ends after the compression methods) or a 2-byte
/// length followed by exactly that many bytes of extensions. `reader` must end where the hello
/// ends.
///
/// An extension of a type this crate does not implement, or whose contents do not parse, is
/// returned as [`Extension::Unknown`].
///
/// # Errors
///
/// Fails if the block is truncated, is followed by further bytes, or holds two extensions of
/// one type (RFC 5246 7.4.1.4).
pub(crate) fn unmarshal_hello_extensions<R: Read>(reader: &mut R) -> Result<Vec<Extension>> {
    let mut rest = vec![];
    reader.read_to_end(&mut rest)?;
    if rest.is_empty() {
        return Ok(vec![]);
    }
    if rest.len() < 2 {
        return Err(Error::ErrBufferTooSmall);
    }
    let block = &rest[2..];
    if u16::from_be_bytes([rest[0], rest[1]]) as usize != block.len() {
        return Err(Error::ErrLengthMismatch);
    }

    let mut extensions = vec![];
    let mut seen: Vec<u16> = vec![];
    let mut offset = 0;
    while offset < block.len() {
        if offset + 4 > block.len() {
            return Err(Error::ErrBufferTooSmall);
        }
        let extension_type = u16::from_be_bytes([block[offset], block[offset + 1]]);
        let data_len = u16::from_be_bytes([block[offset + 2], block[offset + 3]]) as usize;
        let end = offset + 4 + data_len;
        if end > block.len() {
            return Err(Error::ErrBufferTooSmall);
        }
        if seen.contains(&extension_type) {
            return Err(Error::ErrDuplicateExtension);
        }
        seen.push(extension_type);

        let mut extension_reader = &block[offset..end];
        match Extension::unmarshal(&mut extension_reader) {
            Ok(extension) => extensions.push(extension),
            Err(err) => {
                log::debug!("extension type {extension_type} kept unparsed: {err}");
                extensions.push(Extension::Unknown {
                    extension_type,
                    data: block[offset + 4..end].to_vec(),
                });
            }
        }
        offset = end;
    }

    Ok(extensions)
}
