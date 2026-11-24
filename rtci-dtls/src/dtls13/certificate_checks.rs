//! What DTLS 1.3 asks of the certificates an endpoint sends and receives beyond the
//! handshake signature: the server's key may be used for signing (RFC 8446 section 4.4.2.2),
//! a client answers a CertificateRequest's `oid_filters` (sections 4.2.5 and 4.4.2.3) and
//! signs its chain with algorithms the request lists (4.4.2.3), and nobody takes a
//! certificate signed with MD5 (4.4.2.4).

use super::codec::Reader;
use crate::signature_hash_algorithm::SignatureHashAlgorithm;
use rustls::pki_types::CertificateDer;
use shared::error::Result;

/// The DER content of the KeyUsage extension's OID, 2.5.29.15.
const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x0f];
/// The DER content of the ExtendedKeyUsage extension's OID, 2.5.29.37.
const OID_EXTENDED_KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x25];
/// KeyUsage's digitalSignature bit, as x509-parser numbers the flags.
const DIGITAL_SIGNATURE: u16 = 1;

/// One entry of an `oid_filters` extension (RFC 8446 section 4.2.5): a certificate extension
/// OID and the DER of the values asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OidFilter {
    pub(crate) oid: Vec<u8>,
    pub(crate) values: Vec<u8>,
}

/// Reads the data of an `oid_filters` extension.
///
/// # Errors
///
/// When it is malformed (decode_error to the caller).
pub(crate) fn parse_oid_filters(data: &[u8]) -> Result<Vec<OidFilter>> {
    let mut reader = Reader::new(data);
    let mut list = Reader::new(reader.vec16()?);
    reader.finish()?;
    let mut filters = vec![];
    while !list.is_empty() {
        let oid = list.vec8()?;
        if oid.is_empty() {
            return Err(shared::error::Error::ErrLengthMismatch);
        }
        let values = list.vec16()?;
        filters.push(OidFilter {
            oid: oid.to_vec(),
            values: values.to_vec(),
        });
    }
    Ok(filters)
}

/// The content octets of a DER OID, whether `oid` carries its tag and length or not.
fn oid_content(oid: &[u8]) -> &[u8] {
    match oid {
        [0x06, length, rest @ ..] if usize::from(*length) == rest.len() => rest,
        _ => oid,
    }
}

/// A DER tag-length-value at the start of `input`: (tag, value, the rest). Short and long
/// definite lengths up to four bytes.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let mut length = 0usize;
        for byte in &rest[..count] {
            length = (length << 8) | usize::from(*byte);
        }
        rest = &rest[count..];
        length
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

/// The OIDs of a DER `SEQUENCE OF OBJECT IDENTIFIER` (an ExtendedKeyUsage value).
fn der_oids(value: &[u8]) -> Option<Vec<&[u8]>> {
    let (tag, mut items, rest) = der_element(value)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let mut oids = vec![];
    while !items.is_empty() {
        let (tag, oid, rest) = der_element(items)?;
        if tag != 0x06 {
            return None;
        }
        oids.push(oid);
        items = rest;
    }
    Some(oids)
}

/// The flags of a DER BIT STRING that holds a KeyUsage, numbered as x509-parser numbers them
/// (bit 0, digitalSignature, is the first bit of the string).
fn der_key_usage_flags(value: &[u8]) -> Option<u16> {
    let (tag, content, rest) = der_element(value)?;
    if tag != 0x03 || !rest.is_empty() {
        return None;
    }
    let (_unused_bits, data) = content.split_first()?;
    Some(data.iter().take(2).rev().fold(0u16, |flags, byte| {
        (flags << 8) | u16::from(byte.reverse_bits())
    }))
}

/// Whether the end-entity certificate `der` meets `filters` (RFC 8446 section 4.2.5): it
/// carries every extension of a filter this side recognizes (KeyUsage and ExtendedKeyUsage,
/// the two the section defines matching for), with at least the values asked for. Filters
/// for other extensions are skipped, as the section says.
pub(crate) fn matches_oid_filters(der: &[u8], filters: &[OidFilter]) -> bool {
    if filters.is_empty() {
        return true;
    }
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    let extension_value = |oid: &[u8]| {
        certificate
            .extensions()
            .iter()
            .find(|extension| extension.oid.as_bytes() == oid)
            .map(|extension| extension.value)
    };
    filters.iter().all(|filter| match oid_content(&filter.oid) {
        oid if oid == OID_KEY_USAGE => {
            match (
                der_key_usage_flags(&filter.values),
                extension_value(&OID_KEY_USAGE).and_then(der_key_usage_flags),
            ) {
                (Some(asked), Some(held)) => asked & held == asked,
                _ => false,
            }
        }
        oid if oid == OID_EXTENDED_KEY_USAGE => {
            match (
                der_oids(&filter.values),
                extension_value(&OID_EXTENDED_KEY_USAGE).and_then(der_oids),
            ) {
                (Some(asked), Some(held)) => asked.iter().all(|purpose| held.contains(purpose)),
                _ => false,
            }
        }
        _ => true,
    })
}

/// Whether the key of the certificate `der` may sign (RFC 8446 section 4.4.2.2): its
/// KeyUsage, if it has one, asserts digitalSignature. A certificate that does not parse is
/// not judged here.
pub(crate) fn allows_signing(der: &[u8]) -> bool {
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
        return true;
    };
    match certificate.key_usage() {
        Ok(Some(key_usage)) => key_usage.value.flags & DIGITAL_SIGNATURE != 0,
        Ok(None) => true,
        // Two KeyUsage extensions, or one that does not parse: not a key to sign with.
        Err(_) => false,
    }
}

/// Whether the certificate `der` is signed with an MD5-based algorithm (RFC 8446 section
/// 4.4.2.4): md5WithRSAEncryption, in its PKCS#1 and its OIW form.
pub(crate) fn signed_with_md5(der: &[u8]) -> bool {
    x509_parser::parse_x509_certificate(der).is_ok_and(|(_, certificate)| {
        matches!(
            certificate
                .signature_algorithm
                .algorithm
                .to_id_string()
                .as_str(),
            "1.2.840.113549.1.1.4" | "1.3.14.3.2.3"
        )
    })
}

/// Whether the certificate `der` is signed with a SHA-1-based algorithm (RFC 8446 section
/// 4.4.2.4): sha1WithRSAEncryption (PKCS#1 and OIW), ecdsa-with-SHA1, dsa-with-sha1.
pub(crate) fn signed_with_sha1(der: &[u8]) -> bool {
    x509_parser::parse_x509_certificate(der).is_ok_and(|(_, certificate)| {
        matches!(
            certificate
                .signature_algorithm
                .algorithm
                .to_id_string()
                .as_str(),
            "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" | "1.2.840.10045.4.1" | "1.2.840.10040.4.3"
        )
    })
}

/// Whether a certificate is self-signed: it begins a certification path, so its signature
/// is not validated and may use an algorithm the peer did not list (RFC 8446 section 4.2.3).
fn is_self_signed(der: &[u8]) -> bool {
    x509_parser::parse_x509_certificate(der).is_ok_and(|(_, certificate)| {
        certificate.tbs_certificate.issuer.as_raw() == certificate.tbs_certificate.subject.as_raw()
    })
}

/// Whether the chain a client answers a CertificateRequest with is signed with algorithms
/// the request lists (RFC 8446 section 4.4.2.3), a self-signed certificate excepted.
pub(crate) fn client_chain_acceptable(
    chain: &[CertificateDer<'static>],
    schemes: &[SignatureHashAlgorithm],
) -> bool {
    let issued: Vec<CertificateDer<'static>> = chain
        .iter()
        .filter(|certificate| !is_self_signed(certificate.as_ref()))
        .cloned()
        .collect();
    crate::crypto::certificates_signed_within(&issued, schemes)
}
