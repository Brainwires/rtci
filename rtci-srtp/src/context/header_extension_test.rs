//! Encryption of header extension elements (RFC 6904; RFC 7714 section 8.3 for the AEAD
//! profiles; RFC 9335 section 5 for its coexistence with Cryptex).

use super::test_support::*;
use super::*;
use crate::cryptex::Cryptex;
use crate::test_util::{hex, provider};

/// The master key and salt of RFC 3711 Appendix B.3, which RFC 6904 Appendix A reuses.
const MASTER_KEY: &str = "E1F97A0D3E018BE0D64FA32C06DE4139";
const MASTER_SALT: &str = "0EC675AD498AFEEBB6960B3AABE6";

/// The packet of RFC 6904 Appendix A.2 as libsrtp's test suite completes it: SSRC 0xCAFEBABE,
/// sequence number 0x1234, a one-byte header extension of 24 octets and a 16-octet payload.
const PLAIN: &str = "900f1234 decafbad cafebabe BEDE0006
                     17414273 A4752627 48220000 C8308E46 55996386 B395FB00
                     abababab abababab abababab abababab";

fn ids(ids: &[u8]) -> EncryptedHeaderExtensions {
    EncryptedHeaderExtensions::new(ids).unwrap()
}

fn rfc_context(profile: ProtectionProfile, encrypted: &[u8]) -> Context {
    let salt = hex(MASTER_SALT);
    let mut context = Context::new(
        &hex(MASTER_KEY),
        &salt[..profile.salt_len()],
        profile,
        None,
        None,
        provider().crypto(),
    )
    .unwrap();
    context.set_encrypted_header_extensions(ids(encrypted));
    context
}

/// RFC 6904 Appendix A.2: the header extension of a packet protected with AES-CM, with
/// elements 1, 3 and 4 negotiated as encrypted. The whole packet, payload and tag included, is
/// the one libsrtp produces for the same input (`srtp_validate_encrypted_extensions_headers`).
#[test]
fn aes_cm_header_extension_encryption_matches_rfc_6904_appendix_a2() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let plain = hex(PLAIN);
    let protected = rfc_context(profile, &[1, 3, 4])
        .encrypt_rtp(&plain)
        .unwrap();
    // "Ciphertext: 17588A9270F4E15E1C220000C8309546 A994F0BC54789700"
    assert_eq!(
        &protected[16..40],
        &hex("17588A9270F4E15E1C220000C8309546A994F0BC54789700")[..]
    );
    assert_eq!(
        &protected[..],
        &hex("900f1234 decafbad cafebabe BEDE0006
             17588A92 70F4E15E 1C220000 C8309546 A994F0BC 54789700
             4e55dc4c e79978d8 8ca4d215 949d2402
             5a46b3ca 35c535a8 91c7")[..]
    );
    assert_eq!(
        &rfc_context(profile, &[1, 3, 4])
            .decrypt_rtp(&protected)
            .unwrap()[..],
        &plain[..]
    );
}

/// RFC 7714 section 8.3: with AEAD_AES_128_GCM the header extension keystream is generated as
/// RFC 6904 has it with AES-CM, before the AEAD, which authenticates the encrypted elements as
/// associated data. The packet is the one libsrtp produces
/// (`srtp_validate_encrypted_extensions_headers_gcm`, which uses AEAD_AES_128_GCM_8: its tag is
/// the first 8 octets of the 16-octet tag).
#[test]
fn aead_aes_128_gcm_header_extension_encryption_interoperates_with_libsrtp() {
    let profile = ProtectionProfile::AeadAes128Gcm;
    let plain = hex(PLAIN);
    let protected = rfc_context(profile, &[1, 3, 4])
        .encrypt_rtp(&plain)
        .unwrap();
    assert_eq!(protected.len(), plain.len() + 16);
    assert_eq!(
        &protected[..plain.len() + 8],
        &hex("900f1234 decafbad cafebabe BEDE0006
             1712e020 5bfa949b 1C220000 C830bb46 732778d9 929aab00
             0eca0cf9 5ee955b2 6cd3d288 b49f6ca9
             f4b1b759 719eb5bc")[..]
    );
    assert_eq!(
        &rfc_context(profile, &[1, 3, 4])
            .decrypt_rtp(&protected)
            .unwrap()[..],
        &plain[..]
    );
}

/// A packet with one-byte or two-byte header extensions, CSRCs before them, elements 1 to 5
/// (element 3 empty in the two-byte form) and padding.
fn packet_with_extensions(two_byte: bool, seq: u16) -> (Vec<u8>, std::ops::Range<usize>) {
    let mut packet = vec![0x92, 96];
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 1, 0xCA, 0xFE, 0xBA, 0xBE]);
    packet.extend_from_slice(&[0, 0, 0, 0x11, 0, 0, 0, 0x22]);
    let data: Vec<u8> = if two_byte {
        hex("01 03 A1A2A3  02 01 B1  03 00  04 04 D1D2D3D4  00  05 02 E1E2  00 00 00")
    } else {
        hex("12 A1A2A3  20 B1  33 C1C2C3C4  00  43 D1D2D3D4  51 E1E2  00 00 00 00")
    };
    assert_eq!(data.len() % 4, 0);
    packet.extend_from_slice(if two_byte {
        &[0x10, 0x00]
    } else {
        &[0xBE, 0xDE]
    });
    packet.extend_from_slice(&((data.len() / 4) as u16).to_be_bytes());
    let start = packet.len();
    packet.extend_from_slice(&data);
    let end = packet.len();
    packet.extend_from_slice(b"the payload of the packet");
    (packet, start..end)
}

/// RFC 6904 section 3, for every profile and both RFC 8285 forms: only the payload of the
/// negotiated elements changes; element headers, the other elements and padding stay readable;
/// the receiver, given the same ids, restores the packet.
#[test]
fn only_the_selected_elements_are_encrypted_and_they_round_trip() {
    for profile in ProtectionProfile::ALL {
        for two_byte in [false, true] {
            let (plain, extension) = packet_with_extensions(two_byte, 100);
            let selected = [2u8, 4];
            let mut sender = context(profile);
            sender.set_encrypted_header_extensions(ids(&selected));
            assert_eq!(
                sender
                    .encrypted_header_extensions()
                    .ids()
                    .collect::<Vec<_>>(),
                selected
            );
            let protected = sender.encrypt_rtp(&plain).unwrap();

            // The octets of the extension that differ are exactly the payloads of 2 and 4.
            let changed: Vec<usize> = extension
                .clone()
                .filter(|&at| protected[at] != plain[at])
                .map(|at| at - extension.start)
                .collect();
            let expected: Vec<usize> = if profile.is_null_cipher() {
                // RFC 6904 section 3.2: the NULL cipher's header keystream is all zero.
                vec![]
            } else if two_byte {
                vec![7, 12, 13, 14, 15]
            } else {
                vec![5, 13, 14, 15, 16]
            };
            assert_eq!(changed, expected, "{profile:?} two-byte {two_byte}");
            // The fixed header, the CSRCs and the extension header are untouched.
            assert_eq!(&protected[..extension.start], &plain[..extension.start]);

            let mut receiver = context(profile);
            receiver.set_encrypted_header_extensions(ids(&selected));
            assert_eq!(&receiver.decrypt_rtp(&protected).unwrap()[..], &plain[..]);

            // A receiver that was not told the ids authenticates the packet and sees the
            // elements as sent: encrypted.
            let unaware = context(profile).decrypt_rtp(&protected).unwrap();
            assert_eq!(&unaware[extension.clone()], &protected[extension.clone()]);
            assert_eq!(&unaware[extension.end..], &plain[extension.end..]);
        }
    }
}

/// RFC 6904 section 3: the authentication tag is computed over the encrypted header extension,
/// and validated on it before anything is decrypted. A changed octet of an encrypted element is
/// an authentication failure, with the HMAC and with the AEAD (RFC 7714 section 8.3: the
/// extensions are associated data).
#[test]
fn encrypted_header_extensions_are_authenticated_as_sent() {
    for profile in ProtectionProfile::ALL {
        let (plain, extension) = packet_with_extensions(false, 7);
        let mut sender = context(profile);
        sender.set_encrypted_header_extensions(ids(&[1, 2, 3, 4, 5]));
        let protected = sender.encrypt_rtp(&plain).unwrap();
        for at in [extension.start + 1, extension.start + 5, extension.end - 4] {
            let mut forged = protected.to_vec();
            forged[at] ^= 0x40;
            let mut receiver = context(profile);
            receiver.set_encrypted_header_extensions(ids(&[1, 2, 3, 4, 5]));
            let error = receiver.decrypt_rtp(&forged).unwrap_err();
            assert!(
                matches!(
                    error,
                    Error::RtpFailedToVerifyAuthTag | Error::ErrFailedToVerifyAuthTag
                ),
                "{profile:?}: {error}"
            );
        }
    }
}

/// RFC 7941 section 6: the SDES items carried in header extensions (MID, RtpStreamId,
/// RepairedRtpStreamId) identify sources, and "SHOULD" have integrity and source
/// authentication. Left in the clear (the default, no Cryptex, no RFC 6904), they are still
/// part of the authenticated portion (RFC 3711 section 3.1): a changed octet anywhere in the
/// extension block fails the authentication, with the HMAC and with the AEAD profiles.
#[test]
fn clear_header_extensions_are_authenticated_as_sent() {
    for profile in ProtectionProfile::ALL {
        for two_byte in [false, true] {
            let (plain, extension) = packet_with_extensions(two_byte, 9);
            let protected = context(profile).encrypt_rtp(&plain).unwrap();
            assert_eq!(
                &protected[extension.clone()],
                &plain[extension.clone()],
                "{profile:?}: the extensions stay readable"
            );
            // Octets of element data (A1, A2 and B1 in `packet_with_extensions`).
            let data = if two_byte { [2, 3, 7] } else { [1, 2, 5] };
            for at in data.map(|offset| extension.start + offset) {
                let mut forged = protected.to_vec();
                forged[at] ^= 0x01;
                let error = context(profile).decrypt_rtp(&forged).unwrap_err();
                assert!(
                    matches!(
                        error,
                        Error::RtpFailedToVerifyAuthTag | Error::ErrFailedToVerifyAuthTag
                    ),
                    "{profile:?} two-byte {two_byte}, octet {at}: {error}"
                );
            }
        }
    }
}

/// RFC 6904 section 3.2: the header keystream uses the IV of the packet, so it differs from
/// packet to packet and from the payload keystream (k_he and k_hs are keys of their own).
#[test]
fn header_keystream_is_per_packet_and_separate_from_the_payload_keystream() {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let mut sender = context(profile);
    sender.set_encrypted_header_extensions(ids(&[1]));
    let element = |seq: u16| -> Vec<u8> {
        // One element (id 1, 16 octets) and a payload of the same 16 octets.
        let mut packet = vec![0x90, 96];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 9, 0xBE, 0xDE, 0, 5]);
        packet.push(0x1F);
        packet.extend_from_slice(&[0x77; 16]);
        packet.extend_from_slice(&[0, 0, 0]);
        packet.extend_from_slice(&[0x77; 16]);
        packet
    };
    let first = sender.encrypt_rtp(&element(1)).unwrap();
    let second = sender.encrypt_rtp(&element(2)).unwrap();
    assert_ne!(&first[17..33], &[0x77; 16][..], "the element is encrypted");
    assert_ne!(&first[17..33], &second[17..33], "per-packet keystream");
    assert_ne!(&first[17..33], &first[36..52], "not the payload keystream");
}

/// RFC 9335 section 5: both mechanisms may be negotiated, and a packet protected with Cryptex
/// does not also use RFC 6904. With both set, a packet Cryptex applies to is a Cryptex packet
/// and nothing else; one it does not apply to (no RFC 8285 extension here: a sender not using
/// Cryptex) is protected as RFC 6904 has it.
#[test]
fn a_cryptex_packet_is_not_also_encrypted_as_rfc_6904_has_it() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let (plain, extension) = packet_with_extensions(false, 55);
        let send = Cryptex {
            send: true,
            require: false,
        };

        let mut both = context(profile);
        both.set_cryptex(send);
        both.set_encrypted_header_extensions(ids(&[2, 4]));
        let mut cryptex_only = context(profile);
        cryptex_only.set_cryptex(send);
        let protected = both.encrypt_rtp(&plain).unwrap();
        assert_eq!(
            protected,
            cryptex_only.encrypt_rtp(&plain).unwrap(),
            "{profile:?}: Cryptex alone"
        );

        // The receiver has both too: the 0xC0DE packet is decrypted as Cryptex only.
        let mut receiver = context(profile);
        receiver.set_encrypted_header_extensions(ids(&[2, 4]));
        assert_eq!(&receiver.decrypt_rtp(&protected).unwrap()[..], &plain[..]);

        // The same sender with Cryptex off for sending falls back to RFC 6904, and the same
        // receiver takes that packet as well.
        let mut rfc6904 = context(profile);
        rfc6904.set_encrypted_header_extensions(ids(&[2, 4]));
        let (plain, _) = packet_with_extensions(false, 56);
        let protected = rfc6904.encrypt_rtp(&plain).unwrap();
        assert_eq!(
            &protected[extension.start - 4..extension.start - 2],
            &[0xBE, 0xDE]
        );
        assert_ne!(&protected[extension.clone()], &plain[extension.clone()]);
        assert_eq!(&receiver.decrypt_rtp(&protected).unwrap()[..], &plain[..]);
    }
}

/// Packets RFC 6904 has nothing to do with go through unchanged: no extension, an extension
/// that is not RFC 8285's, none of the negotiated ids present.
#[test]
fn packets_without_selected_elements_are_protected_as_usual() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes256Gcm,
    ] {
        let (with_extension, _) = packet_with_extensions(true, 1);
        let mut profile_specific = with_extension.clone();
        profile_specific[20..22].copy_from_slice(&[0xAB, 0xCD]);
        for (packet, selected) in [
            (rtp(1, 1, b"no extension"), vec![1u8, 2, 3]),
            (profile_specific, vec![1, 2, 3, 4, 5]),
            (with_extension, vec![9, 200]),
        ] {
            let mut sender = context(profile);
            sender.set_encrypted_header_extensions(ids(&selected));
            assert_eq!(
                sender.encrypt_rtp(&packet).unwrap(),
                context(profile).encrypt_rtp(&packet).unwrap(),
                "{profile:?}"
            );
        }
    }
}

/// The header keystream never reaches octets the payload transform covers: when the header the
/// caller parsed is not the packet's (it has no extension, the bytes have one), the "extension"
/// lies in what is encrypted as payload, and RFC 6904 leaves it alone.
#[test]
fn a_header_that_is_not_the_packets_gets_no_header_extension_encryption() {
    use shared::marshal::Unmarshal;
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let (packet, _) = packet_with_extensions(false, 3);
        let mut without_extension = packet.clone();
        without_extension[0] = 0x80;
        let header = rtp::Header::unmarshal(&mut &without_extension[..]).unwrap();

        let mut sender = context(profile);
        sender.set_encrypted_header_extensions(ids(&[1, 2, 3, 4, 5]));
        assert_eq!(
            sender.encrypt_rtp_with_header(&packet, &header).unwrap(),
            context(profile)
                .encrypt_rtp_with_header(&packet, &header)
                .unwrap(),
            "{profile:?}"
        );
    }
}
