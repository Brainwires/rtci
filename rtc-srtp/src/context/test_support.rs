//! Helpers shared by the context tests.

use super::*;
use crate::test_util::provider;

/// A master key and salt of the profile's lengths.
pub(crate) fn key_material(profile: ProtectionProfile) -> (Vec<u8>, Vec<u8>) {
    (
        (0..profile.key_len() as u8).map(|i| 0x10 + i).collect(),
        (0..profile.salt_len() as u8).map(|i| 0xA0 + i).collect(),
    )
}

/// A context with the default options (replay protection with a 64-packet window).
pub(crate) fn context(profile: ProtectionProfile) -> Context {
    let (key, salt) = key_material(profile);
    Context::new(&key, &salt, profile, None, None, provider().crypto()).unwrap()
}

/// A context with the given keying, over the same master key as [`context`].
pub(crate) fn keyed_context(profile: ProtectionProfile, keying: Keying) -> Context {
    let (key, salt) = key_material(profile);
    Context::with_keying(&key, &salt, profile, keying, None, None, provider()).unwrap()
}

/// A 12-octet RTP header (payload type 96) and `payload`.
pub(crate) fn rtp(ssrc: u32, sequence_number: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 96];
    packet.extend_from_slice(&sequence_number.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 1]);
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

pub(crate) const RTCP_SSRC: u32 = 0xdead_beef;

/// A receiver report with one report block, from [`RTCP_SSRC`].
pub(crate) fn rtcp() -> Vec<u8> {
    let mut packet = vec![0x81, 0xc9, 0x00, 0x07];
    packet.extend_from_slice(&RTCP_SSRC.to_be_bytes());
    packet.extend_from_slice(&[0x5A; 24]);
    packet
}

/// The ESRTCP word (E flag and SRTCP index) of a protected packet.
pub(crate) fn esrtcp(profile: ProtectionProfile, packet: &[u8], mki_len: usize) -> u32 {
    let at = packet.len() - profile.rtcp_auth_tag_len() - mki_len - 4;
    u32::from_be_bytes([packet[at], packet[at + 1], packet[at + 2], packet[at + 3]])
}

/// The SRTCP index of a protected packet.
pub(crate) fn srtcp_index(profile: ProtectionProfile, packet: &[u8], mki_len: usize) -> u32 {
    esrtcp(profile, packet, mki_len) & 0x7FFF_FFFF
}

/// Every event the context has queued.
pub(crate) fn events(context: &mut Context) -> Vec<ContextEvent> {
    std::iter::from_fn(|| context.poll_event()).collect()
}
