#![no_main]
//! Parser target: the RTP header extensions a peer sends (RFC 8285 one-byte and two-byte forms)
//! and the parsers of each extension the engine reads: audio level (RFC 6464), absolute send
//! time, transport-wide sequence number, video orientation and playout delay. Each parser runs
//! on every extension element of a parsed packet and on the raw input; a parsed packet is
//! marshalled back, converted to the two-byte form and marshalled again. The RFC 3550 Appendix
//! A.1 validity check runs on the raw input.

use libfuzzer_sys::fuzz_target;
use rtci_rtp::extension::abs_capture_time_extension::AbsCaptureTimeExtension;
use rtci_rtp::extension::abs_send_time_extension::AbsSendTimeExtension;
use rtci_rtp::extension::csrc_audio_level_extension::CsrcAudioLevelExtension;
use rtci_rtp::extension::sdes_extension::{Mid, RepairedRtpStreamId, RtpStreamId};
use rtci_rtp::extension::transmission_offset_extension::TransmissionOffsetExtension;
use rtci_rtp::header::validity::check_rtp_validity;
use rtci_rtp::extension::audio_level_extension::AudioLevelExtension;
use rtci_rtp::extension::playout_delay_extension::PlayoutDelayExtension;
use rtci_rtp::extension::transport_cc_extension::TransportCcExtension;
use rtci_rtp::extension::video_orientation_extension::VideoOrientationExtension;
use rtci_rtp::packet::Packet;
use rtci_shared::marshal::{Marshal, MarshalSize, Unmarshal};

fn parse_all(data: &[u8]) {
    let _ = AudioLevelExtension::unmarshal(&mut &data[..]);
    let _ = AbsSendTimeExtension::unmarshal(&mut &data[..]);
    let _ = TransportCcExtension::unmarshal(&mut &data[..]);
    let _ = VideoOrientationExtension::unmarshal(&mut &data[..]);
    let _ = PlayoutDelayExtension::unmarshal(&mut &data[..]);
    // The codecs whose value survives a round trip: what parses marshals back to the same.
    if let Ok(value) = AbsCaptureTimeExtension::unmarshal(&mut &data[..]) {
        let raw = value.marshal().expect("a parsed value marshals");
        assert_eq!(value, AbsCaptureTimeExtension::unmarshal(&mut &raw[..]).unwrap());
    }
    if let Ok(value) = CsrcAudioLevelExtension::unmarshal(&mut &data[..]) {
        let raw = value.marshal().expect("a parsed value marshals");
        assert_eq!(value, CsrcAudioLevelExtension::unmarshal(&mut &raw[..]).unwrap());
    }
    if let Ok(value) = TransmissionOffsetExtension::unmarshal(&mut &data[..]) {
        let raw = value.marshal().expect("a parsed value marshals");
        assert_eq!(value, TransmissionOffsetExtension::unmarshal(&mut &raw[..]).unwrap());
    }
    if let Ok(value) = Mid::unmarshal(&mut &data[..]) {
        assert_eq!(data, &value.marshal().expect("a parsed value marshals")[..]);
    }
    if let Ok(value) = RtpStreamId::unmarshal(&mut &data[..]) {
        assert_eq!(data, &value.marshal().expect("a parsed value marshals")[..]);
    }
    let _ = RepairedRtpStreamId::unmarshal(&mut &data[..]);
}

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = check_rtp_validity(data, |_| true);
    if let Ok(mut packet) = Packet::unmarshal(&mut buf) {
        // What parses re-marshals at the size it says, and the forms convert.
        if let Ok(raw) = packet.marshal() {
            assert_eq!(packet.marshal_size(), raw.len());
        }
        if packet.header.upgrade_to_two_byte().is_ok() {
            let _ = packet.header.set_extension_upgrading(200, bytes::Bytes::new());
            if let Ok(raw) = packet.marshal() {
                assert_eq!(packet.marshal_size(), raw.len());
            }
        }
        for id in packet.header.get_extension_ids() {
            if let Some(extension) = packet.header.get_extension(id) {
                parse_all(&extension);
            }
        }
        let _ = packet.header.get_extension_payload_len();
        let _ = packet.marshal();
    }
    parse_all(data);
});
