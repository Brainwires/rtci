#![no_main]
//! Parser target: the RTP header extensions a peer sends (RFC 8285 one-byte and two-byte forms)
//! and the parsers of each extension the engine reads: audio level (RFC 6464), absolute send
//! time, transport-wide sequence number, video orientation and playout delay. Each parser runs
//! on every extension element of a parsed packet and on the raw input; a parsed packet is
//! marshalled back.

use libfuzzer_sys::fuzz_target;
use rtc_rtp::extension::abs_send_time_extension::AbsSendTimeExtension;
use rtc_rtp::extension::audio_level_extension::AudioLevelExtension;
use rtc_rtp::extension::playout_delay_extension::PlayoutDelayExtension;
use rtc_rtp::extension::transport_cc_extension::TransportCcExtension;
use rtc_rtp::extension::video_orientation_extension::VideoOrientationExtension;
use rtc_rtp::packet::Packet;
use rtc_shared::marshal::{Marshal, Unmarshal};

fn parse_all(data: &[u8]) {
    let _ = AudioLevelExtension::unmarshal(&mut &data[..]);
    let _ = AbsSendTimeExtension::unmarshal(&mut &data[..]);
    let _ = TransportCcExtension::unmarshal(&mut &data[..]);
    let _ = VideoOrientationExtension::unmarshal(&mut &data[..]);
    let _ = PlayoutDelayExtension::unmarshal(&mut &data[..]);
}

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    if let Ok(packet) = Packet::unmarshal(&mut buf) {
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
