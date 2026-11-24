#![no_main]
//! Stateful target: fuzzed SDP into `set_remote_description`, as an offer and as an answer.
//!
//! This is where a remote peer's text reaches the most engine code: the SDP parser, then media
//! section matching, codec and header-extension negotiation, transceiver creation and recycling,
//! simulcast `rid`s, SSRC groups, BUNDLE, ICE credentials and candidates, the DTLS fingerprint and
//! role, `sctp-port` / `max-message-size` and Cryptex. The input is up to three descriptions
//! separated by NUL bytes, applied in turn so renegotiation and glare paths run too. As an
//! offer, the peer then answers it; as an answer, the peer first makes an offer with audio, video
//! and a data channel for it to answer.

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::transport::RTCDtlsRole;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

fuzz_target!(|data: &[u8]| {
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    let now = common::start();
    let role = if config & 0x40 == 0 {
        RTCDtlsRole::Client
    } else {
        RTCDtlsRole::Server
    };
    let Some(mut pc) = common::peer(0, u64::from(config), role) else {
        return;
    };
    let _ = common::add_host_candidate(&mut pc, "192.0.2.1:5000".parse().unwrap());

    for (i, part) in rest.split(|&b| b == 0).take(3).enumerate() {
        let sdp = String::from_utf8_lossy(part).into_owned();
        // Bit i of the config byte: this description is an answer to our own offer, else an
        // offer from the peer.
        let as_answer = config & (1 << i) != 0;
        if as_answer {
            if config & 0x08 != 0 {
                let _ = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None);
                let _ = pc.add_transceiver_from_kind(RtpCodecKind::Video, None);
            }
            let _ = pc.create_data_channel("fuzz", None);
            let Ok(offer) = pc.create_offer(None) else {
                continue;
            };
            if pc.set_local_description(now, offer).is_err() {
                continue;
            }
            if let Ok(answer) = RTCSessionDescription::answer(sdp) {
                let _ = pc.set_remote_description(now, answer);
            }
        } else if let Ok(offer) = RTCSessionDescription::offer(sdp) {
            if pc.set_remote_description(now, offer).is_ok()
                && let Ok(answer) = pc.create_answer(None)
            {
                let _ = pc.set_local_description(now, answer);
            }
        }
        common::drain(&mut pc, |_| {});
        while rtci::sansio::Protocol::poll_write(&mut pc).is_some() {}
    }
    // Whatever was negotiated, the stats walk reads all of it.
    let _ = pc.get_stats(now, rtci::statistics::StatsSelector::None);
});
