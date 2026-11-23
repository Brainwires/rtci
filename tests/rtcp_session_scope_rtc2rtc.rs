//! An RTP session, and with it RTCP, exists only where an RTP m= section is negotiated (RFC
//! 3550 section 6: RTCP is "the control protocol" of an RTP session; RFC 8834 section 4.1;
//! RFC 9429 section 5.2.1: a transport carries RTP only for the sections that use it), and
//! what it sends is SRTCP (RFC 3711 section 3.4, RFC 5764 section 4.1, RFC 8827 section 6.5).
//! Between two `rtc` peers on an in-memory network and a virtual clock:
//!
//! - a data-channel-only connection sends no datagram in the RTP / RTCP range (RFC 7983:
//!   first byte 128 to 191) at all, whether or not its DTLS association negotiated
//!   `use_srtp`;
//! - a media section added later starts RTCP, and every RTCP datagram is protected;
//! - removing every media section ends it: the session says BYE once and is silent from then
//!   on, and a media section added again starts it again.
//!
//! The per-transport form (several transports, RTCP on the ones with a media section only) is
//! in `multi_transport_rtc2rtc.rs`.

mod dtls_sdp_common;

use anyhow::Result;
use dtls_sdp_common::{Peer, World};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::rtp_transceiver::RTCRtpTransceiverInit;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::time::Duration;

fn world(use_srtp_on_every_association: bool) -> Result<World> {
    let peer = |addr: &str| {
        Peer::new(
            addr,
            SettingEngineBuilder::new()
                .with_dtls_use_srtp_on_every_association(use_srtp_on_every_association)
                .build(),
        )
    };
    Ok(World::new(peer("10.0.0.1:5000")?, peer("10.0.0.2:5000")?))
}

/// RFC 7983 section 7: a first byte of 128 to 191 is RTP or RTCP.
fn in_rtp_range(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|b| (128..=191).contains(b))
}

/// RTCP: in the RTP range with a packet type of 192 to 223 (RFC 5761 section 4).
fn is_rtcp(datagram: &[u8]) -> bool {
    in_rtp_range(datagram) && datagram.get(1).is_some_and(|b| (192..=223).contains(b))
}

/// Whether the datagram is plain compound RTCP: RTCP packets whose headers (version 2, length)
/// cover it exactly. SRTCP encrypts everything after the first header and SSRC and appends the
/// SRTCP index and the authentication tag (RFC 3711 section 3.4), so its headers do not.
fn is_plain_rtcp(datagram: &[u8]) -> bool {
    let mut at = 0;
    while at + 4 <= datagram.len() {
        if datagram[at] >> 6 != 2 {
            return false;
        }
        let words = u16::from_be_bytes([datagram[at + 2], datagram[at + 3]]) as usize + 1;
        at += 4 * words;
    }
    at == datagram.len()
}

/// What a datagram in the RTP range is, for a failure message.
fn describe(datagram: &[u8]) -> String {
    let ssrc = |at: usize| {
        datagram
            .get(at..at + 4)
            .map(|b| format!("{:08x}", u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
            .unwrap_or_default()
    };
    if is_rtcp(datagram) {
        format!(
            "RTCP {} B, packet type {}, SSRC {}, {}",
            datagram.len(),
            datagram[1],
            ssrc(4),
            if is_plain_rtcp(datagram) {
                "in the clear"
            } else {
                "SRTCP"
            }
        )
    } else {
        format!("RTP {} B, SSRC {}", datagram.len(), ssrc(8))
    }
}

fn rtcp_since(peer: &Peer, from: usize) -> Vec<&Vec<u8>> {
    peer.written[from..]
        .iter()
        .filter(|datagram| is_rtcp(datagram))
        .collect()
}

/// A connection with a data channel and no media section: for a minute after it is up,
/// neither peer writes a single datagram in the RTP / RTCP range. There is no RTP session, so
/// there are no receiver reports, no SDES and no SSRC to reveal (RFC 3550 section 6; RFC 8834
/// section 4.1). With `use_srtp` on every association (the default) the association has SRTP
/// keys that nothing uses; without it, there are none.
#[test]
fn a_data_channel_only_connection_sends_no_rtcp() -> Result<()> {
    let mut found = vec![];
    for every_association in [true, false] {
        let what = format!("use_srtp on every association: {every_association}");
        let mut world = world(every_association)?;
        world.connect()?;
        world.run_for(Duration::from_secs(60), |_| false);
        world.ping_pong(&what)?;
        for (i, peer) in world.peers.iter().enumerate() {
            let rtp_range: Vec<String> = peer
                .written
                .iter()
                .filter(|datagram| in_rtp_range(datagram))
                .map(|datagram| describe(datagram))
                .collect();
            if !rtp_range.is_empty() {
                found.push(format!(
                    "{what}: peer {i} wrote {} datagrams in the RTP / RTCP range, the first: {:?}",
                    rtp_range.len(),
                    &rtp_range[..rtp_range.len().min(2)]
                ));
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
    Ok(())
}

/// A data-channel-only connection gains an audio section: RTCP starts on both peers, and
/// every RTCP datagram either writes is SRTCP, never RTCP in the clear (RFC 3711 section 3.4;
/// RFC 8827 section 6.5). Without `use_srtp` on the first association a new one is set up for
/// the media (RFC 5764 section 4.1), and no RTCP leaves before it has keys.
#[test]
fn media_added_later_starts_rtcp_and_every_rtcp_packet_is_protected() -> Result<()> {
    for every_association in [true, false] {
        let what = format!("use_srtp on every association: {every_association}");
        let mut world = world(every_association)?;
        world.connect()?;
        world.run_for(Duration::from_secs(10), |_| false);
        let marks = [world.peers[0].written.len(), world.peers[1].written.len()];
        for (i, peer) in world.peers.iter().enumerate() {
            assert!(rtcp_since(peer, 0).is_empty(), "{what}: peer {i}");
        }

        world.peers[0].pc.add_transceiver_from_kind(
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverInit::recvonly()),
        )?;
        world.exchange(0)?;
        world.run(&format!("{what}: RTCP from both peers"), |peers| {
            peers
                .iter()
                .zip(marks)
                .all(|(peer, mark)| !rtcp_since(peer, mark).is_empty())
        })?;
        world.run_for(Duration::from_secs(10), |_| false);
        for (i, peer) in world.peers.iter().enumerate() {
            let sent = rtcp_since(peer, marks[i]);
            assert!(sent.len() >= 3, "{what}: peer {i} sent {} RTCP", sent.len());
            for datagram in sent {
                assert!(
                    !is_plain_rtcp(datagram),
                    "{what}: peer {i}: {}",
                    describe(datagram)
                );
            }
            // DTLS handshake records have content type 22: the last one precedes every RTCP
            // datagram (the association RTCP is keyed from is up before RTCP starts).
            let last_handshake = peer.written.iter().rposition(|d| d.first() == Some(&22));
            let first_rtcp = peer.written.iter().position(|d| is_rtcp(d));
            assert!(
                first_rtcp > last_handshake,
                "{what}: peer {i}: RTCP at {first_rtcp:?}, the last handshake record at \
                 {last_handshake:?}"
            );
        }
        world.ping_pong(&what)?;
    }
    Ok(())
}

/// The only media section is removed (stopped, and the offer rejects it): each peer's RTCP
/// session leaves with one BYE packet (RFC 3550 section 6.6) and sends nothing in the RTP /
/// RTCP range for the minute after. A media section added again starts RTCP again.
#[test]
fn removing_all_media_ends_rtcp_with_one_goodbye_and_adding_media_starts_it_again() -> Result<()> {
    let mut world = world(true)?;
    world.connect()?;
    let transceiver = world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, Some(RTCRtpTransceiverInit::recvonly()))?;
    world.exchange(0)?;
    let marks = [world.peers[0].written.len(), world.peers[1].written.len()];
    world.run("RTCP from both peers", |peers| {
        peers
            .iter()
            .zip(marks)
            .all(|(peer, mark)| rtcp_since(peer, mark).len() >= 2)
    })?;

    let marks = [world.peers[0].written.len(), world.peers[1].written.len()];
    world.peers[0]
        .pc
        .rtp_transceiver(transceiver)
        .expect("the transceiver")
        .stop()?;
    let (offer, _) = world.exchange(0)?;
    assert!(
        offer.lines().any(|line| line.starts_with("m=audio 0 ")),
        "the offer rejects the stopped section:\n{offer}"
    );
    world.run_for(Duration::from_secs(60), |_| false);
    world.ping_pong("after the media section is gone")?;
    for (i, peer) in world.peers.iter().enumerate() {
        let sent: Vec<String> = rtcp_since(peer, marks[i])
            .into_iter()
            .map(|datagram| describe(datagram))
            .collect();
        assert_eq!(
            sent.len(),
            1,
            "peer {i}: one BYE packet and nothing after it: {:?}",
            &sent[..sent.len().min(4)]
        );
        assert!(
            !peer.written[marks[i]..]
                .iter()
                .any(|d| in_rtp_range(d) && !is_rtcp(d)),
            "peer {i}: no RTP"
        );
    }

    let marks = [world.peers[0].written.len(), world.peers[1].written.len()];
    world.peers[1]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, Some(RTCRtpTransceiverInit::recvonly()))?;
    world.exchange(1)?;
    world.run("RTCP from both peers again", |peers| {
        peers
            .iter()
            .zip(marks)
            .all(|(peer, mark)| rtcp_since(peer, mark).len() >= 2)
    })?;
    for (i, peer) in world.peers.iter().enumerate() {
        for datagram in rtcp_since(peer, marks[i]) {
            assert!(!is_plain_rtcp(datagram), "peer {i}: {}", describe(datagram));
        }
    }
    Ok(())
}
