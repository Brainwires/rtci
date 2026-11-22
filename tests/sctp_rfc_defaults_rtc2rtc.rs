//! What a peer connection's SCTP association does by default, between two engines in memory on
//! a virtual clock: user message interleaving (RFC 8260, as RFC 8831 sections 6.1 and 6.6 ask),
//! the zero checksum over DTLS (RFC 9653), the 16 KB message limit without interleaving
//! (RFC 8831 section 6.6) and packets sized for the path (RFC 8831 section 5); each against a
//! peer with the feature turned off, with which the association falls back.
//!
//! What goes on the wire under DTLS (I-DATA or DATA chunks, a zero checksum or a CRC32c, the
//! order two channels are served in) is asserted in the SCTP handler's unit tests, which see
//! the SCTP packets; here the two whole stacks are run against each other.

mod dc_common;

use anyhow::Result;
use dc_common::Pair;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::RTCSctpTransportState;
use rtc::shared::error::Error;

const OFFERER: &str = "127.0.0.1:50010";
const ANSWERER: &str = "127.0.0.1:50011";

/// A pair built from the two setting engines, connected over one channel the offerer opened.
/// Returns the pair and the channel's handle on the offerer and on the answerer.
fn connected(
    offerer: SettingEngineBuilder,
    answerer: SettingEngineBuilder,
) -> Result<(
    Pair,
    rtc::data_channel::RTCDataChannelId,
    rtc::data_channel::RTCDataChannelId,
)> {
    connected_at(OFFERER, offerer, ANSWERER, answerer)
}

fn connected_at(
    offerer_addr: &str,
    offerer: SettingEngineBuilder,
    answerer_addr: &str,
    answerer: SettingEngineBuilder,
) -> Result<(
    Pair,
    rtc::data_channel::RTCDataChannelId,
    rtc::data_channel::RTCDataChannelId,
)> {
    let mut pair = Pair::with_setting_engines(offerer_addr, offerer, answerer_addr, answerer)?;
    let local = pair.open_channel("data")?;
    let remote = *pair
        .answerer
        .opened()
        .last()
        .expect("the answerer's channel");
    for peer in [&pair.offerer, &pair.answerer] {
        assert_eq!(
            peer.pc.sctp().expect("SCTP").state(),
            RTCSctpTransportState::Connected
        );
    }
    Ok((pair, local, remote))
}

fn default() -> SettingEngineBuilder {
    SettingEngineBuilder::new()
}

/// `maxMessageSize` of both peers.
fn max_message_sizes(pair: &Pair) -> (Option<u32>, Option<u32>) {
    (
        pair.offerer.pc.sctp().expect("SCTP").max_message_size(),
        pair.answerer.pc.sctp().expect("SCTP").max_message_size(),
    )
}

/// RFC 8831 section 6.6: "As long as message interleaving is not supported, the sender SHOULD
/// limit the maximum message size to 16 KB". Two engines interleave by default, so the limit
/// between them is the peer's `max-message-size` (64 KiB here) and a message of that size
/// crosses in both directions.
#[test]
fn two_engines_interleave_and_send_messages_up_to_the_negotiated_size() -> Result<()> {
    let (mut pair, local, remote) = connected(default(), default())?;
    assert_eq!(max_message_sizes(&pair), (Some(65536), Some(65536)));
    assert!(pair.deliver(false, local, &vec![1u8; 65536])?);
    assert!(pair.deliver(true, remote, &vec![2u8; 65536])?);
    assert!(pair.deliver(false, local, b"small")?);
    Ok(())
}

/// The same against a peer that does not announce interleaving, whichever side it is: the
/// association is established all the same and uses DATA chunks, `maxMessageSize` is 16384 on
/// both sides (neither interleaves on this association), a message of that size crosses in
/// both directions and a larger one is refused when it is sent.
#[test]
fn without_interleaving_the_association_falls_back_and_messages_are_held_to_16_kb() -> Result<()> {
    let off = || default().with_sctp_message_interleaving(false);
    for (offerer, answerer) in [(default(), off()), (off(), default()), (off(), off())] {
        let (mut pair, local, remote) = connected(offerer, answerer)?;
        assert_eq!(max_message_sizes(&pair), (Some(16384), Some(16384)));
        assert!(pair.deliver(false, local, &vec![1u8; 16384])?);
        assert!(pair.deliver(true, remote, &vec![2u8; 16384])?);

        let now = pair.now;
        for (peer, channel) in [(&mut pair.offerer, local), (&mut pair.answerer, remote)] {
            let refused = peer
                .pc
                .data_channel(channel)
                .expect("the channel")
                .send(now, bytes::BytesMut::from(&vec![3u8; 16385][..]));
            assert_eq!(refused, Err(Error::ErrOutboundPacketTooLarge));
        }
        assert!(
            pair.deliver(false, local, b"after the refusal")?,
            "a refused message leaves the channel usable"
        );
    }
    Ok(())
}

/// What browsers do is a setting: with the limit lifted on the sending side, a message over
/// 16 KB goes to a peer that does not interleave, up to that peer's `max-message-size`.
#[test]
fn the_16_kb_limit_can_be_lifted_for_a_peer_that_does_not_interleave() -> Result<()> {
    let (mut pair, local, remote) = connected(
        default().with_sctp_message_size_limit_without_interleaving(false),
        default().with_sctp_message_interleaving(false),
    )?;
    assert_eq!(
        max_message_sizes(&pair),
        (Some(65536), Some(16384)),
        "the offerer lifted its limit; the answerer keeps the default"
    );
    assert!(pair.deliver(false, local, &vec![1u8; 65536])?);
    assert!(pair.deliver(true, remote, &vec![2u8; 16384])?);
    Ok(())
}

/// RFC 9653 section 5.2: the zero checksum is used only towards a peer that announced it
/// accepts one. Against a peer that does not announce it, whichever side it is, the
/// association is established and data crosses in both directions; a packet with a zero
/// checksum would be dropped by that peer, and one without a CRC32c from it would be dropped
/// here, so nothing would arrive if either side got it wrong.
#[test]
fn a_peer_that_does_not_accept_a_zero_checksum_gets_a_crc32c() -> Result<()> {
    let off = || default().with_sctp_zero_checksum(false);
    for (offerer, answerer) in [(default(), off()), (off(), default()), (off(), off())] {
        let (mut pair, local, remote) = connected(offerer, answerer)?;
        assert!(pair.deliver(false, local, &vec![1u8; 40_000])?);
        assert!(pair.deliver(true, remote, &vec![2u8; 40_000])?);
    }
    Ok(())
}

/// The scheduler is this side's own affair (RFC 8260 section 3: each sender chooses): a peer
/// that sends first come, first served and one that sends by weighted fair queueing exchange
/// data on several channels of different priority, every message arriving on its channel in
/// the order it was sent.
#[test]
fn channels_of_different_priority_deliver_in_order_under_either_scheduler() -> Result<()> {
    use rtc::data_channel::RTCDataChannelInit;

    for weighted in [true, false] {
        let (mut pair, _, _) = connected(
            default().with_sctp_weighted_fair_queueing(weighted),
            default(),
        )?;
        let mut channels = vec![];
        for (label, priority) in [("low", 128u16), ("high", 1024u16)] {
            let before = pair.answerer.opened().len();
            let id = pair
                .offerer
                .pc
                .create_data_channel(
                    label,
                    Some(RTCDataChannelInit {
                        priority,
                        ..Default::default()
                    }),
                )?
                .id();
            assert!(pair.run_until(
                |p| p.offerer.opened().contains(&id) && p.answerer.opened().len() > before
            )?);
            channels.push((id, *pair.answerer.opened().last().expect("opened")));
        }
        let now = pair.now;
        let before = pair.answerer.received.len();
        for n in 0..40u8 {
            for (local, _) in &channels {
                pair.offerer
                    .pc
                    .data_channel(*local)
                    .expect("the channel")
                    .send(now, bytes::BytesMut::from(&vec![n; 2000][..]))?;
            }
        }
        assert!(pair.run_until(|p| p.answerer.received.len() == before + 80)?);
        for (_, remote) in &channels {
            let order: Vec<u8> = pair.answerer.received[before..]
                .iter()
                .filter(|(id, _, _)| id == remote)
                .map(|(_, _, data)| data[0])
                .collect();
            assert_eq!(order, (0..40u8).collect::<Vec<_>>(), "weighted: {weighted}");
        }
    }
    Ok(())
}

/// The largest datagram either peer of a new pair at these addresses writes while a 64 KiB
/// message crosses in each direction.
fn largest_data_datagram(offerer_addr: &str, answerer_addr: &str) -> Result<usize> {
    let (mut pair, local, remote) =
        connected_at(offerer_addr, default(), answerer_addr, default())?;
    largest_datagram_of_a_large_message(&mut pair, local, remote)
}

/// RFC 8831 section 5: "The initial Path MTU at the IP layer SHOULD NOT exceed 1200 bytes for
/// IPv4 and 1280 bytes for IPv6." The association takes its packet size from the selected
/// candidate pair and the DTLS cipher suite, so a full packet of a large message, in its DTLS
/// record, is a UDP payload that fills what 1200 - 20 - 8 bytes leave over IPv4, and
/// 1280 - 40 - 8 over IPv6, to within the three bytes an SCTP packet (a multiple of four
/// bytes long) may fall short. It used to be 1191 + 37 = 1228 bytes on either, which is an
/// IPv4 packet of 1256.
#[test]
fn full_packets_fill_the_initial_path_mtu_of_the_address_family_and_no_more() -> Result<()> {
    for (family, offerer, answerer, path_mtu, ip_header) in [
        ("IPv4", "127.0.0.1:50010", "127.0.0.1:50011", 1200, 20),
        ("IPv6", "[fd00::1]:50010", "[fd00::2]:50011", 1280, 40),
    ] {
        let largest = largest_data_datagram(offerer, answerer)?;
        let limit = path_mtu - ip_header - 8;
        assert!(
            (limit - 3..=limit).contains(&largest),
            "{family}: the largest datagram is {largest} bytes, for a limit of {limit}"
        );
    }
    Ok(())
}

/// The largest datagram either peer writes while a 64 KiB message crosses in each direction
/// of the connected `pair`.
fn largest_datagram_of_a_large_message(
    pair: &mut Pair,
    local: rtc::data_channel::RTCDataChannelId,
    remote: rtc::data_channel::RTCDataChannelId,
) -> Result<usize> {
    pair.offerer.written_sizes.clear();
    pair.answerer.written_sizes.clear();
    assert!(pair.deliver(false, local, &vec![1u8; 65536])?);
    assert!(pair.deliver(true, remote, &vec![2u8; 65536])?);
    Ok(pair
        .offerer
        .written_sizes
        .iter()
        .chain(&pair.answerer.written_sizes)
        .copied()
        .max()
        .unwrap_or(0))
}

/// RFC 8831 section 5: "The ICE/UDP layer can handle IP address changes during a session
/// without needing interaction with the DTLS and SCTP layers. However, SCTP SHOULD be notified
/// when an address change has happened. In this case, SCTP SHOULD retest the Path MTU and
/// reset the congestion state to the initial state." Two connected peers move from IPv4 to
/// IPv6 addresses by an ICE restart: the association, which goes on with its channel open,
/// learns of the new selected pair and sends packets of the size that fits it (an IPv6
/// packet of 1280 bytes, where it was an IPv4 packet of 1200). Nothing used to tell SCTP of a
/// new pair.
#[test]
fn a_move_to_another_candidate_pair_reaches_sctp() -> Result<()> {
    let (mut pair, local, remote) =
        connected_at("127.0.0.1:50010", default(), "127.0.0.1:50011", default())?;
    let over_ipv4 = largest_datagram_of_a_large_message(&mut pair, local, remote)?;
    assert!(
        (1169..=1172).contains(&over_ipv4),
        "over IPv4 the largest datagram is {over_ipv4} bytes"
    );

    pair.offerer.move_to("[fd00::1]:50010".parse()?);
    pair.answerer.move_to("[fd00::2]:50011".parse()?);
    pair.offerer.pc.restart_ice();
    pair.negotiate()?;
    pair.trickle()?;
    // The restart selects the IPv6 pair; until then the session goes on over the old one.
    let mut over_ipv6 = 0;
    for _ in 0..20 {
        pair.run_for(std::time::Duration::from_millis(500))?;
        over_ipv6 = largest_datagram_of_a_large_message(&mut pair, local, remote)?;
        if over_ipv6 > 1172 {
            break;
        }
    }
    assert!(
        (1229..=1232).contains(&over_ipv6),
        "over IPv6 the largest datagram is {over_ipv6} bytes"
    );
    for peer in [&pair.offerer, &pair.answerer] {
        assert_eq!(
            peer.pc.sctp().expect("SCTP").state(),
            RTCSctpTransportState::Connected
        );
        assert!(peer.connected());
    }
    let closed = |peer: &dc_common::Peer| {
        peer.events.iter().any(|event| {
            matches!(
                event,
                rtc::peer_connection::event::RTCDataChannelEvent::OnClose(_)
                    | rtc::peer_connection::event::RTCDataChannelEvent::OnError(_)
            )
        })
    };
    assert!(
        !closed(&pair.offerer) && !closed(&pair.answerer),
        "the channel stayed open: {:?} / {:?}",
        pair.offerer.events,
        pair.answerer.events
    );
    Ok(())
}

/// An SCTP packet budget the application sets is used as it is, on any path.
#[test]
fn a_configured_sctp_mtu_takes_the_place_of_the_paths() -> Result<()> {
    let (mut pair, local, _) = connected(default().with_sctp_mtu(900), default())?;
    pair.offerer.written_sizes.clear();
    assert!(pair.deliver(false, local, &vec![1u8; 65536])?);
    // 900 bytes of SCTP in a DTLS record: 13 bytes of header, 8 of explicit nonce, 16 of tag.
    assert_eq!(pair.offerer.written_sizes.iter().copied().max(), Some(937));
    Ok(())
}
