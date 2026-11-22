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
use dtls::cipher_suite::{CipherSuite, CipherSuiteId, cipher_suite_for_id};
use dtls::record_layer::record_layer_header::RECORD_LAYER_HEADER_SIZE;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::transport::RTCSctpTransportState;
use rtc::shared::error::Error;
use rtc::statistics::StatsSelector;

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

/// A setting engine to build a peer from.
type Settings = fn() -> SettingEngineBuilder;

/// The DTLS versions the tests run under: the default, with which two engines negotiate
/// DTLS 1.3, and a cipher suite list without the TLS 1.3 suites, which gives DTLS 1.2.
fn dtls_versions() -> [(&'static str, Settings); 2] {
    [
        ("DTLS 1.3", default),
        ("DTLS 1.2", || {
            default().with_dtls_cipher_suites(vec![
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            ])
        }),
    ]
}

/// What each DTLS record the offerer sends adds to its content, from the version and cipher
/// suite the connection reports in its statistics (`tlsVersion`, `dtlsCipher`): the record
/// header of that version and what `rtc-dtls` says the suite adds to a record
/// (`CipherSuite::record_expansion`). Neither side asks for a connection id.
fn negotiated_record_overhead(pair: &mut Pair) -> usize {
    let now = pair.now;
    let stats = pair.offerer.pc.get_stats(now, StatsSelector::None);
    let transport = stats.transport().expect("a transport");
    let header = match transport.tls_version.as_str() {
        // RFC 9147 section 4: the unified header with a 16-bit sequence number and the
        // length, and no connection id: 1 + 2 + 2 bytes.
        "FEFC" => 5,
        // RFC 6347 section 4.1.
        "FEFD" => RECORD_LAYER_HEADER_SIZE,
        other => panic!("tlsVersion {other}"),
    };
    let suite = (0..=u16::MAX)
        .map(CipherSuiteId::from)
        .find(|id| id.to_string() == transport.dtls_cipher)
        .unwrap_or_else(|| panic!("dtlsCipher {}", transport.dtls_cipher));
    let suite: Box<dyn CipherSuite> = cipher_suite_for_id(suite).expect("a suite rtc-dtls has");
    header + suite.record_expansion()
}

/// The largest datagram that carries a full SCTP packet on a path whose UDP payload is at
/// most `limit` bytes, under DTLS records that add `overhead` bytes: the largest SCTP packet
/// (a multiple of four bytes long) that fits, in its record.
fn full_datagram(limit: usize, overhead: usize) -> usize {
    let packet = limit - overhead;
    packet - packet % 4 + overhead
}

/// RFC 8831 section 5: "The initial Path MTU at the IP layer SHOULD NOT exceed 1200 bytes for
/// IPv4 and 1280 bytes for IPv6." The association takes its packet size from the selected
/// candidate pair and the DTLS association's record overhead (RFC 8261 section 5), so a full
/// packet of a large message, in its DTLS record, is a UDP payload that fills what
/// 1200 - 20 - 8 bytes leave over IPv4, and 1280 - 40 - 8 over IPv6, to within the three
/// bytes an SCTP packet (a multiple of four bytes long) may fall short, under DTLS 1.3 and
/// DTLS 1.2 alike. It used to be 1191 + 37 = 1228 bytes on either, which is an IPv4 packet of
/// 1256; with the DTLS 1.2 record header counted for DTLS 1.3 records it was 8 bytes short.
#[test]
fn full_packets_fill_the_initial_path_mtu_of_the_address_family_and_no_more() -> Result<()> {
    for (dtls, settings) in dtls_versions() {
        for (family, offerer, answerer, path_mtu, ip_header) in [
            ("IPv4", "127.0.0.1:50010", "127.0.0.1:50011", 1200, 20),
            ("IPv6", "[fd00::1]:50010", "[fd00::2]:50011", 1280, 40),
        ] {
            let (mut pair, local, remote) =
                connected_at(offerer, settings(), answerer, settings())?;
            let overhead = negotiated_record_overhead(&mut pair);
            let largest = largest_datagram_of_a_large_message(&mut pair, local, remote)?;
            let limit = path_mtu - ip_header - 8;
            assert_eq!(
                largest,
                full_datagram(limit, overhead),
                "{dtls}, {family}: records of {overhead} bytes of overhead, a limit of {limit}"
            );
        }
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

/// The address families the datagrams `peer` wrote since its record was last cleared went
/// to: (to an IPv4 address, to an IPv6 address).
fn families_written_to(peer: &dc_common::Peer) -> (bool, bool) {
    (
        peer.written_to.iter().any(|to| to.is_ipv4()),
        peer.written_to.iter().any(|to| to.is_ipv6()),
    )
}

/// RFC 8831 section 5: "The ICE/UDP layer can handle IP address changes during a session
/// without needing interaction with the DTLS and SCTP layers. However, SCTP SHOULD be notified
/// when an address change has happened. In this case, SCTP SHOULD retest the Path MTU and
/// reset the congestion state to the initial state." Two connected peers move from IPv4 to
/// IPv6 addresses by an ICE restart that discards the old local candidates, so the new
/// generation has IPv6 candidates only and the pair it selects is an IPv6 pair. The
/// association, which goes on with its channel open, learns of the new selected pair and
/// sends packets of the size that fits it (an IPv6 packet of 1280 bytes, where it was an
/// IPv4 packet of 1200: RFC 9260 section 7.2 counts congestion control in packets of the
/// path's PMTU, and RFC 8261 section 5 has the SCTP packet fit the DTLS record the path
/// carries). Nothing used to tell SCTP of a new pair.
///
/// RFC 8841 section 12.2: "the SCTP association MUST NOT be affected by such a change in the
/// candidate pair. The DTLS and SCTP handshakes MUST NOT be repeated": no DTLS handshake
/// record leaves either peer after the move, and the channel opened before it is the only one
/// and stays open.
#[test]
fn a_move_to_another_candidate_pair_reaches_sctp() -> Result<()> {
    let settings = || default().with_discard_local_candidates_during_ice_restart(true);
    let (mut pair, local, remote) =
        connected_at("127.0.0.1:50010", settings(), "127.0.0.1:50011", settings())?;
    pair.offerer.written_to.clear();
    pair.answerer.written_to.clear();
    let overhead = negotiated_record_overhead(&mut pair);
    let over_ipv4 = largest_datagram_of_a_large_message(&mut pair, local, remote)?;
    assert_eq!(
        over_ipv4,
        full_datagram(1200 - 20 - 8, overhead),
        "over IPv4"
    );
    assert_eq!(families_written_to(&pair.offerer), (true, false));

    pair.offerer.written_first_bytes.clear();
    pair.answerer.written_first_bytes.clear();
    pair.offerer.move_to("[fd00::1]:50010".parse()?);
    pair.answerer.move_to("[fd00::2]:50011".parse()?);
    pair.offerer.pc.restart_ice();
    pair.negotiate()?;
    pair.trickle()?;
    // The restart selects the IPv6 pair; until then the session goes on over the old one.
    let mut over_ipv6 = 0;
    for _ in 0..20 {
        pair.run_for(std::time::Duration::from_millis(500))?;
        pair.offerer.written_to.clear();
        pair.answerer.written_to.clear();
        over_ipv6 = largest_datagram_of_a_large_message(&mut pair, local, remote)?;
        if families_written_to(&pair.offerer) == (false, true)
            && families_written_to(&pair.answerer) == (false, true)
        {
            break;
        }
    }
    for peer in [&pair.offerer, &pair.answerer] {
        assert_eq!(
            families_written_to(peer),
            (false, true),
            "the restart moved the session to the IPv6 pair"
        );
    }
    assert_eq!(
        over_ipv6,
        full_datagram(1280 - 40 - 8, overhead),
        "over IPv6"
    );
    for peer in [&pair.offerer, &pair.answerer] {
        assert_eq!(
            peer.pc.sctp().expect("SCTP").state(),
            RTCSctpTransportState::Connected
        );
        assert!(peer.connected());
    }
    // RFC 7983 section 7: a DTLS handshake record has content type 22.
    for peer in [&pair.offerer, &pair.answerer] {
        assert!(
            !peer.written_first_bytes.contains(&22),
            "no DTLS handshake after the move"
        );
        assert_eq!(peer.opened().len(), 1, "no channel opened again");
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

/// An SCTP packet budget the application sets is used as it is, on any path and under either
/// DTLS version: 900 bytes of SCTP and the record around them.
#[test]
fn a_configured_sctp_mtu_takes_the_place_of_the_paths() -> Result<()> {
    for (dtls, settings) in dtls_versions() {
        let (mut pair, local, _) = connected(settings().with_sctp_mtu(900), settings())?;
        let overhead = negotiated_record_overhead(&mut pair);
        pair.offerer.written_sizes.clear();
        assert!(pair.deliver(false, local, &vec![1u8; 65536])?);
        assert_eq!(
            pair.offerer.written_sizes.iter().copied().max(),
            Some(900 + overhead),
            "{dtls}"
        );
    }
    Ok(())
}
