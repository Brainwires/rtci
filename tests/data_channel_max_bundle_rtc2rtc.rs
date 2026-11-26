//! A data channel beside audio and video under the `max-bundle` bundle policy, between two
//! engines in memory on a virtual clock.
//!
//! RFC 9429 section 5.2.1: with `must-bundle` (W3C `max-bundle`) every m= section of the
//! initial offer but the first gets "an 'a=bundle-only' line", and section 7.2 of the same
//! document shows the data section of such an offer as `m=application 0 ...` with
//! `a=bundle-only`. RFC 9143 section 7.2: a zero port with `a=bundle-only` asks the answerer to
//! accept the section inside the BUNDLE group; "If the offerer assigns a zero port value to a
//! bundled 'm=' section but does not include an SDP 'bundle-only' attribute in the 'm='
//! section, it is an indication that the offerer wants to disable the 'm=' section"; section 13
//! updates RFC 3264 so that a zero port is not "not used" when an extension says otherwise.
//! In an answer a zero port is a rejection (RFC 9143 section 7.3.3), and an answer has no
//! `a=bundle-only` (RFC 9429 section 5.3.1).
//!
//! 0.2.0 read the zero port of the data section alone as a rejection: under `max-bundle` with
//! media, both peers took the bundle-only data section for a rejected one, no SCTP association
//! was started, and the channel failed with "signalling closed the SCTP association before the
//! channel opened" (WPT `webrtc/RTCPeerConnection-createDataChannel.html`, "addTrack, then
//! creating datachannel, should negotiate properly when max-bundle is used"). The data section
//! alone (the first section, so not bundle-only) worked.

mod dc_common;

use anyhow::{Result, ensure};
use dc_common::{Pair, Peer};
use rtci::data_channel::RTCDataChannelId;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCBundlePolicy, RTCConfigurationBuilder};
use rtci::peer_connection::transport::{RTCDtlsRole, RTCSctpTransportState};
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::time::Instant;

/// A peer at `addr` under `policy` (the default, `balanced`, when `None`), taking
/// `answering_role` when it answers.
fn peer(
    addr: &str,
    policy: Option<RTCBundlePolicy>,
    answering_role: RTCDtlsRole,
    now: Instant,
) -> Result<Peer> {
    let mut configuration = RTCConfigurationBuilder::new();
    if let Some(policy) = policy {
        configuration = configuration.with_bundle_policy(policy);
    }
    Peer::with_configuration(
        addr.parse()?,
        SettingEngineBuilder::new().with_answering_dtls_role(answering_role),
        configuration.build(),
        now,
    )
}

/// A pair whose offerer and answerer follow the given bundle policies.
fn new_pair(
    offerer: Option<RTCBundlePolicy>,
    answerer: Option<RTCBundlePolicy>,
    answerer_role: RTCDtlsRole,
) -> Result<Pair> {
    let now = Instant::now();
    let offerer_role = match answerer_role {
        RTCDtlsRole::Client => RTCDtlsRole::Server,
        _ => RTCDtlsRole::Client,
    };
    Ok(Pair::of(
        peer("127.0.0.1:50110", offerer, offerer_role, now)?,
        peer("127.0.0.1:50111", answerer, answerer_role, now)?,
        now,
    ))
}

/// What the offerer adds before its first offer.
#[derive(Debug, Clone, Copy)]
enum Order {
    /// An audio and a video transceiver, then the data channel (the WPT case).
    MediaThenData,
    /// The data channel, then an audio and a video transceiver.
    DataThenMedia,
    /// The data channel alone: its section is the first, so it is not bundle-only.
    DataOnly,
}

fn add_media(peer: &mut Peer) -> Result<()> {
    peer.pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    peer.pc
        .add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    Ok(())
}

/// Adds what `order` says to the offerer; returns the offerer's channel.
fn prepare(pair: &mut Pair, order: Order) -> Result<RTCDataChannelId> {
    let peer = &mut pair.offerer;
    Ok(match order {
        Order::MediaThenData => {
            add_media(peer)?;
            peer.pc.create_data_channel("data", None)?.id()
        }
        Order::DataThenMedia => {
            let id = peer.pc.create_data_channel("data", None)?.id();
            add_media(peer)?;
            id
        }
        Order::DataOnly => peer.pc.create_data_channel("data", None)?.id(),
    })
}

/// The m= sections of `sdp`, each as its lines (the m= line first).
fn sections(sdp: &str) -> Vec<Vec<&str>> {
    let mut out: Vec<Vec<&str>> = Vec::new();
    for line in sdp.lines().map(str::trim_end) {
        if line.starts_with("m=") {
            out.push(vec![line]);
        } else if let Some(last) = out.last_mut() {
            last.push(line);
        }
    }
    out
}

/// The data section of `sdp`.
fn data_section(sdp: &str) -> Vec<&str> {
    sections(sdp)
        .into_iter()
        .find(|s| s[0].starts_with("m=application "))
        .expect("a data section")
}

/// The m= line's port of a section.
fn port<'a>(section: &[&'a str]) -> &'a str {
    section[0].split(' ').nth(1).expect("a port")
}

/// Runs the pair until the offerer's channel is open on both sides, then sends a message each
/// way. `what` names the case in the failure messages.
fn opens_and_carries(pair: &mut Pair, channel: RTCDataChannelId, what: &str) -> Result<()> {
    let opened = pair
        .run_until(|p| p.offerer.opened().contains(&channel) && !p.answerer.opened().is_empty())?;
    ensure!(
        opened,
        "{what}: the channel never opened; offerer events {:?}, answerer events {:?}",
        pair.offerer.events,
        pair.answerer.events
    );
    let remote = pair.answerer.opened()[0];
    ensure!(
        pair.deliver(false, channel, b"offerer to answerer")?,
        "{what}: the message to the answerer did not arrive"
    );
    ensure!(
        pair.deliver(true, remote, b"answerer to offerer")?,
        "{what}: the message to the offerer did not arrive"
    );
    for (side, peer) in [("offerer", &pair.offerer), ("answerer", &pair.answerer)] {
        let sctp = peer.pc.sctp();
        ensure!(sctp.is_some(), "{what}: the {side} has no SCTP transport");
        ensure!(
            sctp.map(|s| s.state()) == Some(RTCSctpTransportState::Connected),
            "{what}: the {side}'s SCTP transport is not connected"
        );
    }
    Ok(())
}

/// RFC 9429 sections 5.2.1 and 7.2, RFC 9143 sections 7.2 and 13: the offerer under
/// `max-bundle`, with audio and video added before or after the data channel, offers the data
/// section `m=application 0` with `a=bundle-only` (and its `a=sctp-port`, which is not a BUNDLE
/// attribute: RFC 8841 section 5.3, category CAUTION); a default answerer accepts it in the
/// group, with the BUNDLE port and no `a=bundle-only`; both start the association, the channel
/// opens and carries a message each way. The data channel alone (its section is the first, so
/// it keeps a port) is the control. W3C webrtc-pc 4.4.1.6: the offer, which describes an
/// association, gives the offerer an `RTCSctpTransport` once it is applied.
#[test]
fn a_bundle_only_data_section_is_accepted_and_the_channel_opens() -> Result<()> {
    for order in [Order::MediaThenData, Order::DataThenMedia, Order::DataOnly] {
        for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
            let what = format!("{order:?}, answerer {answerer_role}");
            let mut pair = new_pair(Some(RTCBundlePolicy::MaxBundle), None, answerer_role)?;
            let channel = prepare(&mut pair, order)?;

            let now = pair.now;
            let offer = pair.offerer.pc.create_offer(None)?;
            let data = data_section(&offer.sdp);
            match order {
                Order::DataOnly => {
                    ensure!(port(&data) != "0", "{what}: the only section keeps a port");
                    ensure!(!data.contains(&"a=bundle-only"), "{what}:\n{}", offer.sdp);
                }
                _ => {
                    ensure!(
                        sections(&offer.sdp).len() == 3
                            && sections(&offer.sdp)
                                .last()
                                .is_some_and(|s| s[0].starts_with("m=application ")),
                        "{what}: the data section is the last of three (RFC 9429 5.2.1, \"Lastly\"):\n{}",
                        offer.sdp
                    );
                    ensure!(
                        data[0] == "m=application 0 UDP/DTLS/SCTP webrtc-datachannel",
                        "{what}: the data section is bundle-only, port zero:\n{}",
                        offer.sdp
                    );
                    ensure!(data.contains(&"a=bundle-only"), "{what}:\n{}", offer.sdp);
                    ensure!(
                        data.iter().any(|l| l.starts_with("a=sctp-port:")),
                        "{what}: a=sctp-port stays in the bundle-only section:\n{}",
                        offer.sdp
                    );
                }
            }
            pair.offerer.pc.set_local_description(now, offer.clone())?;
            ensure!(
                pair.offerer.pc.sctp().is_some(),
                "{what}: an offer that describes an association gives the offerer its \
                 RTCSctpTransport (W3C webrtc-pc 4.4.1.6)"
            );
            pair.answerer
                .pc
                .set_remote_description(now, offer.clone())?;
            ensure!(
                pair.answerer.pc.sctp().is_some(),
                "{what}: the remote offer describes an association (W3C webrtc-pc 4.4.1.6)"
            );
            let answer = pair.answerer.pc.create_answer(None)?;
            let answered = data_section(&answer.sdp);
            ensure!(
                port(&answered) != "0" && !answered.contains(&"a=bundle-only"),
                "{what}: the answer accepts the data section, without a=bundle-only:\n{}",
                answer.sdp
            );
            pair.answerer
                .pc
                .set_local_description(now, answer.clone())?;
            pair.offerer.pc.set_remote_description(now, answer)?;

            opens_and_carries(&mut pair, channel, &what)?;
        }
    }
    Ok(())
}

/// The answerer under `max-bundle` too: once with an offerer under `max-bundle` (both read a
/// bundle-only data section), once with a default (`balanced`) offerer, whose data section is
/// the first of its type and has a port of its own. The channel opens either way.
#[test]
fn an_answerer_under_max_bundle_opens_the_channel() -> Result<()> {
    for offerer_policy in [Some(RTCBundlePolicy::MaxBundle), None] {
        for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
            let what = format!("offerer {offerer_policy:?}, answerer {answerer_role}");
            let mut pair = new_pair(
                offerer_policy,
                Some(RTCBundlePolicy::MaxBundle),
                answerer_role,
            )?;
            let channel = prepare(&mut pair, Order::MediaThenData)?;
            let (offer, answer) = pair.negotiate()?;
            if offerer_policy.is_some() {
                ensure!(
                    data_section(&offer.sdp).contains(&"a=bundle-only"),
                    "{what}:\n{}",
                    offer.sdp
                );
            }
            ensure!(
                port(&data_section(&answer.sdp)) != "0",
                "{what}: the data section is accepted:\n{}",
                answer.sdp
            );
            opens_and_carries(&mut pair, channel, &what)?;
        }
    }
    Ok(())
}

/// After the channel is open, later offers (RFC 9429 section 5.2.2: no `a=bundle-only` in a
/// subsequent offer, the data section has the BUNDLE port) from either side, one of them
/// adding a transceiver, keep the association: the channel stays open, carries messages, and a
/// second channel opens on the same association.
#[test]
fn later_offers_keep_the_association() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let what = format!("answerer {answerer_role}");
        let mut pair = new_pair(Some(RTCBundlePolicy::MaxBundle), None, answerer_role)?;
        let channel = prepare(&mut pair, Order::MediaThenData)?;
        pair.negotiate()?;
        opens_and_carries(&mut pair, channel, &what)?;
        let remote = pair.answerer.opened()[0];
        let port_before = pair
            .offerer
            .pc
            .local_description()
            .map(|d| {
                data_section(&d.sdp)
                    .iter()
                    .find_map(|l| l.strip_prefix("a=sctp-port:"))
                    .map(str::to_owned)
            })
            .unwrap_or_default();

        // A later offer from the offerer, with one more transceiver.
        pair.offerer
            .pc
            .add_transceiver_from_kind(RtpCodecKind::Video, None)?;
        let (offer, answer) = pair.negotiate()?;
        for sdp in [&offer.sdp, &answer.sdp] {
            let data = data_section(sdp);
            ensure!(
                port(&data) != "0" && !data.contains(&"a=bundle-only"),
                "{what}: a later offer or answer keeps the data section live:\n{sdp}"
            );
            ensure!(
                data.iter()
                    .find_map(|l| l.strip_prefix("a=sctp-port:"))
                    .map(str::to_owned)
                    == port_before,
                "{what}: the same a=sctp-port:\n{sdp}"
            );
        }
        ensure!(
            pair.deliver(false, channel, b"after the later offer")?,
            "{what}: the channel stopped carrying messages after a later offer"
        );

        // And one from the answerer.
        pair.exchange_with(true, str::to_owned, str::to_owned)?;
        ensure!(
            pair.deliver(true, remote, b"after the answerer's offer")?,
            "{what}: the channel stopped carrying messages after the answerer's offer"
        );
        ensure!(
            !pair.offerer.closed(channel) && !pair.answerer.closed(remote),
            "{what}: the channel closed: {:?} / {:?}",
            pair.offerer.events,
            pair.answerer.events
        );
        let second = pair.open_channel("second")?;
        ensure!(
            pair.deliver(false, second, b"on the same association")?,
            "{what}: the second channel carries nothing"
        );
    }
    Ok(())
}

/// The genuine rejection is still one: an answer that gives the data section port zero, with
/// no `a=bundle-only` (RFC 9143 section 7.3.3: port zero, the tag out of the group, no
/// bundle-only), to the bundle-only data section of a `max-bundle` offer. The offerer starts
/// no association (RFC 8841 section 10.4: "the offerer MUST NOT establish an SCTP
/// association"), its channel closes and it has no `RTCSctpTransport`; the media session
/// connects.
#[test]
fn an_answer_that_rejects_the_data_section_still_closes_the_channel() -> Result<()> {
    for answerer_role in [RTCDtlsRole::Client, RTCDtlsRole::Server] {
        let what = format!("answerer {answerer_role}");
        let mut pair = new_pair(Some(RTCBundlePolicy::MaxBundle), None, answerer_role)?;
        let channel = prepare(&mut pair, Order::MediaThenData)?;
        // The answerer, which accepted the section, still sends its INIT.
        pair.offerer.tolerate_read_errors = true;
        let reject = |sdp: &str| -> String {
            let mid = data_section(sdp)
                .iter()
                .find_map(|l| l.strip_prefix("a=mid:"))
                .expect("a=mid")
                .to_owned();
            let mut out = String::new();
            for line in sdp.split_inclusive('\n') {
                if let Some(rest) = line.strip_prefix("m=application ") {
                    let after_port = rest.split_once(' ').map_or("", |(_, r)| r);
                    out.push_str(&format!("m=application 0 {after_port}"));
                } else if let Some(tags) = line.trim_end().strip_prefix("a=group:BUNDLE ") {
                    let kept: Vec<&str> = tags.split(' ').filter(|t| *t != mid).collect();
                    out.push_str(&format!("a=group:BUNDLE {}\r\n", kept.join(" ")));
                } else {
                    out.push_str(line);
                }
            }
            out
        };
        let (offer, answer) = pair.exchange_with(false, str::to_owned, reject)?;
        ensure!(
            data_section(&offer).contains(&"a=bundle-only"),
            "{what}:\n{offer}"
        );
        let received = reject(&answer);
        ensure!(
            port(&data_section(&received)) == "0"
                && !data_section(&received).contains(&"a=bundle-only"),
            "{what}: the munged answer rejects the data section:\n{received}"
        );
        ensure!(
            pair.run_until(|p| p.offerer.closed(channel) && p.offerer.connected())?,
            "{what}: the offerer's channel outlived the rejection: {:?}, states {:?}",
            pair.offerer.events,
            pair.offerer.connection_states
        );
        ensure!(
            !pair.offerer.opened().contains(&channel),
            "{what}: the channel opened on a rejected data section"
        );
        ensure!(
            pair.offerer.pc.sctp().is_none(),
            "{what}: a rejected data section leaves the offerer no RTCSctpTransport"
        );
    }
    Ok(())
}
