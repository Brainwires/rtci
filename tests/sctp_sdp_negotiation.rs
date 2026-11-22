//! RFC 8841 (SDP offer/answer for SCTP over DTLS): what the data channel section of an offer
//! and of an answer says, and what each side does with the other's. Signalling only: no
//! transport is started.

mod jsep_common;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer, media_sections, port_of};
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelState};
use rtc::peer_connection::configuration::setting_engine::{
    SctpMaxMessageSize, SettingEngineBuilder,
};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use std::time::Instant;

/// A remote offer with one data channel section: `m_line`, the transport lines, then
/// `attributes`.
fn data_offer(m_line: &str, attributes: &str) -> RTCSessionDescription {
    let sdp = format!("{SESSION}a=group:BUNDLE 0\n{m_line}\n{TRANSPORT}a=mid:0\n{attributes}");
    RTCSessionDescription::offer(crlf(&sdp)).expect("an offer")
}

const UDP_DATA: &str = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel";

/// Applies `offer` to a new peer and returns the peer with the answer it made and applied.
fn answer_to(
    offer: RTCSessionDescription,
) -> Result<(RTCPeerConnection, String), Box<dyn std::error::Error>> {
    answer_from(default_peer()?, offer)
}

/// Applies `offer` to `pc` and returns it with the answer it made and applied.
fn answer_from(
    mut pc: RTCPeerConnection,
    offer: RTCSessionDescription,
) -> Result<(RTCPeerConnection, String), Box<dyn std::error::Error>> {
    let now = Instant::now();
    pc.set_remote_description(now, offer)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer.clone())?;
    Ok((pc, answer.sdp))
}

/// The lines of the data section of `sdp` (the first `m=application` section).
fn data_section(sdp: &str) -> Vec<String> {
    media_sections(sdp)
        .into_iter()
        .find(|section| section[0].starts_with("m=application"))
        .expect("a data section")
}

fn attribute<'a>(section: &'a [String], name: &str) -> Option<&'a str> {
    let prefix = format!("a={name}:");
    section.iter().find_map(|line| line.strip_prefix(&prefix))
}

fn channel_events(pc: &mut RTCPeerConnection) -> Vec<RTCDataChannelEvent> {
    let mut events = vec![];
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnDataChannel(event) = event {
            events.push(event);
        }
    }
    events
}

/// `sdp` with the first line starting with `from` replaced by `to`.
fn with_line(sdp: &str, from: &str, to: &str) -> String {
    let mut replaced = false;
    let lines: Vec<String> = sdp
        .lines()
        .map(|line| {
            if !replaced && line.starts_with(from) {
                replaced = true;
                to.to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect();
    assert!(replaced, "no line starts with {from:?} in:\n{sdp}");
    crlf(&(lines.join("\n") + "\n"))
}

/// An offerer with one data channel, its offer applied locally, and the answer a second peer
/// made to it. The answer is not applied: the tests change it first.
fn offered() -> Result<(RTCPeerConnection, RTCDataChannelId, String), Box<dyn std::error::Error>> {
    let mut offerer = default_peer()?;
    let channel = offerer.create_data_channel("data", None)?.id();
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    let mut answerer = default_peer()?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    Ok((offerer, channel, answer.sdp))
}

/// RFC 8841 sections 10.2 and 10.3: the offer and the answer each carry `a=sctp-port`, and
/// may carry `a=max-message-size`; sections 5.2 and 6.2: neither value has leading zeroes.
#[test]
fn the_offer_and_the_answer_carry_sctp_port_and_max_message_size() -> TestResult {
    let mut offerer = default_peer()?;
    offerer.create_data_channel("data", None)?;
    let mut answerer = default_peer()?;
    let (offer, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    for (what, sdp) in [("offer", &offer), ("answer", &answer)] {
        let section = data_section(sdp);
        assert_eq!(
            section[0], UDP_DATA,
            "{what}: one fmt, the registered one, over UDP/DTLS/SCTP"
        );
        assert_eq!(attribute(&section, "sctp-port"), Some("5000"), "{what}");
        assert_eq!(
            attribute(&section, "max-message-size"),
            Some("65536"),
            "{what}: the default limit of this endpoint"
        );
        assert!(attribute(&section, "setup").is_some(), "{what}: a=setup");
    }
    assert!(offerer.sctp().is_some());
    assert!(answerer.sctp().is_some());
    Ok(())
}

/// RFC 8841 section 5.1: "if the attribute is not present, the associated 'm=' line MUST be
/// considered invalid." The description is refused and nothing of it applied; it used to be
/// taken, with port 5000 assumed.
#[test]
fn a_data_section_without_a_valid_sctp_port_is_refused() -> TestResult {
    for attributes in [
        "a=max-message-size:262144\n",
        "a=sctp-port:70000\n",
        "a=sctp-port:+5000\n",
        "a=sctp-port:\n",
        "a=sctpmap:5000 webrtc-datachannel 1024\n",
    ] {
        let mut pc = default_peer()?;
        assert_eq!(
            pc.set_remote_description(Instant::now(), data_offer(UDP_DATA, attributes))
                .err(),
            Some(Error::ErrSDPSctpPortInvalid),
            "{attributes:?}"
        );
        assert!(pc.remote_description().is_none());
        assert!(pc.sctp().is_none());
    }

    // An answer is held to the same rule.
    let (mut offerer, _channel, answer) = offered()?;
    let without = crlf(
        &answer
            .lines()
            .filter(|line| !line.starts_with("a=sctp-port:"))
            .collect::<Vec<_>>()
            .join("\n"),
    ) + "\r\n";
    assert_eq!(
        offerer
            .set_remote_description(Instant::now(), RTCSessionDescription::answer(without)?)
            .err(),
        Some(Error::ErrSDPSctpPortInvalid)
    );
    assert!(offerer.sctp().is_none());
    Ok(())
}

/// RFC 8841 section 10.3: "If the answerer does not accept the 'm=' line in the offer, it
/// MUST assign a zero port value to the corresponding 'm=' line in the answer ... In
/// addition, the answerer MUST NOT initiate the establishment of ... a DTLS association
/// associated with the 'm=' line", nor of an SCTP one. A data section the offer already
/// rejects stays rejected, and used to start the SCTP transport all the same.
#[test]
fn a_rejected_data_section_in_the_offer_starts_no_sctp() -> TestResult {
    let sdp = format!(
        "{SESSION}a=group:BUNDLE 0\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=recvonly\na=rtpmap:96 VP8/90000\n\
         m=application 0 UDP/DTLS/SCTP webrtc-datachannel\nc=IN IP4 0.0.0.0\na=mid:1\n"
    );
    let (pc, answer) = answer_to(RTCSessionDescription::offer(crlf(&sdp))?)?;
    let section = data_section(&answer);
    assert_eq!(port_of(&section), 0, "{}", section[0]);
    assert!(
        pc.sctp().is_none(),
        "no SCTP transport for a rejected section"
    );
    Ok(())
}

/// RFC 8841 section 10.4: "If the 'm=' line in the answer contains a zero port value, the
/// offerer MUST NOT initiate the establishment of ... an SCTP association associated with the
/// 'm=' line." The data channels created for it can never open: they fail and close. The
/// SCTP transport used to start and the channels stayed `connecting` for good.
#[test]
fn an_answer_that_rejects_the_data_section_starts_no_sctp_and_closes_the_channels() -> TestResult {
    let (mut offerer, channel, answer) = offered()?;
    let rejected = with_line(
        &answer,
        "m=application",
        "m=application 0 UDP/DTLS/SCTP webrtc-datachannel",
    );
    // A rejected section is in no BUNDLE group (RFC 9143 section 7.3.3): an answer that
    // kept it there is refused as a whole.
    let rejected = rejected
        .split("\r\n")
        .filter(|line| !line.starts_with("a=group:BUNDLE"))
        .collect::<Vec<_>>()
        .join("\r\n");
    offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(rejected)?)?;
    assert!(offerer.sctp().is_none());
    assert_eq!(
        channel_events(&mut offerer),
        vec![
            RTCDataChannelEvent::OnError(channel),
            RTCDataChannelEvent::OnClose(channel),
        ]
    );
    assert!(offerer.data_channel(channel).is_none());
    Ok(())
}

/// RFC 8841 section 10.4: "If the SDP 'sctp-port' attribute in the answer contains an
/// attribute value of zero, the offerer MUST NOT establish an SCTP association." Port 0 used
/// to become the destination port of the INIT.
#[test]
fn an_answer_with_sctp_port_zero_establishes_no_association() -> TestResult {
    let (mut offerer, channel, answer) = offered()?;
    let zero = with_line(&answer, "a=sctp-port:", "a=sctp-port:0");
    offerer.set_remote_description(Instant::now(), RTCSessionDescription::answer(zero)?)?;
    assert!(offerer.sctp().is_none());
    assert_eq!(
        channel_events(&mut offerer),
        vec![
            RTCDataChannelEvent::OnError(channel),
            RTCDataChannelEvent::OnClose(channel),
        ]
    );
    Ok(())
}

/// RFC 8841 section 10.3: "If the offer contained a zero SCTP port value ... the answerer
/// MUST also associate a zero SCTP port value", and "If the SDP 'sctp-port' attribute in the
/// answer contains an attribute value of zero, the answerer MUST NOT establish an SCTP
/// association." The section itself is accepted: DTLS is not affected.
#[test]
fn an_offer_with_sctp_port_zero_is_answered_with_zero() -> TestResult {
    let (pc, answer) = answer_to(data_offer(UDP_DATA, "a=sctp-port:0\n"))?;
    let section = data_section(&answer);
    assert_eq!(section[0], UDP_DATA, "the section is accepted");
    assert_eq!(attribute(&section, "sctp-port"), Some("0"));
    assert!(pc.sctp().is_none());
    Ok(())
}

/// RFC 8841 section 10.3: the answer's m= line has "an 'm=' line proto value identical to the
/// value in the offer". `TCP/DTLS/SCTP` (section 4.2: the same association over a TCP
/// candidate) used to be answered with `UDP/DTLS/SCTP`.
#[test]
fn the_answer_repeats_the_proto_of_the_offer() -> TestResult {
    for m_line in [UDP_DATA, "m=application 9 TCP/DTLS/SCTP webrtc-datachannel"] {
        let (pc, answer) = answer_to(data_offer(m_line, "a=sctp-port:5000\n"))?;
        assert_eq!(data_section(&answer)[0], m_line);
        assert!(pc.sctp().is_some(), "{m_line}");
    }

    // Rejected already in the offer: the rejection repeats the line too.
    let rejected = "m=application 0 TCP/DTLS/SCTP webrtc-datachannel";
    let sdp = format!(
        "{SESSION}a=group:BUNDLE 0\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=recvonly\na=rtpmap:96 VP8/90000\n\
         {rejected}\nc=IN IP4 0.0.0.0\na=mid:1\n"
    );
    let (_pc, answer) = answer_to(RTCSessionDescription::offer(crlf(&sdp))?)?;
    assert_eq!(data_section(&answer)[0], rejected);
    Ok(())
}

/// The data section of the drafts before RFC 8841 (`DTLS/SCTP` with the SCTP port as fmt and
/// `a=sctpmap`), which no current browser sends: it is not a section this endpoint can
/// answer in kind, so it is rejected as any unknown media is, the m= line kept but for the
/// port, and no SCTP transport is started. (It used to be rejected as
/// `UDP/DTLS/SCTP webrtc-datachannel`, a line the offer never had.)
#[test]
fn a_pre_rfc_sctpmap_data_section_is_rejected_with_its_own_m_line() -> TestResult {
    let sdp = format!(
        "{SESSION}a=group:BUNDLE 0 1\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=recvonly\na=rtpmap:96 VP8/90000\n\
         m=application 9 DTLS/SCTP 5000\n{TRANSPORT}a=mid:1\na=sctpmap:5000 webrtc-datachannel 1024\n"
    );
    let (pc, answer) = answer_to(RTCSessionDescription::offer(crlf(&sdp))?)?;
    assert_eq!(data_section(&answer)[0], "m=application 0 DTLS/SCTP 5000");
    assert!(pc.sctp().is_none());
    Ok(())
}

/// RFC 8841 section 9.2: "SDP direction attributes MUST be ignored if present." A data
/// section that says `a=inactive` or `a=recvonly` is a data section like any other.
#[test]
fn direction_attributes_on_the_data_section_are_ignored() -> TestResult {
    for direction in ["a=inactive\n", "a=recvonly\n", "a=sendonly\n", ""] {
        let attributes = format!("a=sctp-port:5000\n{direction}");
        let (pc, answer) = answer_to(data_offer(UDP_DATA, &attributes))?;
        let section = data_section(&answer);
        assert_eq!(section[0], UDP_DATA, "{direction:?}");
        assert_eq!(
            attribute(&section, "sctp-port"),
            Some("5000"),
            "{direction:?}"
        );
        assert!(pc.sctp().is_some(), "{direction:?}");
    }
    Ok(())
}

/// RFC 8841 section 6.1: the peer's `a=max-message-size` bounds what this side sends: "If
/// the SDP 'max-message-size' attribute is not present, the default value is 64K", and zero
/// "indicates that the SCTP endpoint will handle messages of any size", which leaves this
/// side's own ceiling.
#[test]
fn the_peers_max_message_size_is_the_send_limit() -> TestResult {
    for (attribute, limit) in [
        ("", 65536),
        ("a=max-message-size:0\n", 262144),
        ("a=max-message-size:1200\n", 1200),
        ("a=max-message-size:100000000\n", 262144),
    ] {
        let attributes = format!("a=sctp-port:5000\n{attribute}");
        // A peer that sends up to its ceiling of 256 KiB, so that the peer's limit decides.
        let pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_sctp_max_message_size(SctpMaxMessageSize::Unbounded)
                    .build(),
            )
            .build(Instant::now())?;
        let (pc, answer) = answer_from(pc, data_offer(UDP_DATA, &attributes))?;
        assert_eq!(
            self::attribute(&data_section(&answer), "max-message-size"),
            Some("262144"),
            "what this side takes does not depend on the offer"
        );
        assert_eq!(
            pc.sctp().expect("SCTP is negotiated").max_message_size(),
            Some(limit),
            "{attribute:?}"
        );
    }
    Ok(())
}

/// RFC 8841 section 10.3: "If the offer contained a new (different than the one currently
/// used) SCTP port value, the answerer MUST also associate a new SCTP port value." The
/// answer used to say 5000 whatever the offer said.
#[test]
fn a_new_sctp_port_in_the_offer_gets_a_new_one_in_the_answer() -> TestResult {
    let mut pc = default_peer()?;
    let now = Instant::now();
    let mut ports = vec![];
    for offered in ["5000", "5000", "6000", "6000", "6001"] {
        let attributes = format!("a=sctp-port:{offered}\n");
        pc.set_remote_description(now, data_offer(UDP_DATA, &attributes))?;
        let answer = pc.create_answer(None)?;
        pc.set_local_description(now, answer.clone())?;
        let port = attribute(&data_section(&answer.sdp), "sctp-port")
            .expect("a=sctp-port")
            .to_owned();
        assert_ne!(port, "0");
        ports.push(port);
        assert!(pc.sctp().is_some());
    }
    assert_eq!(ports[0], "5000");
    assert_eq!(
        ports[1], ports[0],
        "the same port offered: the same answered"
    );
    assert_ne!(ports[2], ports[1], "a new port offered: a new one answered");
    assert_eq!(ports[3], ports[2]);
    assert_ne!(ports[4], ports[3]);
    Ok(())
}

/// RFC 8841 section 10.5: to "close an SCTP association and immediately establish a new
/// SCTP association", the offer carries "a new (different than the one currently used)"
/// `a=sctp-port`; to close it without a new one, "an attribute value of zero"; and to
/// establish one after that, a port again. `replace_sctp_association` and
/// `close_sctp_association` ask for the first two, a new data channel for the third.
#[test]
fn the_application_asks_for_a_new_association_or_none() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let first = offerer.create_data_channel("first", None)?.id();
    let port = |sdp: &str| {
        attribute(&data_section(sdp), "sctp-port")
            .expect("a=sctp-port")
            .to_owned()
    };

    let (offer, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert_eq!(
        (port(&offer).as_str(), port(&answer).as_str()),
        ("5000", "5000")
    );
    channel_events(&mut offerer);

    // A new association: both sides take a new port, and the channel of the old one closes.
    offerer.replace_sctp_association();
    let waiting = offerer.create_data_channel("second", None)?.id();
    let (offer, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert_ne!(port(&offer), "5000");
    assert_ne!(port(&offer), "0");
    assert_ne!(port(&answer), "5000", "a new port for a new port");
    assert_ne!(port(&answer), "0");
    assert!(offerer.sctp().is_some());
    assert!(answerer.sctp().is_some());
    let replaced_port = port(&offer);
    // Neither channel was dialed (no transport runs in this test), so both wait for the new
    // association rather than being closed with the old one.
    assert!(channel_events(&mut offerer).is_empty());
    assert_eq!(
        offerer
            .data_channel(waiting)
            .expect("waiting")
            .ready_state(),
        RTCDataChannelState::Connecting
    );
    assert!(offerer.data_channel(first).is_some());

    // An offer that asks for nothing new keeps the port.
    let (offer, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert_eq!(port(&offer), replaced_port);
    assert_ne!(port(&answer), "0");

    // No association: zero from the offerer, zero back, and every channel closes.
    offerer.close_sctp_association();
    let (offer, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert_eq!((port(&offer).as_str(), port(&answer).as_str()), ("0", "0"));
    assert_eq!(
        port_of(&data_section(&offer)),
        9,
        "the section itself stays"
    );
    assert!(offerer.sctp().is_none());
    assert!(answerer.sctp().is_none());
    let closed: Vec<_> = channel_events(&mut offerer)
        .into_iter()
        .filter(|event| matches!(event, RTCDataChannelEvent::OnClose(_)))
        .collect();
    assert_eq!(
        closed,
        vec![
            RTCDataChannelEvent::OnClose(first),
            RTCDataChannelEvent::OnClose(waiting),
        ]
    );
    assert!(offerer.data_channel(first).is_none());
    assert!(offerer.data_channel(waiting).is_none());

    // It stays closed in later offers ...
    let (offer, _answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert_eq!(port(&offer), "0");
    assert!(offerer.sctp().is_none());

    // ... until a data channel needs an association again, on a port that is neither zero
    // nor the one of the association that was closed.
    offerer.create_data_channel("third", None)?;
    let (offer, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert_ne!(port(&offer), "0");
    assert_ne!(port(&offer), replaced_port);
    assert_ne!(port(&answer), "0");
    assert!(offerer.sctp().is_some());
    assert!(answerer.sctp().is_some());

    // The answerer may refuse as well: zero in its answer closes it on both sides.
    answerer.close_sctp_association();
    let (offer, answer) = jsep_common::exchange(&mut offerer, &mut answerer)?;
    assert_ne!(port(&offer), "0");
    assert_eq!(port(&answer), "0");
    assert!(offerer.sctp().is_none());
    assert!(answerer.sctp().is_none());
    Ok(())
}
