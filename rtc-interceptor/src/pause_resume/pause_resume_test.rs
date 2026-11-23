//! RFC 7728: the sender's state machine (section 6), the messages of section 8, the
//! receiver's PauseID tracking and retransmissions, and the `ccm pause` parameter of section 9.
//! Two interceptors, one sending media and one receiving it, pass their RTCP to each other in
//! virtual time.

use super::*;
use crate::stream_info::RTCPFeedback;
use rtp::header::Header;

const MEDIA: u32 = 0x0100;
const RECEIVER: u32 = 0x0B0B;

fn info(ssrc: u32, parameter: &str) -> StreamInfo {
    StreamInfo {
        ssrc,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "ccm".to_owned(),
            parameter: parameter.to_owned(),
        }],
        ..Default::default()
    }
}

/// The two ends of one stream, in virtual time.
struct Pair {
    sender: PauseResumeInterceptor,
    sender_handle: PauseResumeHandle,
    receiver: PauseResumeInterceptor,
    receiver_handle: PauseResumeHandle,
    now: Instant,
    next_sequence_number: u16,
    /// The sequence numbers of the RTP the sender let through.
    sent: Vec<u16>,
    /// The PAUSE-RESUME entries each side wrote: (from the sender?, entry).
    messages: Vec<(bool, PauseResumeEntry)>,
}

impl Pair {
    fn new(sender_parameter: &str, receiver_parameter: &str) -> Self {
        let (mut sender, sender_handle) = PauseResumeBuilder::new().build();
        let (mut receiver, receiver_handle) = PauseResumeBuilder::new()
            .with_report_interval(Duration::from_secs(5))
            .build();
        sender.bind_local_stream(&info(MEDIA, sender_parameter));
        receiver.bind_remote_stream(&info(MEDIA, receiver_parameter));
        receiver.bind_local_stream(&StreamInfo {
            ssrc: RECEIVER,
            ..Default::default()
        });
        Self {
            sender,
            sender_handle,
            receiver,
            receiver_handle,
            now: Instant::now(),
            next_sequence_number: 1000,
            sent: vec![],
            messages: vec![],
        }
    }

    fn rtcp(&self, sender_ssrc: u32, entries: Vec<PauseResumeEntry>) -> TaggedPacket {
        TaggedPacket {
            now: self.now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(PauseResume {
                sender_ssrc,
                entries,
            })])),
        }
    }

    /// Moves whatever each side wrote to the other, until nothing is left.
    fn exchange(&mut self) {
        loop {
            let mut moved = false;
            while let Some(out) = self.sender.poll_write() {
                moved = true;
                match &out.message.packet {
                    Packet::Rtp(packet) => {
                        self.sent.push(packet.header.sequence_number);
                    }
                    Packet::Rtcp(packets) => {
                        for p in packets {
                            if let Some(m) = p.as_any().downcast_ref::<PauseResume>() {
                                self.messages
                                    .extend(m.entries.iter().cloned().map(|e| (true, e)));
                            }
                        }
                    }
                }
                let mut out = out;
                out.now = self.now;
                self.receiver.handle_read(out).unwrap();
                while self.receiver.poll_read().is_some() {}
            }
            while let Some(out) = self.receiver.poll_write() {
                moved = true;
                if let Packet::Rtcp(packets) = &out.message.packet {
                    for p in packets {
                        if let Some(m) = p.as_any().downcast_ref::<PauseResume>() {
                            self.messages
                                .extend(m.entries.iter().cloned().map(|e| (false, e)));
                        }
                    }
                }
                let mut out = out;
                out.now = self.now;
                self.sender.handle_read(out).unwrap();
                while self.sender.poll_read().is_some() {}
            }
            if !moved {
                break;
            }
        }
    }

    /// Runs both sides' timers up to `self.now + by`.
    fn advance(&mut self, by: Duration) {
        let until = self.now + by;
        loop {
            self.exchange();
            let next = [self.sender.poll_timeout(), self.receiver.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            match next {
                Some(at) if at <= until => {
                    self.now = self.now.max(at);
                    self.sender.handle_timeout(self.now).unwrap();
                    self.receiver.handle_timeout(self.now).unwrap();
                }
                _ => break,
            }
        }
        self.now = until;
        self.sender.handle_timeout(self.now).unwrap();
        self.receiver.handle_timeout(self.now).unwrap();
        self.exchange();
    }

    /// The application writes one RTP packet of the stream.
    fn write_rtp(&mut self) {
        let sequence_number = self.next_sequence_number;
        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
        self.sender
            .handle_write(TaggedPacket {
                now: self.now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: Header {
                        ssrc: MEDIA,
                        sequence_number,
                        ..Default::default()
                    },
                    ..Default::default()
                })),
            })
            .unwrap();
        self.exchange();
    }

    fn of(&self, from_sender: bool, typ: PauseResumeType) -> Vec<PauseResumeEntry> {
        self.messages
            .iter()
            .filter(|(s, e)| *s == from_sender && e.typ == typ)
            .map(|(_, e)| e.clone())
            .collect()
    }
}

/// Sections 6.2, 6.3 and 8.2: a PAUSE with the current PauseID (0 at first) starts the
/// hold-off period of `2 * RTT + T_dither_max` (1 s with the default 500 ms round trip),
/// during which the stream still plays; then it is paused, nothing is sent, and PAUSED carries
/// the PauseID and the extended sequence number of the last packet sent.
#[test]
fn a_pause_pauses_the_stream_after_the_hold_off_period() {
    let mut pair = Pair::new("pause", "pause");
    pair.write_rtp();
    pair.write_rtp();
    pair.receiver_handle.pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.of(false, PauseResumeType::Pause).len(), 1);
    assert_eq!(pair.of(false, PauseResumeType::Pause)[0].pause_id, 0);
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Pausing));
    pair.write_rtp();
    assert_eq!(pair.sent.len(), 3, "still playing during the hold-off");

    pair.advance(Duration::from_millis(1000));
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Paused));
    let paused = pair.of(true, PauseResumeType::Paused);
    assert_eq!(paused.len(), 1);
    assert_eq!(paused[0].pause_id, 0);
    assert_eq!(paused[0].paused_extended_sequence_number(), Some(1002));
    assert_eq!(
        pair.receiver_handle.remote_state(MEDIA),
        Some(RemotePauseState::Paused)
    );
    pair.write_rtp();
    pair.write_rtp();
    assert_eq!(pair.sent.len(), 3, "nothing is sent while paused");
}

/// Section 6.2 with `nowait` on both lines: the hold-off period is 0.
#[test]
fn with_nowait_the_stream_pauses_at_once() {
    let mut pair = Pair::new("pause nowait", "pause nowait");
    pair.receiver_handle.pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Paused));
    assert_eq!(pair.of(true, PauseResumeType::Paused).len(), 1);
}

/// Section 8.2: "PAUSED MUST also be included in (at least) the next two regular RTCP
/// reports": two more, one report interval apart, and no more.
#[test]
fn paused_is_repeated_twice() {
    let mut pair = Pair::new("pause nowait", "pause nowait");
    pair.receiver_handle.pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    pair.advance(PAUSE_DEFAULT_REPORT_INTERVAL * 4);
    assert_eq!(pair.of(true, PauseResumeType::Paused).len(), 3);
}

/// Sections 6.1 and 8.3: a RESUME with the current PauseID plays the stream again with the
/// next PauseID, and its first packet follows the last one sent before the pause, whatever
/// the application wrote meanwhile.
#[test]
fn a_resume_plays_the_stream_on_from_the_next_sequence_number() {
    let mut pair = Pair::new("pause nowait", "pause nowait");
    pair.write_rtp();
    pair.receiver_handle.pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    for _ in 0..5 {
        pair.write_rtp();
    }
    pair.receiver_handle.resume(MEDIA);
    pair.advance(Duration::from_millis(1));
    let resume = pair.of(false, PauseResumeType::Resume);
    assert_eq!(resume.len(), 1);
    assert_eq!(resume[0].pause_id, 0);
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Playing));
    pair.write_rtp();
    assert_eq!(pair.sent, vec![1000, 1001]);
    assert_eq!(
        pair.receiver_handle.remote_state(MEDIA),
        Some(RemotePauseState::Playing)
    );
    assert_eq!(pair.receiver_handle.remote_pause_id(MEDIA), Some(1));

    // The next PAUSE uses the next PauseID.
    pair.receiver_handle.pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.of(false, PauseResumeType::Pause)[1].pause_id, 1);
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Paused));
}

/// Section 8.4: a PAUSE or RESUME whose PauseID is not the current one is answered with one
/// REFUSED carrying the current PauseID, however many such requests the compound packet
/// had; a RESUME with a past PauseID to a playing stream is ignored.
#[test]
fn a_request_with_another_pause_id_is_refused_once() {
    let mut pair = Pair::new("pause", "pause");
    let packet = pair.rtcp(
        RECEIVER,
        vec![
            PauseResumeEntry::pause(MEDIA, 5),
            PauseResumeEntry::pause(MEDIA, 6),
            PauseResumeEntry::resume(MEDIA, 9),
        ],
    );
    pair.sender.handle_read(packet).unwrap();
    pair.exchange();
    let refused = pair.of(true, PauseResumeType::Refused);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].pause_id, 0);
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Playing));

    let past = pair.rtcp(RECEIVER, vec![PauseResumeEntry::resume(MEDIA, 0xffff)]);
    pair.sender.handle_read(past).unwrap();
    pair.exchange();
    assert_eq!(pair.of(true, PauseResumeType::Refused).len(), 1, "ignored");
}

/// Section 6.4: a local pause sends PAUSED unasked; a RESUME cannot end it ("RESUME messages
/// alone cannot resume a paused RTP stream as long as the local decision still applies") and
/// is refused; the local resume plays the stream with the next PauseID.
#[test]
fn a_local_pause_is_announced_and_only_the_sender_ends_it() {
    let mut pair = Pair::new("pause", "pause");
    pair.write_rtp();
    pair.sender_handle.local_pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(
        pair.sender_handle.state(MEDIA),
        Some(PauseState::LocalPaused)
    );
    assert_eq!(pair.of(true, PauseResumeType::Paused).len(), 1);
    assert_eq!(
        pair.receiver_handle.remote_state(MEDIA),
        Some(RemotePauseState::Paused)
    );
    pair.receiver_handle.resume(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.of(true, PauseResumeType::Refused).len(), 1);
    assert_eq!(
        pair.sender_handle.state(MEDIA),
        Some(PauseState::LocalPaused)
    );

    pair.sender_handle.local_resume(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Playing));
    pair.write_rtp();
    assert_eq!(pair.sent, vec![1000, 1001]);
}

/// Section 6.3.1: when the receiver that paused the stream sends BYE, the stream resumes.
#[test]
fn the_requesters_bye_resumes_the_stream() {
    let mut pair = Pair::new("pause nowait", "pause nowait");
    pair.receiver_handle.pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Paused));
    let bye = TaggedPacket {
        now: pair.now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(Goodbye {
            sources: vec![RECEIVER],
            reason: Default::default(),
        })])),
    };
    pair.sender.handle_read(bye).unwrap();
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Playing));
}

/// Section 6.3.2: a requester silent for five report intervals has timed out; the stream it
/// paused resumes.
#[test]
fn the_requesters_time_out_resumes_the_stream() {
    let mut pair = Pair::new("pause nowait", "pause nowait");
    pair.receiver_handle.pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Paused));
    pair.advance(PAUSE_DEFAULT_REPORT_INTERVAL * 5 + Duration::from_millis(1));
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Playing));
}

/// Section 8.1: a PAUSE that gets neither PAUSED nor REFUSED is retransmitted with the same
/// PauseID after `2 * RTT + T_dither_max`.
#[test]
fn an_unanswered_pause_is_retransmitted_with_the_same_pause_id() {
    let (mut receiver, handle) = PauseResumeBuilder::new().build();
    receiver.bind_remote_stream(&info(MEDIA, "pause"));
    let start = Instant::now();
    receiver.handle_timeout(start).unwrap();
    handle.pause(MEDIA);
    receiver.handle_timeout(start).unwrap();
    let mut written = 0;
    let mut now = start;
    while let Some(at) = receiver.poll_timeout() {
        if at > start + Duration::from_millis(2500) {
            break;
        }
        now = now.max(at);
        receiver.handle_timeout(now).unwrap();
        while let Some(out) = receiver.poll_write() {
            if let Packet::Rtcp(packets) = out.message.packet {
                for p in packets {
                    let m = p.as_any().downcast_ref::<PauseResume>().expect("PAUSE");
                    assert_eq!(m.entries[0].typ, PauseResumeType::Pause);
                    assert_eq!(m.entries[0].pause_id, 0);
                    written += 1;
                }
            }
        }
    }
    // At 0 ms, 1000 ms and 2000 ms.
    assert_eq!(written, 3);
}

/// Section 8.4: "An RTP stream receiver that sent a PAUSE or RESUME request and receives a
/// REFUSED containing a PauseID different from the request MAY schedule another request
/// using the PauseID from the REFUSED notification": after a local pause and its end the
/// sender is at PauseID 1, the receiver still at 0; its PAUSE is refused with 1 and repeated
/// with 1, which pauses the stream.
#[test]
fn a_pause_refused_with_another_pause_id_is_asked_again_with_it() {
    let mut pair = Pair::new("pause", "pause");
    pair.sender_handle.local_pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    pair.sender_handle.local_resume(MEDIA);
    pair.advance(Duration::from_millis(1));
    pair.receiver_handle.pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    let pauses: Vec<u16> = pair
        .of(false, PauseResumeType::Pause)
        .iter()
        .map(|p| p.pause_id)
        .collect();
    assert_eq!(pauses, vec![0, 1]);
    assert_eq!(pair.of(true, PauseResumeType::Refused)[0].pause_id, 1);
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Pausing));
}

/// Section 8.4: after a REFUSED with its own PauseID the receiver "SHOULD refrain from
/// sending an identical request for some appropriate time" (one report interval for RESUME):
/// a RESUME to a locally paused stream is refused, and asking again at once sends nothing.
#[test]
fn after_a_refused_resume_the_receiver_refrains() {
    let mut pair = Pair::new("pause", "pause");
    pair.sender_handle.local_pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    pair.receiver_handle.resume(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.of(true, PauseResumeType::Refused).len(), 1);
    pair.receiver_handle.resume(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.of(false, PauseResumeType::Resume).len(), 1);
    pair.advance(PAUSE_DEFAULT_REPORT_INTERVAL);
    pair.receiver_handle.resume(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.of(false, PauseResumeType::Resume).len(), 2);
}

/// Section 9: the parameter, its defaults and its offer/answer rules (Figure 9).
#[test]
fn the_pause_parameter_parses_and_negotiates_as_section_9_says() {
    assert_eq!(
        PauseCapability::parse("pause"),
        Some(PauseCapability {
            nowait: false,
            config: 1
        })
    );
    assert_eq!(
        PauseCapability::parse("pause config=3 nowait"),
        Some(PauseCapability {
            nowait: true,
            config: 3
        })
    );
    assert_eq!(
        PauseCapability::parse("pause future-thing"),
        PauseCapability::parse("pause")
    );
    assert_eq!(PauseCapability::parse("pause nowait nowait"), None);
    assert_eq!(PauseCapability::parse("pause config=1 config=2"), None);
    assert_eq!(PauseCapability::parse("tmmbr"), None);
    for (offer, answer) in [
        (1, 1),
        (2, 3),
        (3, 2),
        (4, 5),
        (5, 4),
        (6, 6),
        (7, 8),
        (8, 7),
    ] {
        assert_eq!(pause_config_answer(offer), Some(answer));
    }
    assert_eq!(pause_config_answer(9), None);
    let full = PauseCapability::parse("pause").unwrap();
    let offer = PauseCapability::parse("pause nowait config=2").unwrap();
    let answer = PauseCapability::negotiate(&full, &offer).unwrap();
    assert_eq!(
        answer.parameter(),
        "pause config=3",
        "no nowait unless both"
    );
    let both = PauseCapability::negotiate(&PauseCapability::parse("pause nowait").unwrap(), &offer)
        .unwrap();
    assert_eq!(both.parameter(), "pause nowait config=3");
    assert!(
        PauseCapability::negotiate(&full, &PauseCapability::parse("pause config=12").unwrap())
            .is_none()
    );
}

/// Section 9: "SHOULD omit sending messages not supported by the remote peer": a sender whose
/// peer only receives PAUSED (config 7) sends no REFUSED; one that does not receive PAUSE
/// (config 8 for this side: it only sends PAUSED) ignores a PAUSE.
#[test]
fn messages_follow_the_negotiated_config() {
    // This side is 8 (sends PAUSED only), the peer 7 (receives PAUSED only).
    let mut pair = Pair::new("pause config=8", "pause config=7");
    let packet = pair.rtcp(RECEIVER, vec![PauseResumeEntry::pause(MEDIA, 0)]);
    pair.sender.handle_read(packet).unwrap();
    pair.exchange();
    assert_eq!(pair.sender_handle.state(MEDIA), Some(PauseState::Playing));
    let wrong = pair.rtcp(RECEIVER, vec![PauseResumeEntry::pause(MEDIA, 4)]);
    pair.sender.handle_read(wrong).unwrap();
    pair.exchange();
    assert!(pair.of(true, PauseResumeType::Refused).is_empty());
    // A local pause is still announced: the peer receives PAUSED.
    pair.sender_handle.local_pause(MEDIA);
    pair.advance(Duration::from_millis(1));
    assert_eq!(pair.of(true, PauseResumeType::Paused).len(), 1);
}
