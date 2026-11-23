//! RTP stream pause and resume (RFC 7728).
//!
//! [`PauseResumeInterceptor`] runs both roles of the PAUSE-RESUME message
//! ([`rtcp::transport_feedbacks::pause_resume`]) for the streams that negotiated
//! `a=rtcp-fb:<pt> ccm pause` (section 9):
//!
//! - as RTP stream **sender** it keeps the state machine of section 6 per local SSRC (playing,
//!   pausing, paused, local paused) and the current PauseID: a PAUSE with the current PauseID
//!   starts the hold-off period (section 6.2; none when `nowait` was negotiated), after which
//!   the stream is paused and a PAUSED indication is sent at once and with the next two
//!   reports (section 6.3); a RESUME with the current PauseID plays it again with the next
//!   PauseID (section 6.1); a request it cannot honour, or one with a PauseID that is not
//!   current, is answered with REFUSED (section 8.4), one REFUSED per PauseID and compound
//!   packet. While paused, the RTP the application still writes is not sent, and the stream
//!   goes on afterwards with the sequence number after the last one sent (section 6.1). The
//!   requester's BYE or time-out resumes the stream (sections 6.3.1, 6.3.2).
//! - as RTP stream **receiver** it sends the PAUSE and RESUME the application asks for through
//!   [`PauseResumeHandle`], with the current PauseID it learned from PAUSED, REFUSED and its
//!   own requests (section 8.1), retransmits them after `2 * RTT + T_dither_max` (sections
//!   8.1, 8.3) and refrains for a while after a REFUSED for its own PauseID.
//!
//! The messages a peer did not declare it can receive (its `config`, section 9) are not sent
//! to it. Every PAUSE-RESUME message read is also delivered to the application.

#[cfg(test)]
mod pause_resume_test;

use crate::rtcp_session::{RepeatInRegularReports, RtcpSessionControl, RtcpSessionEvent};
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Interceptor, Packet, TaggedPacket};
use rtcp::goodbye::Goodbye;
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use rtcp::transport_feedbacks::pause_resume::{PauseResume, PauseResumeEntry, PauseResumeType};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The `ccm` parameter of `a=rtcp-fb` that negotiates the messages (RFC 7728 section 9).
pub const RTCP_FB_CCM_PAUSE: &str = "pause";

/// The round trip a sender or receiver assumes while it knows none (RFC 7728 section 8.1:
/// "RTP stream receivers that lack an RTT estimate to the sender SHOULD use 500 ms as the
/// default value").
pub const PAUSE_DEFAULT_ROUND_TRIP_TIME: Duration = Duration::from_millis(500);

/// How often PAUSED is repeated after the first one: "PAUSED MUST also be included in (at
/// least) the next two regular RTCP reports" (section 8.2).
pub const PAUSED_REPETITIONS: u8 = 2;

/// The fewest times a local-pause PAUSED is repeated after the first one (RFC 7728 section
/// 6.4: "a sufficient number of times to reach a high probability that the message is
/// correctly delivered"); more when the receivers report loss
/// ([`local_pause_repetitions`]).
pub const LOCAL_PAUSED_MIN_REPETITIONS: u8 = PAUSED_REPETITIONS + 1;

/// The most times a local-pause PAUSED is repeated after the first one, whatever the loss.
pub const LOCAL_PAUSED_MAX_REPETITIONS: u8 = 10;

/// The probability that every copy of a local-pause PAUSED is lost, which the repetitions
/// are chosen to stay under (section 6.4's "high probability" of delivery: 99.9 %).
pub const LOCAL_PAUSED_LOSS_TARGET: f64 = 1e-3;

/// How many times a local-pause PAUSED is repeated after the first one when the receivers
/// report `fraction_lost` (the RFC 3550 report block's fraction, out of 256) on the stream:
/// the fewest repetitions `n` for which all `n + 1` copies are lost with a probability of at
/// most [`LOCAL_PAUSED_LOSS_TARGET`], between [`LOCAL_PAUSED_MIN_REPETITIONS`] and
/// [`LOCAL_PAUSED_MAX_REPETITIONS`] (RFC 7728 section 6.4).
pub fn local_pause_repetitions(fraction_lost: u8) -> u8 {
    let loss = f64::from(fraction_lost) / 256.0;
    let mut repetitions = LOCAL_PAUSED_MIN_REPETITIONS;
    while repetitions < LOCAL_PAUSED_MAX_REPETITIONS
        && loss.powi(i32::from(repetitions) + 1) > LOCAL_PAUSED_LOSS_TARGET
    {
        repetitions += 1;
    }
    repetitions
}

/// The interval at which PAUSED is repeated and after which a participant that sent nothing
/// for five of them has timed out (RFC 3550 section 6.3.5), unless the builder says otherwise:
/// the RTCP report interval of a session at the minimum RTCP rate (RFC 3550 section 6.2).
pub const PAUSE_DEFAULT_REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// The `config` values of RFC 7728 section 9 (Figure 7): what an endpoint sends and receives.
/// `1` is the full implementation, the default when the attribute is left out.
fn supports(config: u8, sending: bool, typ: PauseResumeType) -> bool {
    use PauseResumeType::*;
    // (send PAUSE, RESUME, PAUSED, REFUSED), (receive PAUSE, RESUME, PAUSED, REFUSED).
    let (send, receive): ([bool; 4], [bool; 4]) = match config {
        1 => ([true; 4], [true; 4]),
        2 => ([true, true, true, false], [false, false, true, true]),
        3 => ([false, false, true, true], [true, true, true, false]),
        4 => ([true, true, false, false], [false, false, true, true]),
        5 => ([false, false, true, true], [true, true, false, false]),
        6 => ([false, false, true, false], [false, false, true, false]),
        7 => ([false; 4], [false, false, true, false]),
        8 => ([false, false, true, false], [false; 4]),
        _ => ([false; 4], [false; 4]),
    };
    let row = if sending { send } else { receive };
    match typ {
        Pause => row[0],
        Resume => row[1],
        Paused => row[2],
        Refused => row[3],
        Reserved(_) => false,
    }
}

/// The `config` an answerer that implements everything answers to an offered one (RFC 7728
/// section 9.1, Figure 9): the complementary subset, so that what one side sends the other
/// receives. `None` for a value the section does not define: "MUST remove the "pause" CCM
/// line in the answer when receiving an offer with a "config" value it does not understand".
/// The mapping is its own inverse, so it also gives the peer's `config` from this endpoint's.
pub fn pause_config_answer(offered: u8) -> Option<u8> {
    Some(match offered {
        1 => 1,
        2 => 3,
        3 => 2,
        4 => 5,
        5 => 4,
        6 => 6,
        7 => 8,
        8 => 7,
        _ => return None,
    })
}

/// What a negotiated `ccm pause` line says (RFC 7728 section 9, Figure 8): `pause`, then
/// `nowait` and `config=<n>` in any order; unknown attributes are ignored ("Unknown pause
/// attributes MUST be ignored").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PauseCapability {
    /// `nowait`: the hold-off period is 0.
    pub nowait: bool,
    /// `config`, 1 when left out.
    pub config: u8,
}

impl PauseCapability {
    /// Parses the parameter of a `ccm` feedback line (`pause nowait config=3`); `None` when it
    /// is not `pause`, or names `config` or `nowait` more than once ("MUST NOT appear more
    /// than once"), or `config` is not a number.
    pub fn parse(parameter: &str) -> Option<Self> {
        let mut words = parameter.split_whitespace();
        if !words.next()?.eq_ignore_ascii_case(RTCP_FB_CCM_PAUSE) {
            return None;
        }
        let (mut nowait, mut config) = (false, None);
        for word in words {
            if word.eq_ignore_ascii_case("nowait") {
                if nowait {
                    return None;
                }
                nowait = true;
            } else if let Some(value) = word
                .split_once('=')
                .filter(|(key, _)| key.eq_ignore_ascii_case("config"))
                .map(|(_, value)| value)
            {
                if config.is_some() || value.is_empty() || value.len() > 2 {
                    return None;
                }
                config = Some(value.parse().ok()?);
            }
        }
        Some(Self {
            nowait,
            config: config.unwrap_or(1),
        })
    }

    /// The line's parameter: `pause`, `nowait` when set, `config` when not 1.
    pub fn parameter(&self) -> String {
        let mut parameter = RTCP_FB_CCM_PAUSE.to_owned();
        if self.nowait {
            parameter.push_str(" nowait");
        }
        if self.config != 1 {
            parameter.push_str(&format!(" config={}", self.config));
        }
        parameter
    }

    /// The negotiated capability of this endpoint from its own line (`local`) and the peer's
    /// (`remote`), as an answer states it (section 9.1): this endpoint implements every
    /// message, so its `config` is the one complementary to the peer's, and `nowait` holds
    /// only when both lines have it. `None` when the peer's `config` is not one the section
    /// defines.
    pub fn negotiate(local: &Self, remote: &Self) -> Option<Self> {
        Some(Self {
            nowait: local.nowait && remote.nowait,
            config: pause_config_answer(remote.config)?,
        })
    }

    /// Whether the peer receives `typ`: its `config` is the complement of this endpoint's.
    fn peer_receives(&self, typ: PauseResumeType) -> bool {
        pause_config_answer(self.config).is_some_and(|peer| supports(peer, false, typ))
    }

    /// Whether this endpoint acts on a received `typ`.
    fn receives(&self, typ: PauseResumeType) -> bool {
        supports(self.config, false, typ)
    }
}

/// The negotiated `ccm pause` of a stream, if it has one.
fn negotiated_pause(info: &StreamInfo) -> Option<PauseCapability> {
    info.rtcp_feedback
        .iter()
        .filter(|feedback| feedback.typ == "ccm")
        .find_map(|feedback| PauseCapability::parse(&feedback.parameter))
}

/// Where a local RTP stream is in the state machine of RFC 7728 section 6 (Figure 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseState {
    /// Sending (section 6.1).
    Playing,
    /// A PAUSE was received; the hold-off period runs (section 6.2).
    Pausing,
    /// Paused at a receiver's request (section 6.3).
    Paused,
    /// Paused by this endpoint's own decision (section 6.4).
    LocalPaused,
}

/// What a receiver knows of a remote RTP stream it can pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemotePauseState {
    /// The stream is played as far as the receiver knows.
    Playing,
    /// A PAUSE was sent and neither PAUSED nor REFUSED has come back.
    PauseRequested,
    /// A PAUSED indication arrived.
    Paused,
    /// A RESUME was sent and neither the stream's RTP nor REFUSED has come back.
    ResumeRequested,
}

enum Command {
    Pause(u32),
    Resume(u32),
    LocalPause(u32),
    LocalResume(u32),
    /// The stream was bound initially paused (`StreamInfo::initially_paused`).
    InitialPause(u32),
}

#[derive(Default)]
struct Shared {
    commands: Vec<Command>,
    local: HashMap<u32, PauseState>,
    remote: HashMap<u32, RemotePauseState>,
    /// The PauseID each remote stream's sender uses now, as far as known.
    remote_pause_ids: HashMap<u32, u16>,
}

fn lock(shared: &Arc<Mutex<Shared>>) -> MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What the peer connection tells the [`PauseResumeInterceptor`] while it runs: a local
/// stream it sends made inactive or active again (W3C webrtc-pc `RTCRtpEncodingParameters`
/// `active`), which RFC 8853 section 5.2 has treated as an RFC 7728 local pause (section 6.4,
/// announced with PAUSED) and resume. A stream that did not negotiate pause and resume is
/// not affected.
///
/// It travels as an [`Attribute::Custom`] on an empty RTCP packet written into the chain
/// ([`PauseResumeControl::into_packet`]), which the interceptor hands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PauseResumeControl {
    /// The local stream of this SSRC is paused by local decision.
    LocalPause(u32),
    /// The local stream of this SSRC, paused by local decision, plays again.
    LocalResume(u32),
}

impl PauseResumeControl {
    /// The packet that carries this to the pause-resume interceptor when written into the
    /// chain at `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(self))),
        }
    }
}

/// The application's side of [`PauseResumeInterceptor`]: asks a remote stream to pause or
/// resume, pauses its own streams by local decision, and reads where each stream is. A
/// request takes effect at the interceptor's next timeout, which the interceptor asks for at
/// once.
#[derive(Clone)]
pub struct PauseResumeHandle {
    shared: Arc<Mutex<Shared>>,
}

impl PauseResumeHandle {
    /// Asks the sender of the remote stream `ssrc` to pause it (RFC 7728 section 8.1).
    pub fn pause(&self, ssrc: u32) {
        lock(&self.shared).commands.push(Command::Pause(ssrc));
    }

    /// Asks the sender of the remote stream `ssrc` to resume it (section 8.3).
    pub fn resume(&self, ssrc: u32) {
        lock(&self.shared).commands.push(Command::Resume(ssrc));
    }

    /// Pauses the local stream `ssrc` by local decision (section 6.4).
    pub fn local_pause(&self, ssrc: u32) {
        lock(&self.shared).commands.push(Command::LocalPause(ssrc));
    }

    /// Ends a local pause of the local stream `ssrc`: it plays (section 6.4, "When leaving the
    /// local paused state, the stream state SHALL become Playing").
    pub fn local_resume(&self, ssrc: u32) {
        lock(&self.shared).commands.push(Command::LocalResume(ssrc));
    }

    /// The state of the local stream `ssrc`, if it negotiated pause.
    pub fn state(&self, ssrc: u32) -> Option<PauseState> {
        lock(&self.shared).local.get(&ssrc).copied()
    }

    /// What is known of the remote stream `ssrc`, if it negotiated pause.
    pub fn remote_state(&self, ssrc: u32) -> Option<RemotePauseState> {
        lock(&self.shared).remote.get(&ssrc).copied()
    }

    /// The PauseID the sender of the remote stream `ssrc` uses now, as far as known.
    pub fn remote_pause_id(&self, ssrc: u32) -> Option<u16> {
        lock(&self.shared).remote_pause_ids.get(&ssrc).copied()
    }
}

/// Builder for [`PauseResumeInterceptor`].
#[derive(Debug, Clone)]
pub struct PauseResumeBuilder {
    round_trip_time: Duration,
    report_interval: Duration,
    dither_max: Duration,
    repeat_in_regular_reports: bool,
}

impl Default for PauseResumeBuilder {
    fn default() -> Self {
        Self {
            round_trip_time: PAUSE_DEFAULT_ROUND_TRIP_TIME,
            report_interval: PAUSE_DEFAULT_REPORT_INTERVAL,
            dither_max: Duration::ZERO,
            repeat_in_regular_reports: true,
        }
    }
}

impl PauseResumeBuilder {
    /// The defaults: a 500 ms round trip, a 5 s report interval, `T_dither_max` 0 (RFC 4585
    /// section 3.4 for a point-to-point session).
    pub fn new() -> Self {
        Self::default()
    }

    /// The round trip to the peer assumed until one is measured, used for the hold-off period
    /// and the retransmission of requests (`2 * RTT + T_dither_max`). Once the RTCP session
    /// reports round trips ([`RtcpSessionEvent::RoundTripTime`]), the longest one measured is
    /// used instead (RFC 7728 section 6.2: "RTT is the longest round trip known to the RTP
    /// stream sender").
    pub fn with_round_trip_time(mut self, round_trip_time: Duration) -> Self {
        self.round_trip_time = round_trip_time;
        self
    }

    /// The RTCP report interval: PAUSED is repeated once per interval, twice (section 8.2),
    /// a participant silent for five intervals has timed out (section 6.3.2), and a refused
    /// request is not repeated for two intervals (PAUSE) or one (RESUME).
    pub fn with_report_interval(mut self, report_interval: Duration) -> Self {
        self.report_interval = report_interval;
        self
    }

    /// `T_dither_max` (RFC 4585 section 3.4): 0 in a point-to-point session.
    pub fn with_dither_max(mut self, dither_max: Duration) -> Self {
        self.dither_max = dither_max;
        self
    }

    /// How PAUSED is repeated (RFC 7728 sections 6.3, 6.4, 8.2). `true`, the default: the
    /// first PAUSED is written with a [`RepeatInRegularReports`], so the RTCP session
    /// ([`Slot::RtcpSession`](crate::Slot::RtcpSession)) carries it again in the next Regular
    /// compound packets, "the next two regular RTCP reports" (section 8.2), and drops what is
    /// still owed when the stream leaves the state. `false`: the interceptor writes each
    /// repetition itself, one [`Self::with_report_interval`] apart, for a chain without the
    /// RTCP session.
    pub fn with_repeats_in_regular_reports(mut self, repeat_in_regular_reports: bool) -> Self {
        self.repeat_in_regular_reports = repeat_in_regular_reports;
        self
    }

    /// The interceptor and its handle.
    pub fn build(self) -> (PauseResumeInterceptor, PauseResumeHandle) {
        let shared = Arc::new(Mutex::new(Shared::default()));
        (
            PauseResumeInterceptor {
                config: self,
                shared: shared.clone(),
                senders: HashMap::new(),
                receivers: HashMap::new(),
                initially_paused: HashSet::new(),
                local_ssrcs: Vec::new(),
                last_heard: HashMap::new(),
                round_trips: HashMap::new(),
                cnames: HashMap::new(),
                fraction_lost: HashMap::new(),
                stop_repeating: Vec::new(),
                fallback_ssrc: rand::random(),
                now: None,
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            },
            PauseResumeHandle { shared },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderState {
    Playing,
    Pausing {
        until: Instant,
        requester: u32,
    },
    Paused {
        requester: u32,
    },
    LocalPaused {
        requester: Option<u32>,
    },
    /// Paused from the start by the session description (RFC 8853 section 5.2): an
    /// unsolicited local pause that, unlike [`SenderState::LocalPaused`], a RESUME ends
    /// ("Initially paused simulcast streams are resumed as described by the RTP pause/resume
    /// specification").
    InitiallyPaused,
}

impl SenderState {
    fn view(self) -> PauseState {
        match self {
            Self::Playing => PauseState::Playing,
            Self::Pausing { .. } => PauseState::Pausing,
            Self::Paused { .. } => PauseState::Paused,
            Self::LocalPaused { .. } | Self::InitiallyPaused => PauseState::LocalPaused,
        }
    }
}

struct SenderStream {
    capability: PauseCapability,
    state: SenderState,
    pause_id: u16,
    /// The packets not sent while paused: later sequence numbers are lowered by this many,
    /// so that the first packet after a pause follows the last one sent (section 6.1).
    dropped: u16,
    /// The extended sequence number of the last packet sent.
    highest: Option<u32>,
    /// PAUSED indications still owed, and when the next one is (without the RTCP session's
    /// repetitions, [`PauseResumeBuilder::with_repeats_in_regular_reports`]).
    paused_left: u8,
    next_paused: Option<Instant>,
    /// The RTCP session repeats this stream's PAUSED.
    repeating: bool,
    /// The repetitions are to stop: the stream left the paused states.
    stop_repeating: bool,
    ssrc: u32,
}

impl SenderStream {
    fn on_sent(&mut self, sequence_number: u16) {
        self.highest = Some(match self.highest {
            None => u32::from(sequence_number),
            Some(highest) => {
                let cycles = highest & 0xffff_0000;
                let last = highest as u16;
                let ahead = sequence_number.wrapping_sub(last);
                if ahead == 0 || ahead >= 0x8000 {
                    highest
                } else if sequence_number < last {
                    (cycles + 0x1_0000) | u32::from(sequence_number)
                } else {
                    cycles | u32::from(sequence_number)
                }
            }
        });
    }

    fn sending(&self) -> bool {
        matches!(
            self.state,
            SenderState::Playing | SenderState::Pausing { .. }
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct Request {
    typ: PauseResumeType,
    pause_id: u16,
    next_at: Instant,
    tries: u8,
}

struct ReceiverStream {
    capability: PauseCapability,
    state: RemotePauseState,
    pause_id: Option<u16>,
    request: Option<Request>,
    /// No new request of this type before then (a REFUSED for this endpoint's PauseID).
    hold: Option<(PauseResumeType, Instant)>,
    /// The sender said BYE for this SSRC: no further PAUSE or RESUME goes to it (section
    /// 6.3.1).
    left: bool,
}

/// How often a request is retransmitted before the receiver gives up.
const MAX_REQUEST_TRIES: u8 = 5;

/// RFC 7728 pause and resume for the streams that negotiated `ccm pause`; see the module
/// documentation.
pub struct PauseResumeInterceptor {
    config: PauseResumeBuilder,
    shared: Arc<Mutex<Shared>>,
    senders: HashMap<u32, SenderStream>,
    receivers: HashMap<u32, ReceiverStream>,
    /// The local SSRCs that were bound initially paused once: a later binding (after a
    /// renegotiation) does not pause them again; RFC 7728 signalling decides from then on
    /// (RFC 8853 section 5.3.4).
    initially_paused: HashSet<u32>,
    /// Every bound local SSRC: a request is sent from one of them (section 7: "any of its
    /// SSRCs MAY be used").
    local_ssrcs: Vec<u32>,
    /// When each remote SSRC was last heard from (RTP or RTCP), for the time-out of a
    /// requester (section 6.3.2).
    last_heard: HashMap<u32, Instant>,
    /// The round trip the RTCP session measured to the receiver of each local SSRC.
    round_trips: HashMap<u32, Duration>,
    /// The CNAME of each remote SSRC, from the RTCP session (section 6.2: one CNAME across
    /// the received SSRCs is a single receiver).
    cnames: HashMap<u32, String>,
    /// The latest fraction lost the receivers reported on each local SSRC.
    fraction_lost: HashMap<u32, u8>,
    /// Keys whose repetitions the RTCP session is to stop (a stream left the paused states).
    stop_repeating: Vec<u32>,
    fallback_ssrc: u32,
    now: Option<Instant>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl PauseResumeInterceptor {
    fn send(&mut self, now: Instant, sender_ssrc: u32, entries: Vec<PauseResumeEntry>) {
        if entries.is_empty() {
            return;
        }
        self.write_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(PauseResume {
                sender_ssrc,
                entries,
            })])),
        });
    }

    /// RTT for `2 * RTT + T_dither_max` (sections 6.2, 8.1): "the longest round trip known",
    /// the configured one until one is measured.
    fn round_trip_time(&self) -> Duration {
        self.round_trips
            .values()
            .copied()
            .max()
            .unwrap_or(self.config.round_trip_time)
    }

    /// Section 6.2: whether the received SSRCs show more than one CNAME, i.e. several
    /// receivers.
    fn several_receivers(&self) -> bool {
        let mut cnames = self.cnames.values();
        cnames
            .next()
            .is_some_and(|first| cnames.any(|other| other != first))
    }

    fn request_ssrc(&self) -> u32 {
        self.local_ssrcs
            .first()
            .copied()
            .unwrap_or(self.fallback_ssrc)
    }

    fn publish(&self) {
        let mut shared = lock(&self.shared);
        shared.local = self
            .senders
            .iter()
            .map(|(ssrc, stream)| (*ssrc, stream.state.view()))
            .collect();
        shared.remote = self
            .receivers
            .iter()
            .map(|(ssrc, stream)| (*ssrc, stream.state))
            .collect();
        shared.remote_pause_ids = self
            .receivers
            .iter()
            .filter_map(|(ssrc, stream)| stream.pause_id.map(|id| (*ssrc, id)))
            .collect();
    }

    /// Section 6.1: "When entering the state, the current PauseID MUST be incremented".
    /// Repetitions of PAUSED still owed stop (sections 6.3: "as long as it is then still in
    /// paused state", 6.4: "stopping such repetition whenever leaving the state").
    fn enter_playing(stream: &mut SenderStream) {
        stream.state = SenderState::Playing;
        stream.pause_id = stream.pause_id.wrapping_add(1);
        stream.paused_left = 0;
        stream.next_paused = None;
        stream.stop_repeating |= std::mem::take(&mut stream.repeating);
    }

    /// Tells the RTCP session to stop the repetitions of the streams that left the paused
    /// states.
    fn flush_stop_repeating(&mut self, now: Instant) {
        for stream in self.senders.values_mut() {
            if std::mem::take(&mut stream.stop_repeating) {
                self.stop_repeating.push(stream.ssrc);
            }
        }
        for key in std::mem::take(&mut self.stop_repeating) {
            self.write_queue
                .push_back(RtcpSessionControl::StopRepeating { key }.into_packet(now));
        }
    }

    /// Paused (section 6.3) or local paused (6.4): PAUSED now, and `repeats` more, in the
    /// next Regular RTCP packets of the session (or, without it, one report interval apart).
    fn enter_paused(&mut self, now: Instant, ssrc: u32, state: SenderState, repeats: u8) {
        let interval = self.config.report_interval;
        let in_regular = self.config.repeat_in_regular_reports;
        let Some(stream) = self.senders.get_mut(&ssrc) else {
            return;
        };
        stream.state = state;
        let entry = PauseResumeEntry::paused(ssrc, stream.pause_id, stream.highest.unwrap_or(0));
        if !stream.capability.peer_receives(PauseResumeType::Paused) {
            return;
        }
        if in_regular {
            stream.paused_left = 0;
            stream.next_paused = None;
            stream.repeating = repeats > 0;
            stream.stop_repeating = false;
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(PauseResume {
                    sender_ssrc: ssrc,
                    entries: vec![entry],
                })]))
                .with(Attribute::Custom(Arc::new(RepeatInRegularReports {
                    key: ssrc,
                    count: repeats,
                }))),
            });
        } else {
            stream.paused_left = repeats;
            stream.next_paused = (repeats > 0).then(|| now + interval);
            self.send(now, ssrc, vec![entry]);
        }
    }

    /// The sender's side of the requests of one compound packet (sections 8.1, 8.3, 8.4).
    fn on_requests(&mut self, now: Instant, requester: u32, entries: &[PauseResumeEntry]) {
        let several_receivers = self.several_receivers();
        let round_trip_time = self.round_trip_time();
        let dither_max = self.config.dither_max;
        let mut refused: Vec<(u32, u16)> = vec![];
        let mut paused_now: Vec<u32> = vec![];
        for entry in entries {
            let Some(stream) = self.senders.get_mut(&entry.target_ssrc) else {
                continue;
            };
            if !stream.capability.receives(entry.typ) {
                continue;
            }
            let current = stream.pause_id;
            let is_current = entry.pause_id == current;
            match (entry.typ, stream.state) {
                (PauseResumeType::Pause, SenderState::Playing) if is_current => {
                    // Section 6.2: 0 with `nowait`, unless the sender learned that there are
                    // several receivers after all: then "it MUST change the hold-off period
                    // to be based on the above formula instead".
                    let hold_off = if stream.capability.nowait && !several_receivers {
                        Duration::ZERO
                    } else {
                        round_trip_time * 2 + dither_max
                    };
                    if hold_off.is_zero() {
                        paused_now.push(entry.target_ssrc);
                        stream.state = SenderState::Paused { requester };
                    } else {
                        stream.state = SenderState::Pausing {
                            until: now + hold_off,
                            requester,
                        };
                    }
                }
                // "the received PAUSE SHALL be ignored".
                (PauseResumeType::Pause, _) if is_current => {}
                (PauseResumeType::Resume, SenderState::Pausing { .. })
                | (PauseResumeType::Resume, SenderState::Paused { .. })
                | (PauseResumeType::Resume, SenderState::InitiallyPaused)
                    if is_current =>
                {
                    Self::enter_playing(stream);
                }
                (PauseResumeType::Resume, SenderState::Playing)
                    if is_current || past(entry.pause_id, current) =>
                {
                    // "the received RESUME SHALL be ignored".
                }
                (PauseResumeType::Pause, _) | (PauseResumeType::Resume, _) => {
                    // Not the current PauseID, or (local paused) a RESUME local considerations
                    // make it impossible to honour: REFUSED with the current PauseID.
                    refused.push((entry.target_ssrc, current));
                }
                _ => {}
            }
        }
        for ssrc in paused_now {
            if let Some(stream) = self.senders.get(&ssrc) {
                let state = stream.state;
                self.enter_paused(now, ssrc, state, PAUSED_REPETITIONS);
            }
        }
        // "duplicate REFUSED notifications MUST NOT be scheduled".
        let mut seen: HashSet<(u32, u16)> = HashSet::new();
        for (ssrc, pause_id) in refused {
            let receives = self
                .senders
                .get(&ssrc)
                .is_some_and(|s| s.capability.peer_receives(PauseResumeType::Refused));
            if seen.insert((ssrc, pause_id)) && receives {
                self.send(now, ssrc, vec![PauseResumeEntry::refused(ssrc, pause_id)]);
            }
        }
    }

    /// The receiver's side of PAUSED and REFUSED (sections 8.2, 8.4).
    fn on_answers(&mut self, now: Instant, entries: &[PauseResumeEntry]) {
        let (pause_hold, resume_hold) =
            (self.config.report_interval * 2, self.config.report_interval);
        for entry in entries {
            let Some(stream) = self.receivers.get_mut(&entry.target_ssrc) else {
                continue;
            };
            if !stream.capability.receives(entry.typ) {
                continue;
            }
            match entry.typ {
                PauseResumeType::Paused => {
                    stream.pause_id = Some(entry.pause_id);
                    stream.state = RemotePauseState::Paused;
                    if stream
                        .request
                        .is_some_and(|r| r.typ == PauseResumeType::Pause)
                    {
                        stream.request = None;
                    }
                }
                PauseResumeType::Refused => {
                    let Some(request) = stream.request else {
                        stream.pause_id = Some(entry.pause_id);
                        continue;
                    };
                    stream.request = None;
                    if request.pause_id == entry.pause_id {
                        // Section 8.4: "SHOULD refrain from sending an identical request for
                        // some appropriate time".
                        let hold = if request.typ == PauseResumeType::Pause {
                            pause_hold
                        } else {
                            resume_hold
                        };
                        stream.hold = Some((request.typ, now + hold));
                        stream.state = if request.typ == PauseResumeType::Pause {
                            RemotePauseState::Playing
                        } else {
                            RemotePauseState::Paused
                        };
                    } else {
                        // "MAY schedule another request using the PauseID from the REFUSED".
                        stream.pause_id = Some(entry.pause_id);
                        stream.request = Some(Request {
                            typ: request.typ,
                            pause_id: entry.pause_id,
                            next_at: now,
                            tries: 0,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    /// Section 6.4 for the local stream `ssrc`, from the loss its receivers last reported.
    fn local_pause_repetitions(&self, ssrc: u32) -> u8 {
        local_pause_repetitions(self.fraction_lost.get(&ssrc).copied().unwrap_or(0))
    }

    /// The report blocks a remote SR or RR carries about the local streams.
    fn observe_report_blocks(&mut self, reports: &[ReceptionReport]) {
        for report in reports {
            if self.senders.contains_key(&report.ssrc) {
                self.fraction_lost.insert(report.ssrc, report.fraction_lost);
            }
        }
    }

    fn run_commands(&mut self, now: Instant) {
        let commands = std::mem::take(&mut lock(&self.shared).commands);
        for command in commands {
            match command {
                Command::Pause(ssrc) | Command::Resume(ssrc) => {
                    let typ = if matches!(command, Command::Pause(_)) {
                        PauseResumeType::Pause
                    } else {
                        PauseResumeType::Resume
                    };
                    let Some(stream) = self.receivers.get_mut(&ssrc) else {
                        continue;
                    };
                    if stream.left
                        || !stream.capability.peer_receives(typ)
                        || stream
                            .hold
                            .is_some_and(|(held, until)| held == typ && now < until)
                    {
                        continue;
                    }
                    // Section 8.1: "The initial value SHOULD be 0".
                    let pause_id = stream.pause_id.unwrap_or(0);
                    stream.state = if typ == PauseResumeType::Pause {
                        RemotePauseState::PauseRequested
                    } else {
                        RemotePauseState::ResumeRequested
                    };
                    stream.request = Some(Request {
                        typ,
                        pause_id,
                        next_at: now,
                        tries: 0,
                    });
                }
                Command::LocalPause(ssrc) => {
                    let Some(stream) = self.senders.get(&ssrc) else {
                        continue;
                    };
                    match stream.state {
                        SenderState::LocalPaused { .. } => {}
                        SenderState::InitiallyPaused => {
                            if let Some(stream) = self.senders.get_mut(&ssrc) {
                                stream.state = SenderState::LocalPaused { requester: None };
                            }
                        }
                        // "unless the stream was already in paused state".
                        SenderState::Paused { requester } => {
                            if let Some(stream) = self.senders.get_mut(&ssrc) {
                                stream.state = SenderState::LocalPaused {
                                    requester: Some(requester),
                                };
                            }
                        }
                        SenderState::Playing | SenderState::Pausing { .. } => {
                            // "SHALL be repeated a sufficient number of times to reach a high
                            // probability that the message is correctly delivered": as many
                            // as the loss the receivers report on the stream needs.
                            let repetitions = self.local_pause_repetitions(ssrc);
                            self.enter_paused(
                                now,
                                ssrc,
                                SenderState::LocalPaused { requester: None },
                                repetitions,
                            );
                        }
                    }
                }
                Command::LocalResume(ssrc) => {
                    if let Some(stream) = self.senders.get_mut(&ssrc)
                        && matches!(
                            stream.state,
                            SenderState::LocalPaused { .. } | SenderState::InitiallyPaused
                        )
                    {
                        Self::enter_playing(stream);
                    }
                }
                Command::InitialPause(ssrc) => {
                    if self
                        .senders
                        .get(&ssrc)
                        .is_some_and(|stream| matches!(stream.state, SenderState::Playing))
                    {
                        // Announced as a local pause is (section 6.4).
                        let repetitions = self.local_pause_repetitions(ssrc);
                        self.enter_paused(now, ssrc, SenderState::InitiallyPaused, repetitions);
                    }
                }
            }
        }
    }

    fn run_timers(&mut self, now: Instant) {
        let interval = self.config.report_interval;
        let timeout = interval * 5;
        let retransmit = self.round_trip_time() * 2 + self.config.dither_max;
        let last_heard = self.last_heard.clone();
        let mut pause_now = vec![];
        let mut paused_due = vec![];
        for (ssrc, stream) in &mut self.senders {
            match stream.state {
                SenderState::Pausing { until, requester } if until <= now => {
                    stream.state = SenderState::Paused { requester };
                    pause_now.push(*ssrc);
                }
                SenderState::Paused { requester } | SenderState::Pausing { requester, .. }
                    if last_heard
                        .get(&requester)
                        .is_some_and(|heard| *heard + timeout <= now) =>
                {
                    // Section 6.3.2: the requester timed out; the stream is resumed.
                    Self::enter_playing(stream);
                }
                _ => {}
            }
            if !stream.sending()
                && stream.paused_left > 0
                && stream.next_paused.is_some_and(|at| at <= now)
            {
                stream.paused_left -= 1;
                stream.next_paused = (stream.paused_left > 0).then(|| now + interval);
                if stream.capability.peer_receives(PauseResumeType::Paused) {
                    paused_due.push(PauseResumeEntry::paused(
                        *ssrc,
                        stream.pause_id,
                        stream.highest.unwrap_or(0),
                    ));
                }
            }
        }
        for ssrc in pause_now {
            if let Some(stream) = self.senders.get(&ssrc) {
                let state = stream.state;
                self.enter_paused(now, ssrc, state, PAUSED_REPETITIONS);
            }
        }
        for entry in paused_due {
            let ssrc = entry.target_ssrc;
            self.send(now, ssrc, vec![entry]);
        }

        let request_ssrc = self.request_ssrc();
        let mut requests = vec![];
        for (ssrc, stream) in &mut self.receivers {
            let Some(request) = stream.request.as_mut() else {
                continue;
            };
            if request.next_at > now {
                continue;
            }
            if request.tries >= MAX_REQUEST_TRIES {
                stream.request = None;
                continue;
            }
            request.tries += 1;
            request.next_at = now + retransmit;
            requests.push(match request.typ {
                PauseResumeType::Pause => PauseResumeEntry::pause(*ssrc, request.pause_id),
                _ => PauseResumeEntry::resume(*ssrc, request.pause_id),
            });
        }
        self.send(now, request_ssrc, requests);
    }

    fn next_timer(&self) -> Option<Instant> {
        let timeout = self.config.report_interval * 5;
        let mut next: Option<Instant> = None;
        let mut consider = |at: Instant| {
            next = Some(next.map_or(at, |n| n.min(at)));
        };
        for stream in self.senders.values() {
            match stream.state {
                SenderState::Pausing { until, requester } => {
                    consider(until);
                    if let Some(heard) = self.last_heard.get(&requester) {
                        consider(*heard + timeout);
                    }
                }
                SenderState::Paused { requester } => {
                    if let Some(heard) = self.last_heard.get(&requester) {
                        consider(*heard + timeout);
                    }
                }
                _ => {}
            }
            if let Some(at) = stream.next_paused {
                consider(at);
            }
        }
        for stream in self.receivers.values() {
            if let Some(request) = stream.request {
                consider(request.next_at);
            }
        }
        next
    }
}

/// Whether `pause_id` is a past PauseID of `current` (RFC 7728 section 8: between
/// `current - 2^15` and `current - 1`, modulo 2^16).
fn past(pause_id: u16, current: u16) -> bool {
    let behind = current.wrapping_sub(pause_id);
    (1..=0x8000).contains(&behind)
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for PauseResumeInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let now = msg.now;
        self.now = Some(self.now.map_or(now, |n| n.max(now)));
        self.run_commands(now);
        match &msg.message.packet {
            Packet::Rtp(packet) => {
                let ssrc = packet.header.ssrc;
                self.last_heard.insert(ssrc, now);
                // Section 8.3: a RESUME is retransmitted until RTP of the stream arrives.
                if let Some(stream) = self.receivers.get_mut(&ssrc)
                    && matches!(
                        stream.state,
                        RemotePauseState::Paused | RemotePauseState::ResumeRequested
                    )
                {
                    // The sender plays again, with the next PauseID (section 6.1).
                    stream.pause_id = stream.pause_id.map(|id| id.wrapping_add(1));
                    stream.state = RemotePauseState::Playing;
                    stream.request = None;
                }
            }
            Packet::Rtcp(packets) => {
                let mut deliver = false;
                for packet in packets {
                    if let Some(message) = packet.as_any().downcast_ref::<PauseResume>() {
                        deliver = true;
                        self.last_heard.insert(message.sender_ssrc, now);
                        let message = message.clone();
                        self.on_requests(now, message.sender_ssrc, &message.entries);
                        self.on_answers(now, &message.entries);
                    } else if let Some(bye) = packet.as_any().downcast_ref::<Goodbye>() {
                        // Section 6.3.1: the requester left; the stream is resumed.
                        for left in &bye.sources {
                            self.last_heard.remove(left);
                            self.cnames.remove(left);
                            for stream in self.senders.values_mut() {
                                if matches!(
                                    stream.state,
                                    SenderState::Paused { requester }
                                        | SenderState::Pausing { requester, .. }
                                        if requester == *left
                                ) {
                                    Self::enter_playing(stream);
                                }
                            }
                            // "receivers observing this SHALL NOT send further PAUSE or
                            // RESUME requests to it".
                            if let Some(stream) = self.receivers.get_mut(left) {
                                stream.request = None;
                                stream.left = true;
                            }
                        }
                    } else if let Some(report) = packet.as_any().downcast_ref::<ReceiverReport>() {
                        self.last_heard.insert(report.ssrc, now);
                        self.observe_report_blocks(&report.reports);
                    } else if let Some(report) = packet.as_any().downcast_ref::<SenderReport>() {
                        self.last_heard.insert(report.ssrc, now);
                        self.observe_report_blocks(&report.reports);
                    }
                }
                // What the RTCP session learned: round trips (section 6.2: "the longest
                // round trip known") and the CNAMEs of the remote sources (section 6.2: one
                // CNAME across the received SSRCs is a single receiver).
                match msg.message.custom::<RtcpSessionEvent>() {
                    Some(RtcpSessionEvent::RoundTripTime { ssrc, rtt }) => {
                        self.round_trips.insert(*ssrc, *rtt);
                    }
                    Some(RtcpSessionEvent::RemoteCname { ssrc, cname }) => {
                        self.cnames.insert(*ssrc, cname.clone());
                    }
                    Some(RtcpSessionEvent::SourceTimedOut { ssrc }) => {
                        self.cnames.remove(ssrc);
                    }
                    _ => {}
                }
                if deliver && !msg.message.has(&Attribute::DeliverToApplication) {
                    msg.message.attributes.push(Attribute::DeliverToApplication);
                }
            }
        }
        self.publish();
        self.read_queue.push_back(msg);
        self.flush_stop_repeating(now);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        self.now = Some(self.now.map_or(msg.now, |n| n.max(msg.now)));
        if let Some(control) = msg.message.custom::<PauseResumeControl>() {
            lock(&self.shared).commands.push(match *control {
                PauseResumeControl::LocalPause(ssrc) => Command::LocalPause(ssrc),
                PauseResumeControl::LocalResume(ssrc) => Command::LocalResume(ssrc),
            });
        }
        // A local pause asked for before this packet applies to it.
        self.run_commands(msg.now);
        self.flush_stop_repeating(msg.now);
        if let Packet::Rtp(packet) = &mut msg.message.packet
            && let Some(stream) = self.senders.get_mut(&packet.header.ssrc)
        {
            if !stream.sending() {
                // Paused: nothing is sent (sections 6.3, 6.4). Keepalives are ICE's.
                stream.dropped = stream.dropped.wrapping_add(1);
                return Ok(());
            }
            packet.header.sequence_number =
                packet.header.sequence_number.wrapping_sub(stream.dropped);
            stream.on_sent(packet.header.sequence_number);
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.now = Some(self.now.map_or(now, |n| n.max(now)));
        self.run_commands(now);
        self.run_timers(now);
        self.flush_stop_repeating(now);
        self.publish();
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        // Commands run at the next timeout (or packet): the interceptor has no clock of its
        // own, so it asks for the latest time it was given.
        let commands = !lock(&self.shared).commands.is_empty();
        match (commands.then_some(self.now).flatten(), self.next_timer()) {
            (Some(now), Some(timer)) => Some(now.min(timer)),
            (now, timer) => now.or(timer),
        }
    }
}

impl Interceptor for PauseResumeInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if let Some(capability) = negotiated_pause(info) {
            self.receivers
                .entry(info.ssrc)
                .or_insert(ReceiverStream {
                    capability,
                    state: RemotePauseState::Playing,
                    pause_id: None,
                    request: None,
                    hold: None,
                    left: false,
                })
                .capability = capability;
            self.publish();
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.receivers.remove(&info.ssrc);
        self.publish();
    }

    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if !self.local_ssrcs.contains(&info.ssrc) {
            self.local_ssrcs.push(info.ssrc);
        }
        if let Some(capability) = negotiated_pause(info) {
            // RFC 8853 section 5.2: an initially paused stream is "an unsolicited locally
            // paused stream", from the start; it can be paused only with pause and resume
            // negotiated for it (section 5.3.3), which is when this interceptor binds it.
            if info.initially_paused
                && !self.senders.contains_key(&info.ssrc)
                && self.initially_paused.insert(info.ssrc)
            {
                lock(&self.shared)
                    .commands
                    .push(Command::InitialPause(info.ssrc));
            }
            self.senders
                .entry(info.ssrc)
                .or_insert(SenderStream {
                    capability,
                    state: SenderState::Playing,
                    pause_id: 0,
                    dropped: 0,
                    highest: None,
                    paused_left: 0,
                    next_paused: None,
                    repeating: false,
                    stop_repeating: false,
                    ssrc: info.ssrc,
                })
                .capability = capability;
            self.publish();
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.local_ssrcs.retain(|ssrc| *ssrc != info.ssrc);
        if self
            .senders
            .remove(&info.ssrc)
            .is_some_and(|stream| stream.repeating)
        {
            self.stop_repeating.push(info.ssrc);
        }
        self.fraction_lost.remove(&info.ssrc);
        self.round_trips.remove(&info.ssrc);
        self.publish();
    }
}
