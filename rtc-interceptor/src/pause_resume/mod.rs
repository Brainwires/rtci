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

use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Interceptor, Packet, TaggedPacket};
use rtcp::goodbye::Goodbye;
use rtcp::receiver_report::ReceiverReport;
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
}

impl Default for PauseResumeBuilder {
    fn default() -> Self {
        Self {
            round_trip_time: PAUSE_DEFAULT_ROUND_TRIP_TIME,
            report_interval: PAUSE_DEFAULT_REPORT_INTERVAL,
            dither_max: Duration::ZERO,
        }
    }
}

impl PauseResumeBuilder {
    /// The defaults: a 500 ms round trip, a 5 s report interval, `T_dither_max` 0 (RFC 4585
    /// section 3.4 for a point-to-point session).
    pub fn new() -> Self {
        Self::default()
    }

    /// The round trip to the peer, used for the hold-off period and the retransmission of
    /// requests (`2 * RTT + T_dither_max`).
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

    /// The interceptor and its handle.
    pub fn build(self) -> (PauseResumeInterceptor, PauseResumeHandle) {
        let shared = Arc::new(Mutex::new(Shared::default()));
        (
            PauseResumeInterceptor {
                config: self,
                shared: shared.clone(),
                senders: HashMap::new(),
                receivers: HashMap::new(),
                local_ssrcs: Vec::new(),
                last_heard: HashMap::new(),
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
    Pausing { until: Instant, requester: u32 },
    Paused { requester: u32 },
    LocalPaused { requester: Option<u32> },
}

impl SenderState {
    fn view(self) -> PauseState {
        match self {
            Self::Playing => PauseState::Playing,
            Self::Pausing { .. } => PauseState::Pausing,
            Self::Paused { .. } => PauseState::Paused,
            Self::LocalPaused { .. } => PauseState::LocalPaused,
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
    /// PAUSED indications still owed, and when the next one is.
    paused_left: u8,
    next_paused: Option<Instant>,
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
    /// Every bound local SSRC: a request is sent from one of them (section 7: "any of its
    /// SSRCs MAY be used").
    local_ssrcs: Vec<u32>,
    /// When each remote SSRC was last heard from (RTP or RTCP), for the time-out of a
    /// requester (section 6.3.2).
    last_heard: HashMap<u32, Instant>,
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
    fn enter_playing(stream: &mut SenderStream) {
        stream.state = SenderState::Playing;
        stream.pause_id = stream.pause_id.wrapping_add(1);
        stream.paused_left = 0;
        stream.next_paused = None;
    }

    /// Paused (section 6.3) or local paused (6.4): PAUSED now, and `repeats` more.
    fn enter_paused(&mut self, now: Instant, ssrc: u32, state: SenderState, repeats: u8) {
        let interval = self.config.report_interval;
        let Some(stream) = self.senders.get_mut(&ssrc) else {
            return;
        };
        stream.state = state;
        stream.paused_left = repeats;
        stream.next_paused = (repeats > 0).then(|| now + interval);
        let entry = PauseResumeEntry::paused(ssrc, stream.pause_id, stream.highest.unwrap_or(0));
        if stream.capability.peer_receives(PauseResumeType::Paused) {
            self.send(now, ssrc, vec![entry]);
        }
    }

    /// The sender's side of the requests of one compound packet (sections 8.1, 8.3, 8.4).
    fn on_requests(&mut self, now: Instant, requester: u32, entries: &[PauseResumeEntry]) {
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
                    let hold_off = if stream.capability.nowait {
                        Duration::ZERO
                    } else {
                        self.config.round_trip_time * 2 + self.config.dither_max
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
                    if !stream.capability.peer_receives(typ)
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
                        // "unless the stream was already in paused state".
                        SenderState::Paused { requester } => {
                            if let Some(stream) = self.senders.get_mut(&ssrc) {
                                stream.state = SenderState::LocalPaused {
                                    requester: Some(requester),
                                };
                            }
                        }
                        SenderState::Playing | SenderState::Pausing { .. } => {
                            // "SHALL be repeated a sufficient number of times".
                            self.enter_paused(
                                now,
                                ssrc,
                                SenderState::LocalPaused { requester: None },
                                PAUSED_REPETITIONS + 1,
                            );
                        }
                    }
                }
                Command::LocalResume(ssrc) => {
                    if let Some(stream) = self.senders.get_mut(&ssrc)
                        && matches!(stream.state, SenderState::LocalPaused { .. })
                    {
                        Self::enter_playing(stream);
                    }
                }
            }
        }
    }

    fn run_timers(&mut self, now: Instant) {
        let interval = self.config.report_interval;
        let timeout = interval * 5;
        let retransmit = self.config.round_trip_time * 2 + self.config.dither_max;
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
                            }
                        }
                    } else if let Some(report) = packet.as_any().downcast_ref::<ReceiverReport>() {
                        self.last_heard.insert(report.ssrc, now);
                    } else if let Some(report) = packet.as_any().downcast_ref::<SenderReport>() {
                        self.last_heard.insert(report.ssrc, now);
                    }
                }
                if deliver && !msg.message.has(&Attribute::DeliverToApplication) {
                    msg.message.attributes.push(Attribute::DeliverToApplication);
                }
            }
        }
        self.publish();
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        self.now = Some(self.now.map_or(msg.now, |n| n.max(msg.now)));
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
                })
                .capability = capability;
            self.publish();
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.local_ssrcs.retain(|ssrc| *ssrc != info.ssrc);
        self.senders.remove(&info.ssrc);
        self.publish();
    }
}
