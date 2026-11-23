//! `RTCDTMFSender` (W3C webrtc-pc section 7; RFC 4733): the tones an application inserts are
//! queued here and played out as telephone-event packets in the audio sender's RTP stream.
//!
//! The engine makes no audio of its own: the application writes the audio packets with
//! [`RTCRtpSender::write_rtp`](super::RTCRtpSender::write_rtp), sequence numbers and
//! timestamps included. Event packets share the audio stream's SSRC, sequence number space and
//! timestamp base (RFC 4733 section 2.5.1.2), so the engine numbers each event packet one past
//! the last packet sent and adds the count of event packets sent so far to the sequence
//! number of every later audio packet. Its timestamps follow the last audio packet's, at the
//! telephone-event clock rate.

use crate::rtp_transceiver::RTCRtpSenderId;
use rtp::codec::telephone_event::{
    EventPacket, EventSet, TELEPHONE_EVENT_END_REPEATS, TelephoneEventSender, dtmf_event_from_char,
};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The default `duration` of `insert_dtmf` (W3C: 100 ms).
pub const DTMF_DEFAULT_DURATION: Duration = Duration::from_millis(100);
/// The default `interToneGap` of `insert_dtmf` (W3C: 70 ms).
pub const DTMF_DEFAULT_INTER_TONE_GAP: Duration = Duration::from_millis(70);
/// The shortest tone (W3C: a shorter `duration` is played for 40 ms).
pub const DTMF_MIN_DURATION: Duration = Duration::from_millis(40);
/// The longest tone, and the longest gap (W3C: 6000 ms).
pub const DTMF_MAX_DURATION: Duration = Duration::from_millis(6000);
/// The shortest gap between tones (W3C: 30 ms).
pub const DTMF_MIN_INTER_TONE_GAP: Duration = Duration::from_millis(30);
/// The pause a `,` in the tone buffer stands for (W3C: 2 seconds).
pub const DTMF_COMMA_DELAY: Duration = Duration::from_millis(2000);
/// How often an event in progress is reported, and how far apart the three final packets go
/// (RFC 4733 section 2.5.1.2: the update interval, 50 ms when there is no audio
/// packetization interval to follow).
pub const DTMF_UPDATE_INTERVAL: Duration = Duration::from_millis(50);

/// The MIME type of the telephone-event codec (RFC 4733 section 7.1.1).
pub const MIME_TYPE_TELEPHONE_EVENT: &str = "audio/telephone-event";

/// W3C `RTCDTMFToneChangeEvent`: a tone began, or the tone buffer ran out (`tone` empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RTCDTMFToneChangeEvent {
    /// The sender whose `RTCDTMFSender` fired the event.
    pub sender_id: RTCRtpSenderId,
    /// The tone that began (`0`-`9`, `A`-`D`, `#`, `*`, or `,` for a pause), or the empty
    /// string at the end of the buffer.
    pub tone: String,
}

/// The telephone-event codec negotiated for the sender, and the stream it goes in.
#[derive(Debug, Copy, Clone)]
pub(crate) struct DtmfStream {
    pub(crate) payload_type: u8,
    pub(crate) clock_rate: u32,
    pub(crate) ssrc: u32,
}

#[derive(Debug, Clone)]
struct PlayingTone {
    sender: TelephoneEventSender,
    start: Instant,
    end: Instant,
    next_update: Instant,
    stream: DtmfStream,
}

/// The `RTCDTMFSender` slots and the playout, for one sender.
#[derive(Debug, Clone, Default)]
pub(crate) struct DtmfState {
    /// `[[ToneBuffer]]`.
    pub(crate) tone_buffer: String,
    /// `[[Duration]]`.
    duration: Duration,
    /// `[[InterToneGap]]`.
    inter_tone_gap: Duration,
    /// When the DTMF playout task steps next run, if they are scheduled.
    next_task: Option<Instant>,
    playing: Option<PlayingTone>,
    /// Event packets due later: the repeats of a final report, one update interval apart.
    pending: VecDeque<(Instant, DtmfStream, EventPacket)>,
    /// Event packets sent so far: added to the sequence number of every later audio packet.
    seq_offset: u16,
    /// The last packet sent in the stream (sequence number as sent, timestamp, when).
    last_sent: Option<(u16, u32, Instant)>,
}

/// What the playout produced at an instant: the packets to send and the tone changes.
#[derive(Debug, Default)]
pub(crate) struct DtmfOutput {
    pub(crate) packets: Vec<rtp::Packet>,
    pub(crate) tone_changes: Vec<String>,
}

/// Whether `c` is a character `insertDTMF` takes (W3C: `0`-`9`, `A`-`D` in either case, `#`,
/// `*` and `,`).
fn recognized(c: char) -> bool {
    c == ',' || dtmf_event_from_char(c.to_ascii_uppercase()).is_some()
}

impl DtmfState {
    /// W3C `insertDTMF`, once "determine if DTMF can be sent" said yes: validates `tones`,
    /// replaces the tone buffer, clamps the duration and gap, and schedules the playout task
    /// at `now` unless one is scheduled already.
    pub(crate) fn insert(
        &mut self,
        now: Instant,
        tones: &str,
        duration: Duration,
        inter_tone_gap: Duration,
    ) -> shared::error::Result<()> {
        if let Some(c) = tones.chars().find(|c| !recognized(*c)) {
            return Err(shared::error::Error::ErrDtmfInvalidCharacter(c));
        }
        self.tone_buffer = tones.to_ascii_uppercase();
        self.duration = duration.clamp(DTMF_MIN_DURATION, DTMF_MAX_DURATION);
        self.inter_tone_gap = inter_tone_gap.clamp(DTMF_MIN_INTER_TONE_GAP, DTMF_MAX_DURATION);
        if self.tone_buffer.is_empty() || self.next_task.is_some() {
            return Ok(());
        }
        self.next_task = Some(now);
        Ok(())
    }

    /// The next instant the playout has something to do.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        [
            self.next_task,
            self.playing.as_ref().map(|p| p.next_update.min(p.end)),
            self.pending.front().map(|(at, _, _)| *at),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// An audio packet the application writes in the stream: its sequence number moves past
    /// the event packets sent before it, and it is the reference for the next event's
    /// timestamp.
    pub(crate) fn on_media_packet(&mut self, now: Instant, packet: &mut rtp::Packet) {
        packet.header.sequence_number = packet.header.sequence_number.wrapping_add(self.seq_offset);
        self.last_sent = Some((packet.header.sequence_number, packet.header.timestamp, now));
    }

    /// Runs the playout up to `now`. `stream` is the telephone-event codec and SSRC to send
    /// with, `None` when "determine if DTMF can be sent" says no: the playout task then stops
    /// (an event in progress is still ended, so the receiver is not left with a tone that
    /// never ends).
    pub(crate) fn run(&mut self, now: Instant, stream: Option<DtmfStream>) -> DtmfOutput {
        let mut out = DtmfOutput::default();
        loop {
            // The earliest thing due: a pending repeat, the tone in progress, or the task.
            let pending_at = self.pending.front().map(|(at, _, _)| *at);
            let playing_at = self.playing.as_ref().map(|p| p.next_update.min(p.end));
            let task_at = self.next_task;
            let Some(at) = [pending_at, playing_at, task_at]
                .into_iter()
                .flatten()
                .min()
            else {
                break;
            };
            if at > now {
                break;
            }
            if pending_at == Some(at) {
                let (_, stream, event) = self.pending.pop_front().expect("pending");
                out.packets.push(self.packet(at, stream, event));
            } else if playing_at == Some(at) {
                self.advance_tone(at, &mut out);
            } else {
                self.next_task = None;
                self.playout_task(at, stream, &mut out);
            }
        }
        out
    }

    /// Reports the tone in progress at `at`: an update, or its end, whose three final packets
    /// go one update interval apart (RFC 4733 section 2.5.1.4).
    fn advance_tone(&mut self, at: Instant, out: &mut DtmfOutput) {
        let Some(mut playing) = self.playing.take() else {
            return;
        };
        let stream = playing.stream;
        if at >= playing.end {
            let units = units(playing.end - playing.start, stream.clock_rate);
            if let Ok(packets) = playing.sender.end(units) {
                // The segment boundary (if any) and the first final report now, the other two
                // final reports one and two intervals later.
                let finals = TELEPHONE_EVENT_END_REPEATS.min(packets.len());
                let (now_packets, later) = packets.split_at(packets.len() - finals + 1);
                for event in now_packets {
                    out.packets.push(self.packet(at, stream, *event));
                }
                for (i, event) in later.iter().enumerate() {
                    let due = at + DTMF_UPDATE_INTERVAL * (i as u32 + 1);
                    self.pending.push_back((due, stream, *event));
                }
            }
            return;
        }
        let units = units(at - playing.start, stream.clock_rate);
        if let Ok(packets) = playing.sender.update(units) {
            for event in packets {
                out.packets.push(self.packet(at, stream, event));
            }
        }
        playing.next_update = at + DTMF_UPDATE_INTERVAL;
        self.playing = Some(playing);
    }

    /// W3C "DTMF playout task steps", at the instant they were scheduled for.
    fn playout_task(&mut self, at: Instant, stream: Option<DtmfStream>, out: &mut DtmfOutput) {
        let Some(stream) = stream else {
            // "If determine if DTMF can be sent returns false, abort these steps."
            return;
        };
        if self.tone_buffer.is_empty() {
            out.tone_changes.push(String::new());
            return;
        }
        let tone = self.tone_buffer.remove(0);
        if tone == ',' {
            self.next_task = Some(at + DTMF_COMMA_DELAY);
        } else {
            let event = dtmf_event_from_char(tone).expect("validated by insert");
            let start_timestamp = self.timestamp_at(at, stream.clock_rate);
            let mut sender = TelephoneEventSender::new(EventSet::dtmf());
            // Volume 10 (-10 dBm0), what browsers send.
            if sender.start(event, 10, start_timestamp).is_ok() {
                self.playing = Some(PlayingTone {
                    sender,
                    start: at,
                    end: at + self.duration,
                    next_update: at,
                    stream,
                });
            }
            self.next_task = Some(at + self.duration + self.inter_tone_gap);
        }
        out.tone_changes.push(tone.to_string());
    }

    /// The RTP timestamp of instant `at` in the stream: the last packet's, moved on by the
    /// time since it was sent.
    fn timestamp_at(&mut self, at: Instant, clock_rate: u32) -> u32 {
        match self.last_sent {
            Some((_, timestamp, sent)) => {
                timestamp.wrapping_add(units(at.saturating_duration_since(sent), clock_rate))
            }
            None => {
                // Nothing sent yet in the stream: a random base (RFC 3550 5.1).
                let base: u32 = rand::random();
                let seq: u16 = rand::random();
                self.last_sent = Some((seq, base, at));
                base
            }
        }
    }

    fn packet(&mut self, at: Instant, stream: DtmfStream, event: EventPacket) -> rtp::Packet {
        let sequence_number = match self.last_sent {
            Some((seq, _, _)) => seq.wrapping_add(1),
            None => rand::random(),
        };
        let timestamp_reference = self.last_sent.map(|(_, ts, sent)| (ts, sent));
        self.seq_offset = self.seq_offset.wrapping_add(1);
        // The reference for timestamps stays the last audio packet: an event packet carries
        // its event's start timestamp, not the instant it is sent.
        self.last_sent = Some((
            sequence_number,
            timestamp_reference.map_or(event.timestamp, |(ts, _)| ts),
            timestamp_reference.map_or(at, |(_, sent)| sent),
        ));
        rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                marker: event.marker,
                payload_type: stream.payload_type,
                sequence_number,
                timestamp: event.timestamp,
                ssrc: stream.ssrc,
                ..Default::default()
            },
            payload: event.payload().unwrap_or_default(),
        }
    }
}

/// `duration` in units of a `clock_rate` clock.
fn units(duration: Duration, clock_rate: u32) -> u32 {
    (duration.as_nanos() * u128::from(clock_rate) / 1_000_000_000) as u32
}

/// W3C `RTCDTMFSender`: the DTMF sender of an audio [`RTCRtpSender`](super::RTCRtpSender),
/// from [`RTCRtpSender::dtmf`](super::RTCRtpSender::dtmf).
///
/// Tones play out as the connection's timers fire ([`handle_timeout`]); each tone that
/// begins, and the end of the buffer, is announced with
/// [`RTCPeerConnectionEvent::OnDtmfToneChange`].
///
/// [`handle_timeout`]: sansio::Protocol::handle_timeout
/// [`RTCPeerConnectionEvent::OnDtmfToneChange`]: crate::peer_connection::event::RTCPeerConnectionEvent::OnDtmfToneChange
pub struct RTCDTMFSender<'a> {
    pub(crate) id: RTCRtpSenderId,
    pub(crate) peer_connection: &'a mut crate::peer_connection::RTCPeerConnection,
}

impl RTCDTMFSender<'_> {
    /// W3C `canInsertDTMF`: whether DTMF can be sent now ("determine if DTMF can be sent":
    /// the connection is connected, the transceiver is not stopping, the sender has a track,
    /// its current direction sends, its first encoding is active, and telephone-event is
    /// negotiated for sending).
    pub fn can_insert_dtmf(&mut self) -> bool {
        self.peer_connection.dtmf_stream(self.id).is_some()
    }

    /// W3C `toneBuffer`: the tones still to be played (upper case).
    pub fn tone_buffer(&self) -> &str {
        self.peer_connection.rtp_transceivers[self.id.0]
            .sender()
            .as_ref()
            .map_or("", |sender| sender.dtmf.tone_buffer.as_str())
    }

    /// W3C `insertDTMF(tones, duration, interToneGap)`: replaces the tone buffer with `tones`
    /// and plays it out, each tone for `duration` (100 ms when `None`; kept within 40 to
    /// 6000 ms) followed by `inter_tone_gap` (70 ms when `None`; kept within 30 to 6000 ms).
    /// `,` is a two-second pause; `a` to `d` are taken as `A` to `D`. An empty `tones` cancels
    /// the tones not yet begun. The first tone begins at `now`, when the connection's
    /// `handle_timeout` runs for it.
    ///
    /// # Errors
    ///
    /// `InvalidStateError` when DTMF cannot be sent ([`Self::can_insert_dtmf`]);
    /// [`Error::ErrDtmfInvalidCharacter`](shared::error::Error::ErrDtmfInvalidCharacter)
    /// (W3C `InvalidCharacterError`) for a character other than those.
    pub fn insert_dtmf(
        &mut self,
        now: Instant,
        tones: &str,
        duration: Option<Duration>,
        inter_tone_gap: Option<Duration>,
    ) -> shared::error::Result<()> {
        if !self.can_insert_dtmf() {
            return Err(shared::error::Error::InvalidStateError);
        }
        let sender = self.peer_connection.rtp_transceivers[self.id.0]
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender");
        sender.dtmf.insert(
            now,
            tones,
            duration.unwrap_or(DTMF_DEFAULT_DURATION),
            inter_tone_gap.unwrap_or(DTMF_DEFAULT_INTER_TONE_GAP),
        )
    }
}

impl crate::peer_connection::RTCPeerConnection {
    /// W3C "determine if DTMF can be sent" for sender `id`, with what to send on when it can:
    /// the negotiated telephone-event codec and the first encoding's SSRC.
    pub(crate) fn dtmf_stream(&mut self, id: RTCRtpSenderId) -> Option<DtmfStream> {
        use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
        use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
        if self.peer_connection_state != RTCPeerConnectionState::Connected {
            return None;
        }
        let media_engine = &self.media_engine;
        let transceiver = self.rtp_transceivers.get_mut(id.0)?;
        if transceiver.stopped()
            || !matches!(
                transceiver.current_direction(),
                RTCRtpTransceiverDirection::Sendrecv | RTCRtpTransceiverDirection::Sendonly
            )
        {
            return None;
        }
        let negotiated_header_extensions = transceiver.negotiated_header_extensions().to_vec();
        let sender = transceiver.sender_mut().as_mut()?;
        if sender.kind() != super::RtpCodecKind::Audio || sender.attached_track().is_none() {
            return None;
        }
        let parameters = sender.get_parameters(media_engine, &negotiated_header_extensions);
        let encoding = parameters.encodings.first()?;
        if !encoding.active {
            return None;
        }
        let ssrc = encoding.rtp_coding_parameters.ssrc?;
        let codecs = &parameters.rtp_parameters.codecs;
        // The telephone-event codec at the audio codec's clock rate when there is one (RFC
        // 7874 section 5: the same rate as the audio), else the first one.
        let audio_rate = codecs
            .iter()
            .find(|c| {
                !c.rtp_codec
                    .mime_type
                    .eq_ignore_ascii_case(MIME_TYPE_TELEPHONE_EVENT)
            })
            .map(|c| c.rtp_codec.clock_rate);
        let telephone_events = || {
            codecs.iter().filter(|c| {
                c.rtp_codec
                    .mime_type
                    .eq_ignore_ascii_case(MIME_TYPE_TELEPHONE_EVENT)
            })
        };
        let codec = telephone_events()
            .find(|c| Some(c.rtp_codec.clock_rate) == audio_rate)
            .or_else(|| telephone_events().next())?;
        Some(DtmfStream {
            payload_type: codec.payload_type,
            clock_rate: codec.rtp_codec.clock_rate,
            ssrc,
        })
    }

    /// The next instant a DTMF sender has something to do.
    pub(crate) fn dtmf_timeout(&self) -> Option<Instant> {
        self.rtp_transceivers
            .iter()
            .filter_map(|t| t.sender().as_ref())
            .filter_map(|sender| sender.dtmf.poll_timeout())
            .min()
    }

    /// Runs every DTMF sender's playout up to `now`: sends the telephone-event packets that are
    /// due and announces the tone changes.
    pub(crate) fn run_dtmf(&mut self, now: Instant) -> shared::error::Result<()> {
        for index in 0..self.rtp_transceivers.len() {
            let due = self.rtp_transceivers[index]
                .sender()
                .as_ref()
                .and_then(|sender| sender.dtmf.poll_timeout())
                .is_some_and(|at| at <= now);
            if !due {
                continue;
            }
            let id = RTCRtpSenderId(index);
            let stream = self.dtmf_stream(id);
            let out = self.rtp_transceivers[index]
                .sender_mut()
                .as_mut()
                .expect("every transceiver has a sender")
                .dtmf
                .run(now, stream);
            for tone in out.tone_changes {
                self.pipeline_context.event_outs.push_back(
                    crate::peer_connection::event::RTCPeerConnectionEvent::OnDtmfToneChange(
                        RTCDTMFToneChangeEvent {
                            sender_id: id,
                            tone,
                        },
                    ),
                );
            }
            for packet in out.packets {
                super::RTCRtpSender {
                    id,
                    peer_connection: self,
                }
                .write_rtp_inner(now, packet, false)?;
            }
        }
        Ok(())
    }
}
