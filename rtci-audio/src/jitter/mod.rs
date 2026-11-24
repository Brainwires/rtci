//! The receive pipeline: an adaptive jitter buffer that decodes, conceals and time-stretches
//! (the equivalent of libwebrtc's NetEq), with the W3C statistics of the inbound audio
//! stream.
//!
//! The caller inserts RTP packets as they arrive ([`JitterBuffer::insert`]) and pulls 10 ms
//! of audio whenever its playout needs it ([`JitterBuffer::pull`]); both take the time from
//! the caller, so a run on a virtual clock is exact. Nothing here reads a clock or starts a
//! thread.
//!
//! # What happens to a packet
//!
//! - It is filed by its (unwrapped) RTP timestamp: reordered packets fall into place, a second
//!   copy of a timestamp is dropped ([`ReceiveStats::packets_duplicated`]), and a packet
//!   older than what has been played is dropped as late ([`ReceiveStats::packets_late`]).
//!   RED packets (RFC 2198) are opened and every block filed, so a redundant copy stands in
//!   for a lost primary.
//! - Its arrival time, against its media time, feeds the delay estimate: the 95th percentile
//!   of how late packets arrive relative to the fastest of the last two seconds, plus one
//!   packet. The target delay is that estimate, or the application's `jitterBufferTarget`
//!   when it set one, clamped to `[max(min_delay, one packet), max_delay]`.
//! - Playout starts, and restarts after DTX, once the buffer holds the target delay of audio
//!   (or its first packet has waited that long).
//!
//! # What playout does every 10 ms
//!
//! - **Normal**: the packet at the playout position is decoded.
//! - **FEC**: when that packet is missing and the next one carries in-band FEC for it (Opus
//!   LBRR, RFC 7587 section 3.3), the missing audio is decoded from there.
//! - **Expand** (concealment): when the packet is missing and cannot be recovered, the codec's
//!   PLC (Opus) or the generic period repetition (G.711, G.722) fills in. While nothing at all
//!   is buffered the playout position does not move (a late packet still plays, a little
//!   later); when a later packet is buffered, concealment covers the gap up to it and playout
//!   resumes there. The return from the generic PLC is cross-faded.
//! - **Accelerate / preemptive expand**: when the filtered buffer level is above the target
//!   (by more than `max(target, low + 20 ms)`) one pitch period of decoded audio is removed;
//!   below `max(3/4 target, target - 85 ms)` one is inserted (see
//!   [`crate::dsp::timestretch`]). This is also how clock drift between the sender's clock
//!   and the playout clock is absorbed: a faster sender fills the buffer, a slower one drains
//!   it.
//! - **DTX / comfort noise**: after an Opus DTX packet (the TOC byte alone) the decoder makes
//!   comfort noise until speech resumes; after an RFC 3389 SID the comfort noise generator
//!   does, with the SID's level and spectrum. Neither counts as concealment.
//!
//! RFC 4733 telephone events are taken out of the stream and reported as
//! [`ReceiveEvent::TelephoneEvent`]; they never reach a decoder (RFC 7874 section 3).

mod delay;
mod expand;

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rtp::codec::comfort_noise::ComfortNoise;
use rtp::codec::red::RedPacket;
use rtp::codec::telephone_event::{TelephoneEventReceiver, TelephoneEventReport};

use crate::codec::AudioDecoder;
use crate::dsp::cng::ComfortNoiseGenerator;
use crate::dsp::level::LevelMeter;
use crate::dsp::resample::MultiResampler;
use crate::dsp::timestretch;
use crate::frame::{AudioFrame, convert_channels};
use crate::{Error, Result};
use delay::DelayManager;
use expand::GenericPlc;

/// How the buffer is set up.
#[derive(Debug, Clone, PartialEq)]
pub struct JitterBufferConfig {
    /// The rate of the audio [`JitterBuffer::pull`] returns.
    pub output_rate: u32,
    /// The channels it returns; `None` for the decoder's.
    pub output_channels: Option<u16>,
    /// The lowest target delay allowed (the W3C "minimum allowed target"); never below one
    /// packet.
    pub min_delay: Duration,
    /// The highest target delay allowed (the W3C "maximum allowed target").
    pub max_delay: Duration,
    /// The application's `jitterBufferTarget`: the delay to aim for instead of the network
    /// estimate. `None` leaves it to the estimate.
    pub target_delay: Option<Duration>,
    /// Packets the buffer holds before it is flushed.
    pub max_packets: usize,
}

impl Default for JitterBufferConfig {
    fn default() -> Self {
        Self {
            output_rate: 48_000,
            output_channels: None,
            min_delay: Duration::ZERO,
            max_delay: Duration::from_secs(2),
            target_delay: None,
            max_packets: 200,
        }
    }
}

/// The receive-side statistics of the stream, as webrtc-stats defines them for
/// `RTCInboundRtpStreamStats` (audio). Sample counts are per channel, at the decoder's rate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReceiveStats {
    /// `totalSamplesReceived`: every sample played out since playout started, concealment
    /// included.
    pub total_samples_received: u64,
    /// `concealedSamples`.
    pub concealed_samples: u64,
    /// `silentConcealedSamples`: concealed samples that are silence (below -60 dBFS).
    pub silent_concealed_samples: u64,
    /// `concealmentEvents`.
    pub concealment_events: u64,
    /// `insertedSamplesForDeceleration`.
    pub inserted_samples_for_deceleration: u64,
    /// `removedSamplesForAcceleration`.
    pub removed_samples_for_acceleration: u64,
    /// `jitterBufferDelay`, seconds: for each emitted sample, its time from the arrival of
    /// its packet to its playout.
    pub jitter_buffer_delay: f64,
    /// `jitterBufferTargetDelay`, seconds: the target delay at each emitted sample's playout.
    pub jitter_buffer_target_delay: f64,
    /// `jitterBufferMinimumDelay`, seconds: the network estimate (without
    /// `jitterBufferTarget`) at each emitted sample's playout.
    pub jitter_buffer_minimum_delay: f64,
    /// `jitterBufferEmittedCount`: samples that came out of the buffer from packets.
    pub jitter_buffer_emitted_count: u64,
    /// `audioLevel` of the played audio.
    pub audio_level: f64,
    /// `totalAudioEnergy` of the played audio.
    pub total_audio_energy: f64,
    /// `totalSamplesDuration`, seconds.
    pub total_samples_duration: f64,
    /// Packets inserted.
    pub packets_received: u64,
    /// Second copies of a timestamp dropped.
    pub packets_duplicated: u64,
    /// Packets that came after their playout time and were dropped (W3C
    /// `packetsDiscarded`).
    pub packets_late: u64,
    /// Packets that could not be decoded (concealed instead).
    pub decode_errors: u64,
    /// Packets that carried in-band FEC (W3C adds these to `fecPacketsReceived`).
    pub fec_packets_received: u64,
    /// Frames recovered from in-band FEC.
    pub fec_frames_recovered: u64,
    /// Packets played from a RED redundant block (their primary was lost).
    pub red_packets_recovered: u64,
    /// Times playout ran dry (concealment with nothing buffered).
    pub underruns: u64,
    /// Times the buffer overflowed and was flushed.
    pub flushes: u64,
}

impl ReceiveStats {
    /// The share of played samples that were concealed.
    pub fn concealment_ratio(&self) -> f64 {
        if self.total_samples_received == 0 {
            0.0
        } else {
            self.concealed_samples as f64 / self.total_samples_received as f64
        }
    }

    /// The mean jitter buffer delay (`jitterBufferDelay / jitterBufferEmittedCount`).
    pub fn mean_delay(&self) -> Option<Duration> {
        (self.jitter_buffer_emitted_count > 0).then(|| {
            Duration::from_secs_f64(
                self.jitter_buffer_delay / self.jitter_buffer_emitted_count as f64,
            )
        })
    }
}

/// Something the buffer reports besides audio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveEvent {
    /// A telephone event (RFC 4733) began, went on or ended.
    TelephoneEvent(TelephoneEventReport),
}

/// What a payload type carries.
enum Format {
    Audio(Box<dyn AudioDecoder>),
    ComfortNoise { clock: u32 },
    TelephoneEvent,
    Red,
}

#[derive(Debug, Clone)]
struct Buffered {
    pt: u8,
    payload: Bytes,
    arrival: Instant,
    marker: bool,
    redundant: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Waiting for the buffer to fill before the first playout.
    Idle,
    Normal,
    Expand,
    /// Opus DTX: the decoder's comfort noise.
    Dtx,
    /// RFC 3389 comfort noise.
    Cng,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Origin {
    /// Decoded from a packet that arrived then.
    Packet(Instant),
    /// Concealment, comfort noise or silence: not emitted from the buffer.
    Synthesized,
}

/// The adaptive jitter buffer and decoder of one audio stream (see the module docs).
pub struct JitterBuffer {
    config: JitterBufferConfig,
    formats: BTreeMap<u8, Format>,
    /// The payload type of the decoder in use.
    active: Option<u8>,
    buffer: BTreeMap<i64, Buffered>,
    last_ts: Option<(u32, i64)>,
    expected: Option<i64>,
    mode: Mode,
    /// RTP units concealed since playout last decoded at `expected`.
    stalled: i64,
    sync: VecDeque<f32>,
    origins: VecDeque<(usize, Origin)>,
    plc: Option<GenericPlc>,
    cng: ComfortNoiseGenerator,
    delay: DelayManager,
    filtered_level: f64,
    packet_secs: f64,
    resampler: Option<MultiResampler>,
    out: VecDeque<f32>,
    level: LevelMeter,
    stats: ReceiveStats,
    events: VecDeque<ReceiveEvent>,
    dtmf: TelephoneEventReceiver,
    last_concealed: bool,
    scratch: Vec<f32>,
}

impl std::fmt::Debug for JitterBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JitterBuffer")
            .field("config", &self.config)
            .field("mode", &self.mode)
            .field("buffered", &self.buffer.len())
            .field("stats", &self.stats)
            .finish()
    }
}

/// Mean square below which concealment counts as silent (-60 dBFS).
const SILENT_POWER: f64 = 1e-6;

impl JitterBuffer {
    /// An empty buffer; register the stream's payload types next.
    pub fn new(config: JitterBufferConfig) -> Self {
        Self {
            config,
            formats: BTreeMap::new(),
            active: None,
            buffer: BTreeMap::new(),
            last_ts: None,
            expected: None,
            mode: Mode::Idle,
            stalled: 0,
            sync: VecDeque::new(),
            origins: VecDeque::new(),
            plc: None,
            cng: ComfortNoiseGenerator::new(0xc0ffee),
            delay: DelayManager::new(),
            filtered_level: 0.0,
            packet_secs: 0.02,
            resampler: None,
            out: VecDeque::new(),
            level: LevelMeter::new(),
            stats: ReceiveStats::default(),
            events: VecDeque::new(),
            dtmf: TelephoneEventReceiver::new(),
            last_concealed: false,
            scratch: Vec::new(),
        }
    }

    /// Decodes payload type `pt` with `decoder`.
    pub fn register_decoder(&mut self, pt: u8, decoder: Box<dyn AudioDecoder>) {
        self.formats.insert(pt, Format::Audio(decoder));
    }

    /// Takes payload type `pt` as RFC 3389 comfort noise at `clock` Hz.
    pub fn register_comfort_noise(&mut self, pt: u8, clock: u32) {
        self.formats.insert(pt, Format::ComfortNoise { clock });
    }

    /// Takes payload type `pt` as RFC 4733 telephone events.
    pub fn register_telephone_event(&mut self, pt: u8) {
        self.formats.insert(pt, Format::TelephoneEvent);
    }

    /// Takes payload type `pt` as RFC 2198 redundant audio.
    pub fn register_red(&mut self, pt: u8) {
        self.formats.insert(pt, Format::Red);
    }

    /// Sets `jitterBufferTarget` (`None` returns the choice to the estimate).
    pub fn set_target_delay(&mut self, target: Option<Duration>) {
        self.config.target_delay = target;
    }

    /// The statistics so far.
    pub fn stats(&self) -> &ReceiveStats {
        &self.stats
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<ReceiveEvent> {
        self.events.pop_front()
    }

    /// The target delay now.
    pub fn target_delay(&self) -> Duration {
        Duration::from_secs_f64(self.target_secs().0)
    }

    /// The audio buffered now (packets and decoded audio not yet played).
    pub fn buffered_delay(&self) -> Duration {
        Duration::from_secs_f64(self.level_secs())
    }

    fn decoder(&self, pt: u8) -> Option<&dyn AudioDecoder> {
        match self.formats.get(&pt) {
            Some(Format::Audio(d)) => Some(d.as_ref()),
            _ => None,
        }
    }

    fn active_decoder(&self) -> Option<&dyn AudioDecoder> {
        self.active.and_then(|pt| self.decoder(pt))
    }

    /// The clock rate of payload type `pt`.
    fn clock(&self, pt: u8) -> Option<u32> {
        match self.formats.get(&pt)? {
            Format::Audio(d) => Some(d.rtp_clock_rate()),
            Format::ComfortNoise { clock } => Some(*clock),
            _ => None,
        }
    }

    fn rate_and_channels(&self) -> (u32, u16) {
        match self.active_decoder() {
            Some(d) => (d.sample_rate(), d.channels()),
            None => (
                self.config.output_rate,
                self.config.output_channels.unwrap_or(1),
            ),
        }
    }

    /// RTP units to samples of the active decoder.
    fn units_to_samples(&self, units: i64) -> usize {
        match self.active_decoder() {
            Some(d) => {
                (units.max(0) as u64 * u64::from(d.sample_rate())
                    / u64::from(d.rtp_clock_rate().max(1))) as usize
            }
            None => units.max(0) as usize,
        }
    }

    fn samples_to_units(&self, samples: usize) -> i64 {
        match self.active_decoder() {
            Some(d) => {
                (samples as u64 * u64::from(d.rtp_clock_rate()) / u64::from(d.sample_rate().max(1)))
                    as i64
            }
            None => samples as i64,
        }
    }

    fn unwrap_ts(&mut self, ts: u32) -> i64 {
        let ext = match self.last_ts {
            None => i64::from(ts),
            Some((last, ext)) => ext + i64::from(ts.wrapping_sub(last) as i32),
        };
        self.last_ts = Some((ts, ext));
        ext
    }

    /// The RTP units a buffered payload spans.
    fn duration_units(&self, b: &Buffered) -> i64 {
        match self.formats.get(&b.pt) {
            Some(Format::Audio(d)) => d
                .packet_samples(&b.payload)
                .map(|s| {
                    (s as u64 * u64::from(d.rtp_clock_rate()) / u64::from(d.sample_rate().max(1)))
                        as i64
                })
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Inserts an RTP packet that arrived at `arrival`.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for a payload type nothing was registered for; malformed RED or
    /// telephone-event payloads are [`Error::Format`].
    pub fn insert(
        &mut self,
        arrival: Instant,
        header: &rtp::header::Header,
        payload: &Bytes,
    ) -> Result<()> {
        self.stats.packets_received += 1;
        match self.formats.get(&header.payload_type) {
            None => Err(Error::Unsupported(format!(
                "payload type {}",
                header.payload_type
            ))),
            Some(Format::TelephoneEvent) => {
                let reports = self
                    .dtmf
                    .receive(header.timestamp, header.marker, payload)
                    .map_err(|e| Error::Format(e.to_string()))?;
                self.events
                    .extend(reports.into_iter().map(ReceiveEvent::TelephoneEvent));
                Ok(())
            }
            Some(Format::Red) => {
                let red = RedPacket::parse(payload).map_err(|e| Error::Format(e.to_string()))?;
                // The primary first (it counts for the delay estimate), then the older copies.
                let primary = red.primary();
                self.insert_media(
                    arrival,
                    header.timestamp,
                    primary.payload_type,
                    primary.data.clone(),
                    header.marker,
                    false,
                );
                for block in red.redundant().iter().filter(|b| b.timestamp_offset != 0) {
                    self.insert_media(
                        arrival,
                        block.timestamp(header.timestamp),
                        block.payload_type,
                        block.data.clone(),
                        false,
                        true,
                    );
                }
                Ok(())
            }
            Some(_) => {
                self.insert_media(
                    arrival,
                    header.timestamp,
                    header.payload_type,
                    payload.clone(),
                    header.marker,
                    false,
                );
                Ok(())
            }
        }
    }

    fn insert_media(
        &mut self,
        arrival: Instant,
        ts: u32,
        pt: u8,
        payload: Bytes,
        marker: bool,
        redundant: bool,
    ) {
        if !matches!(
            self.formats.get(&pt),
            Some(Format::Audio(_) | Format::ComfortNoise { .. })
        ) || payload.is_empty()
        {
            return;
        }
        let ext = self.unwrap_ts(ts);
        let comfort = matches!(self.mode, Mode::Dtx | Mode::Cng);
        if let Some(exp) = self.expected
            && ext < exp
            && !comfort
        {
            if !redundant {
                self.stats.packets_late += 1;
            }
            return;
        }
        if self.buffer.contains_key(&ext) {
            if !redundant {
                self.stats.packets_duplicated += 1;
            }
            return;
        }
        let b = Buffered {
            pt,
            payload,
            arrival,
            marker,
            redundant,
        };
        if !redundant {
            if let Some(clock) = self.clock(pt) {
                self.delay
                    .update(arrival, ext as f64 / f64::from(clock.max(1)));
            }
            if let Some(d) = self.decoder(pt) {
                let fec = d.fec_samples(&b.payload).is_some();
                let packet = d
                    .packet_samples(&b.payload)
                    .filter(|&s| s > 0 && !d.is_dtx(&b.payload))
                    .map(|s| s as f64 / f64::from(d.sample_rate().max(1)));
                if fec {
                    self.stats.fec_packets_received += 1;
                }
                if let Some(p) = packet {
                    self.packet_secs = p;
                }
            }
        }
        self.buffer.insert(ext, b);
        if self.buffer.len() > self.config.max_packets {
            // Overflow: keep the newest packet and start over from it.
            self.stats.flushes += 1;
            let last = self.buffer.pop_last();
            self.buffer.clear();
            if let Some((k, v)) = last {
                self.buffer.insert(k, v);
            }
            self.expected = None;
            self.mode = Mode::Idle;
        }
    }

    /// The target delay and the network-only minimum, in seconds.
    fn target_secs(&self) -> (f64, f64) {
        let packet = self.packet_secs.max(0.0025);
        // At least a packet plus one 10 ms pull: below that the playout runs dry between
        // two packets on a clean link.
        let floor = self.config.min_delay.as_secs_f64().max(packet + 0.010);
        let ceiling = self.config.max_delay.as_secs_f64().max(floor);
        // The jitter, a packet and a 10 ms pull.
        let estimate = (self.delay.jitter_estimate() + packet + 0.010).clamp(floor, ceiling);
        let target = self
            .config
            .target_delay
            .map(|t| t.as_secs_f64())
            .unwrap_or(estimate)
            .clamp(floor, ceiling);
        (target, estimate)
    }

    /// Seconds of audio from `from` to the end of the run of contiguous packets.
    fn buffered_from(&self, from: i64) -> f64 {
        let mut end = from;
        let mut secs = 0.0;
        for (&ts, b) in self.buffer.range(from..) {
            if ts > end + 1 && secs > 0.0 {
                break;
            }
            let units = self.duration_units(b);
            let clock = self.clock(b.pt).unwrap_or(48_000);
            secs += units as f64 / f64::from(clock.max(1));
            end = ts + units;
        }
        secs
    }

    /// Seconds buffered: packets at or after the playout position plus decoded audio.
    fn level_secs(&self) -> f64 {
        let (rate, ch) = self.rate_and_channels();
        let sync = self.sync.len() as f64 / f64::from(ch.max(1)) / f64::from(rate.max(1));
        let mut packets = 0.0;
        let from = self.expected.unwrap_or(i64::MIN);
        for b in self.buffer.range(from..).map(|(_, b)| b) {
            let clock = self.clock(b.pt).unwrap_or(48_000);
            packets += self.duration_units(b) as f64 / f64::from(clock.max(1));
        }
        sync + packets
    }

    /// Whether playout may start (or resume after comfort noise) at the packet at `ts`.
    fn prefetch_done(&self, now: Instant, ts: i64) -> bool {
        let Some(b) = self.buffer.get(&ts) else {
            return false;
        };
        let target = self.target_secs().0;
        self.buffered_from(ts) + 1e-9 >= target
            || now.saturating_duration_since(b.arrival).as_secs_f64() + 1e-9 >= target
    }

    /// The next 10 ms of audio at the output rate and channels.
    pub fn pull(&mut self, now: Instant) -> AudioFrame {
        let out_rate = self.config.output_rate;
        let out_ch = self
            .config
            .output_channels
            .or_else(|| self.active_decoder().map(|d| d.channels()))
            .unwrap_or(1);
        let need = crate::frame::frame_samples(out_rate) * usize::from(out_ch);
        let mut started = self.mode != Mode::Idle;
        while self.out.len() < need {
            let chunk = self.produce(now);
            started |= self.mode != Mode::Idle;
            let (rate, ch) = self.rate_and_channels();
            self.scratch.clear();
            if convert_channels(&chunk, ch, out_ch, &mut self.scratch).is_err() {
                self.scratch.resize(
                    chunk.len() / usize::from(ch.max(1)) * usize::from(out_ch),
                    0.0,
                );
            }
            if rate == out_rate {
                self.out.extend(self.scratch.iter().copied());
            } else {
                let rebuild = self
                    .resampler
                    .as_ref()
                    .is_none_or(|r| r.from_rate() != rate || r.channels() != out_ch);
                if rebuild {
                    self.resampler = Some(MultiResampler::new(rate, out_rate, out_ch));
                }
                let mut resampled = Vec::new();
                if let Some(r) = self.resampler.as_mut() {
                    r.process(&self.scratch, &mut resampled);
                }
                self.out.extend(resampled);
            }
        }
        let samples: Vec<f32> = self.out.drain(..need).collect();
        if started {
            self.level.process(&samples, out_ch, out_rate);
            self.stats.audio_level = self.level.audio_level();
            self.stats.total_audio_energy = self.level.total_audio_energy();
            self.stats.total_samples_duration = self.level.total_samples_duration();
        }
        AudioFrame {
            samples,
            sample_rate: out_rate,
            channels: out_ch,
        }
    }

    /// 10 ms at the decoder's rate and channels.
    fn produce(&mut self, now: Instant) -> Vec<f32> {
        let level = self.level_secs();
        self.filtered_level = 0.98 * self.filtered_level + 0.02 * level;
        let (rate, ch) = self.rate_and_channels();
        let n = crate::frame::frame_samples(rate) * usize::from(ch);
        self.time_stretch(now);
        let mut guard = 0;
        while self.sync.len() < n && guard < 64 {
            guard += 1;
            if !self.step(now) {
                break;
            }
            // The decoder (and so the rate) can change on the first packet.
            if self.rate_and_channels() != (rate, ch) {
                break;
            }
        }
        let (rate2, ch2) = self.rate_and_channels();
        let n = crate::frame::frame_samples(rate2) * usize::from(ch2);
        if self.sync.len() < n {
            let missing = n - self.sync.len();
            self.push(&vec![0.0; missing], Origin::Synthesized);
        }
        let out: Vec<f32> = self.sync.drain(..n).collect();
        self.account_output(now, n / usize::from(ch2.max(1)));
        out
    }

    /// Counts `samples` per channel leaving the buffer for playout.
    fn account_output(&mut self, now: Instant, mut samples: usize) {
        let started = self.mode != Mode::Idle;
        if started {
            self.stats.total_samples_received += samples as u64;
        }
        let (target, minimum) = self.target_secs();
        while samples > 0 {
            let Some((count, origin)) = self.origins.front_mut() else {
                break;
            };
            let take = (*count).min(samples);
            if let Origin::Packet(arrival) = *origin {
                let d = now.saturating_duration_since(arrival).as_secs_f64();
                self.stats.jitter_buffer_delay += d * take as f64;
                self.stats.jitter_buffer_target_delay += target * take as f64;
                self.stats.jitter_buffer_minimum_delay += minimum * take as f64;
                self.stats.jitter_buffer_emitted_count += take as u64;
            }
            *count -= take;
            samples -= take;
            if *count == 0 {
                self.origins.pop_front();
            }
        }
    }

    fn push(&mut self, samples: &[f32], origin: Origin) {
        let (_, ch) = self.rate_and_channels();
        let per_channel = samples.len() / usize::from(ch.max(1));
        if per_channel == 0 {
            return;
        }
        self.sync.extend(samples.iter().copied());
        match self.origins.back_mut() {
            Some((count, o)) if *o == origin => *count += per_channel,
            _ => self.origins.push_back((per_channel, origin)),
        }
    }

    fn count_concealment(&mut self, samples: &[f32], per_channel: usize) {
        self.stats.concealed_samples += per_channel as u64;
        let power = if samples.is_empty() {
            0.0
        } else {
            samples.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / samples.len() as f64
        };
        if power < SILENT_POWER {
            self.stats.silent_concealed_samples += per_channel as u64;
        }
        if !self.last_concealed {
            self.stats.concealment_events += 1;
        }
        self.last_concealed = true;
    }

    /// Conceals `units` of RTP time (at most 10 ms of it).
    fn conceal(&mut self, units: i64) {
        let samples = self.units_to_samples(units).max(1);
        let mut out = Vec::new();
        let mut done = false;
        if let Some(pt) = self.active
            && let Some(Format::Audio(d)) = self.formats.get_mut(&pt)
            && d.has_plc()
        {
            done = d.conceal(samples, &mut out).unwrap_or(false);
            if !done {
                out.clear();
            }
        }
        if !done {
            let (rate, ch) = self.rate_and_channels();
            let plc = self.plc.get_or_insert_with(|| GenericPlc::new(rate, ch));
            plc.conceal(samples, &mut out);
        }
        self.count_concealment(&out, samples);
        if self.mode != Mode::Expand {
            if self
                .buffer
                .range(self.expected.unwrap_or(i64::MIN)..)
                .next()
                .is_none()
            {
                self.stats.underruns += 1;
            }
            self.mode = Mode::Expand;
        }
        self.push(&out, Origin::Synthesized);
    }

    /// 10 ms of comfort noise (DTX or RFC 3389), advancing the playout position.
    fn comfort_noise(&mut self) {
        let (rate, ch) = self.rate_and_channels();
        let samples = crate::frame::frame_samples(rate);
        let mut out = Vec::new();
        if self.mode == Mode::Dtx
            && let Some(pt) = self.active
            && let Some(Format::Audio(d)) = self.formats.get_mut(&pt)
            && d.conceal(samples, &mut out).unwrap_or(false)
        {
        } else {
            out.clear();
            let mut mono = vec![0.0f32; samples];
            self.cng.generate(&mut mono);
            let _ = convert_channels(&mono, 1, ch, &mut out);
        }
        self.last_concealed = false;
        let units = self.samples_to_units(samples);
        if let Some(e) = self.expected.as_mut() {
            *e += units;
        }
        self.push(&out, Origin::Synthesized);
    }

    /// Makes some audio into the sync buffer. False when nothing could be made.
    fn step(&mut self, now: Instant) -> bool {
        if self.mode == Mode::Idle {
            let Some(&first) = self.buffer.keys().next() else {
                return false;
            };
            if !self.prefetch_done(now, first) {
                return false;
            }
            self.expected = Some(first);
            self.mode = Mode::Normal;
            self.filtered_level = self.level_secs();
        }
        let Some(exp) = self.expected else {
            return false;
        };
        let comfort = matches!(self.mode, Mode::Dtx | Mode::Cng);
        if !comfort {
            // Drop what playout has passed.
            let stale: Vec<i64> = self.buffer.range(..exp).map(|(k, _)| *k).collect();
            for k in stale {
                if let Some(b) = self.buffer.remove(&k)
                    && !b.redundant
                {
                    self.stats.packets_late += 1;
                }
            }
        }
        let next = self.buffer.keys().next().copied();
        match next {
            Some(ts) if comfort => {
                if ts == exp || self.prefetch_done(now, ts) {
                    self.expected = Some(ts);
                    self.decode_at(now, ts);
                    self.filtered_level = self.level_secs();
                } else {
                    self.comfort_noise();
                }
            }
            Some(ts) if ts <= exp => self.decode_at(now, ts),
            Some(ts) => {
                let gap = ts - exp;
                let (marker, clock) = self
                    .buffer
                    .get(&ts)
                    .map(|b| (b.marker, self.clock(b.pt).unwrap_or(48_000)))
                    .unwrap_or((false, 48_000));
                let discontinuity =
                    gap > (self.config.max_delay.as_secs_f64() * f64::from(clock)) as i64;
                if (marker && self.prefetch_done(now, ts)) || discontinuity {
                    // A new talkspurt after the sender's silence, or a discontinuity.
                    self.expected = Some(ts);
                    self.stalled = 0;
                    self.decode_at(now, ts);
                } else if self.stalled < gap && self.try_fec(ts, gap) {
                    // Recovered: what was concealed while waiting stays as added delay.
                    self.stalled = 0;
                } else if self.stalled >= gap {
                    self.expected = Some(ts);
                    self.stalled = 0;
                    self.decode_at(now, ts);
                } else {
                    let ten_ms = self
                        .samples_to_units(crate::frame::frame_samples(self.rate_and_channels().0));
                    let units = (gap - self.stalled).min(ten_ms.max(1));
                    self.conceal(units);
                    self.stalled += units;
                }
            }
            None if comfort => self.comfort_noise(),
            None => {
                let ten_ms =
                    self.samples_to_units(crate::frame::frame_samples(self.rate_and_channels().0));
                self.conceal(ten_ms.max(1));
                self.stalled += ten_ms.max(1);
            }
        }
        true
    }

    /// Recovers the `gap` before the packet at `ts` from its in-band FEC.
    fn try_fec(&mut self, ts: i64, gap: i64) -> bool {
        let Some(b) = self.buffer.get(&ts).cloned() else {
            return false;
        };
        if Some(b.pt) != self.active {
            return false;
        }
        let samples = self.units_to_samples(gap);
        let Some(Format::Audio(d)) = self.formats.get_mut(&b.pt) else {
            return false;
        };
        if d.fec_samples(&b.payload) != Some(samples) {
            return false;
        }
        let mut out = Vec::new();
        if !d.decode_fec(&b.payload, samples, &mut out).unwrap_or(false) {
            return false;
        }
        self.stats.fec_frames_recovered += 1;
        self.last_concealed = false;
        self.mode = Mode::Normal;
        self.expected = Some(ts);
        self.push(&out, Origin::Packet(b.arrival));
        true
    }

    /// Decodes the packet at `ts` (the playout position).
    fn decode_at(&mut self, _now: Instant, ts: i64) {
        let Some(b) = self.buffer.remove(&ts) else {
            return;
        };
        self.stalled = 0;
        match self.formats.get(&b.pt) {
            Some(Format::ComfortNoise { .. }) => {
                let mut bytes = b.payload.clone();
                if let Ok(cn) = <ComfortNoise as shared::marshal::Unmarshal>::unmarshal(&mut bytes)
                {
                    self.cng.update(&cn);
                }
                self.mode = Mode::Cng;
                self.last_concealed = false;
                return;
            }
            Some(Format::Audio(_)) => {}
            _ => return,
        }
        if self.active != Some(b.pt) {
            // A new decoder: its own state and rate.
            let before = self.rate_and_channels();
            if let Some(Format::Audio(d)) = self.formats.get_mut(&b.pt) {
                d.reset();
            }
            self.active = Some(b.pt);
            self.plc = None;
            if self.rate_and_channels() != before {
                self.sync.clear();
                self.origins.clear();
            }
        }
        let Some(Format::Audio(d)) = self.formats.get_mut(&b.pt) else {
            return;
        };
        let dtx = d.is_dtx(&b.payload);
        let mut out = Vec::new();
        let decoded = d.decode(&b.payload, &mut out);
        let units = match decoded {
            Ok(n) => {
                (n as u64 * u64::from(d.rtp_clock_rate()) / u64::from(d.sample_rate().max(1)))
                    as i64
            }
            Err(_) => 0,
        };
        if decoded.is_err() || units == 0 {
            self.stats.decode_errors += 1;
            let units = self.duration_units(&b).max(
                self.samples_to_units(crate::frame::frame_samples(self.rate_and_channels().0)),
            );
            self.conceal(units);
            if let Some(e) = self.expected.as_mut() {
                *e = ts + units;
            }
            return;
        }
        if b.redundant {
            self.stats.red_packets_recovered += 1;
        }
        if !d.has_plc() {
            let (rate, ch) = (d.sample_rate(), d.channels());
            let plc = self.plc.get_or_insert_with(|| GenericPlc::new(rate, ch));
            if plc.is_active() {
                plc.merge_into(&mut out);
            }
            plc.push_history(&out);
        }
        self.expected = Some(ts + units);
        self.last_concealed = false;
        self.mode = if dtx { Mode::Dtx } else { Mode::Normal };
        self.push(&out, Origin::Packet(b.arrival));
    }

    /// Accelerates or preemptively expands the decoded audio when the buffer level is off
    /// target.
    fn time_stretch(&mut self, now: Instant) {
        if self.mode != Mode::Normal {
            return;
        }
        let (target, _) = self.target_secs();
        let low = (0.75 * target).max(target - 0.085);
        let high = target.max(low + 0.020);
        // The level is a sawtooth (a packet in, then 10 ms out at a time): its mean is half a
        // packet below its peak, which is what the target is about.
        let level = self.filtered_level + self.packet_secs / 2.0;
        let accelerate = level > high;
        let expand = level < low && !self.buffer.is_empty();
        if !accelerate && !expand {
            return;
        }
        let (rate, ch) = self.rate_and_channels();
        let need = timestretch::required_input(rate) * usize::from(ch);
        // Decode ahead while the next packet is at the playout position.
        let mut guard = 0;
        while self.sync.len() < need && guard < 16 {
            guard += 1;
            let Some(exp) = self.expected else { return };
            if self.buffer.keys().next() != Some(&exp) {
                break;
            }
            self.decode_at(now, exp);
            if self.mode != Mode::Normal || self.rate_and_channels() != (rate, ch) {
                return;
            }
        }
        if self.sync.len() < need {
            return;
        }
        // Only decoded audio is stretched.
        let span = timestretch::required_input(rate);
        let mut decoded = 0;
        for (count, origin) in &self.origins {
            if !matches!(origin, Origin::Packet(_)) {
                break;
            }
            decoded += count;
        }
        if decoded < span {
            return;
        }
        let input: Vec<f32> = self.sync.drain(..span * usize::from(ch)).collect();
        let mut out = Vec::with_capacity(input.len() * 3 / 2);
        let result = if accelerate {
            timestretch::accelerate(&input, ch, rate, &mut out)
        } else {
            timestretch::preemptive_expand(&input, ch, rate, &mut out)
        };
        for s in out.iter().rev() {
            self.sync.push_front(*s);
        }
        if let Some(s) = result {
            let secs = s.lag as f64 / f64::from(rate);
            if accelerate {
                self.stats.removed_samples_for_acceleration += s.lag as u64;
                self.filtered_level -= secs;
                self.adjust_origins(-(s.lag as i64));
            } else {
                self.stats.inserted_samples_for_deceleration += s.lag as u64;
                self.filtered_level += secs;
                self.adjust_origins(s.lag as i64);
            }
        }
    }

    /// Moves the front origin records by `delta` samples per channel after a stretch.
    fn adjust_origins(&mut self, delta: i64) {
        if delta >= 0 {
            if let Some((count, _)) = self.origins.front_mut() {
                *count += delta as usize;
            }
            return;
        }
        let mut left = (-delta) as usize;
        while left > 0 {
            let Some((count, _)) = self.origins.front_mut() else {
                break;
            };
            let take = (*count).min(left);
            *count -= take;
            left -= take;
            if *count == 0 {
                self.origins.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod jitter_test;
