//! Jitter Buffer Interceptor
//!
//! A receiver-side interceptor that buffers incoming RTP packets and releases
//! them in sequence order after an adaptive playout delay.
//!
//! # Algorithm
//!
//! The target playout delay adapts to observed interarrival jitter using the
//! RFC 3550 §A.8 formula: `target = clamp(jitter / clock_rate × 3, min, max)`.
//! The ×3 factor covers ~99.7% of the jitter spread under a Gaussian model.
//!
//! If the sender includes a `playout-delay` RTP header extension, its
//! `min_delay` and `max_delay` values (in 10 ms increments) are applied as
//! bounds on the adaptive target.
//!
//! # Placement in the interceptor chain
//!
//! The jitter buffer should be the **outermost** interceptor so that all inner
//! interceptors (NACK generator, receiver-report, TWCC) still observe every
//! packet in its eventually-correct order:
//!
//! ```text
//! JitterBuffer → NackGenerator → ReceiverReport → TwccReceiver → Noop
//! ```
//!
//! # Usage
//!
//! [`JitterBufferBuilder::build`] returns a factory closure for
//! [`Interceptor::with`](crate::Interceptor::with) around a
//! [`PassThroughInterceptor`](crate::PassThroughInterceptor), in
//! [`Slot::JitterBuffer`](crate::Slot::JitterBuffer). The compiled example is on the builder
//! (exported as `AdaptiveJitterBufferBuilder`; this module is not public).

use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket, interceptor};
use log::error;
use shared::error::Error;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

mod stream;
use stream::{JitterBufferStream, PLAYOUT_DELAY_URI};

/// The application's jitter buffer target for the streams of one receiver (W3C webrtc 5.3
/// `jitterBufferTarget`): written into the chain ([`into_packet`](Self::into_packet)), the
/// jitter buffer takes it for each SSRC, now or when the stream is bound, and holds those
/// streams' packets for `target` clamped to its minimum and maximum delay instead of its
/// adaptive target; `None` returns them to the adaptive target. Consumed by the jitter
/// buffer; without one in the chain it reaches the terminus and is dropped there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitterBufferControl {
    /// The SSRCs the target is for.
    pub ssrcs: Vec<u32>,
    /// The target delay, or `None` for no preference.
    pub target: Option<Duration>,
}

impl JitterBufferControl {
    /// The packet that carries this to the jitter buffer when written into the chain at
    /// `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: shared::TransportContext::default(),
            message: crate::AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(crate::Attribute::Custom(std::sync::Arc::new(self))),
        }
    }
}

/// Builder for [`JitterBufferInterceptor`] (exported as `AdaptiveJitterBufferBuilder` and
/// `AdaptiveJitterBufferInterceptor`).
///
/// [`build`](Self::build) returns a factory: a closure that takes the inner interceptor and
/// returns the jitter buffer around it. Apply it with
/// [`Interceptor::with`](crate::Interceptor::with) to a
/// [`PassThroughInterceptor`](crate::PassThroughInterceptor) (never a
/// [`NoopInterceptor`](crate::NoopInterceptor): that is the chain's RTCP terminus, and inside
/// this slot it would end the inbound RTCP of every slot after it), and put the result in
/// [`Slot::JitterBuffer`](crate::Slot::JitterBuffer), the application-most position:
///
/// ```
/// use rtci_interceptor::{
///     AdaptiveJitterBufferBuilder, Interceptor, PassThroughInterceptor, Registry, Slot,
/// };
/// use std::time::Duration;
///
/// let jitter = PassThroughInterceptor::new().with(
///     AdaptiveJitterBufferBuilder::new()
///         .with_min_delay(Duration::from_millis(20))
///         .with_max_delay(Duration::from_millis(500))
///         .with_initial_delay(Duration::from_millis(50))
///         .build(),
/// );
/// let chain = Registry::new().with(Slot::JitterBuffer, jitter).build();
/// # let _ = chain;
/// ```
pub struct JitterBufferBuilder<P> {
    min_delay: Duration,
    max_delay: Duration,
    initial_delay: Duration,
    _phantom: PhantomData<P>,
}

impl<P> Default for JitterBufferBuilder<P> {
    fn default() -> Self {
        Self {
            min_delay: Duration::from_millis(20),
            max_delay: Duration::from_millis(500),
            initial_delay: Duration::from_millis(50),
            _phantom: PhantomData,
        }
    }
}

impl<P> JitterBufferBuilder<P> {
    /// Creates a builder with the default delays.
    pub fn new() -> Self {
        Self::default()
    }

    /// Minimum playout delay floor (default 20 ms).
    pub fn with_min_delay(mut self, d: Duration) -> Self {
        self.min_delay = d;
        self
    }

    /// Maximum playout delay / force-release ceiling (default 500 ms).
    pub fn with_max_delay(mut self, d: Duration) -> Self {
        self.max_delay = d;
        self
    }

    /// Starting target delay before enough packets have been seen to estimate jitter
    /// (default 50 ms).
    pub fn with_initial_delay(mut self, d: Duration) -> Self {
        self.initial_delay = d;
        self
    }

    /// The interceptor factory: a closure that takes the inner interceptor `P` and returns
    /// the [`JitterBufferInterceptor`] around it, for
    /// [`Interceptor::with`](crate::Interceptor::with).
    pub fn build(self) -> impl FnOnce(P) -> JitterBufferInterceptor<P> {
        move |inner| JitterBufferInterceptor {
            inner,
            min_delay: self.min_delay,
            max_delay: self.max_delay,
            initial_delay: self.initial_delay,
            streams: HashMap::new(),
            targets: HashMap::new(),
            last_now: None,
        }
    }
}

/// Receiver-side jitter buffer interceptor.
///
/// Buffers incoming RTP packets per SSRC and releases them in sequence order
/// after an adaptive playout delay. RTCP packets and packets from unbound
/// SSRCs are forwarded immediately without buffering.
#[derive(Interceptor)]
pub struct JitterBufferInterceptor<P> {
    #[next]
    inner: P,

    min_delay: Duration,
    max_delay: Duration,
    initial_delay: Duration,

    /// Per-SSRC jitter buffer state, created in `bind_remote_stream`.
    streams: HashMap<u32, JitterBufferStream>,

    /// The application's target of each SSRC that has one ([`JitterBufferControl`]), for
    /// the streams bound later too.
    targets: HashMap<u32, Duration>,

    /// Monotonic timestamp tracked from `handle_read` / `handle_timeout` calls,
    /// used by `poll_read` instead of `Instant::now()` to avoid wall-clock dependency.
    last_now: Option<Instant>,
}

#[interceptor]
impl<P: Interceptor> JitterBufferInterceptor<P> {
    /// Buffer incoming RTP for tracked SSRCs; pass everything else through immediately.
    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Track the latest timestamp for use by poll_read.
        self.last_now = Some(msg.now);
        if let Packet::Rtp(ref rtp) = msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp.header.ssrc)
        {
            // insert() returns false for already-released sequences or duplicates; drop those.
            stream.insert(msg.now, msg);
            return Ok(());
        }
        // RTCP, or RTP from an unbound SSRC → forward without delay.
        self.inner.handle_read(msg)
    }

    /// A [`JitterBufferControl`] is taken here, not passed on; anything else goes on.
    #[overrides]
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Some(control) = msg.message.custom::<JitterBufferControl>() {
            for &ssrc in &control.ssrcs {
                match control.target {
                    Some(target) => self.targets.insert(ssrc, target),
                    None => self.targets.remove(&ssrc),
                };
                if let Some(stream) = self.streams.get_mut(&ssrc) {
                    stream.set_application_target(control.target);
                }
            }
            return Ok(());
        }
        self.inner.handle_write(msg)
    }

    /// Flush ready buffered packets into the inner chain, then poll the inner chain.
    ///
    /// Uses the latest timestamp seen from `handle_read`/`handle_timeout` rather
    /// than `Instant::now()`, so the interceptor stays deterministic and avoids
    /// panics when buffered arrivals are in the future relative to wall-clock time.
    #[overrides]
    fn poll_read(&mut self) -> Option<Self::Rout> {
        if let Some(now) = self.last_now {
            self.drain_ready(now);
        }
        self.inner.poll_read()
    }

    /// Drain ready packets on each timer tick so buffers don't stall between app polls.
    #[overrides]
    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        self.last_now = Some(now);
        self.drain_ready(now);
        self.inner.handle_timeout(now)
    }

    /// Return the earliest scheduled release time so the driver wakes at the right moment.
    #[overrides]
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        let buf_eto = self
            .streams
            .values()
            .filter_map(|s| s.next_wake_time())
            .min();
        let inner_eto = self.inner.poll_timeout();
        match (buf_eto, inner_eto) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, b) => b,
        }
    }

    /// Create a per-SSRC buffer when a remote stream is bound.
    #[overrides]
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        let ext_id = info
            .rtp_header_extensions
            .iter()
            .find(|e| e.uri == PLAYOUT_DELAY_URI)
            .map(|e| e.id as u8);

        let mut stream = JitterBufferStream::new(
            info.clock_rate,
            ext_id,
            self.initial_delay,
            self.min_delay,
            self.max_delay,
        );
        stream.set_application_target(self.targets.get(&info.ssrc).copied());
        self.streams.insert(info.ssrc, stream);
        self.inner.bind_remote_stream(info);
    }

    /// Drop the per-SSRC buffer when a remote stream is unbound.
    #[overrides]
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
        self.inner.unbind_remote_stream(info);
    }
}

impl<P: Interceptor> JitterBufferInterceptor<P> {
    /// Collect ready packets from all streams and inject them into the inner chain.
    ///
    /// We collect first to satisfy the borrow checker: `streams` and `inner`
    /// are separate fields but both require `&mut self`.
    fn drain_ready(&mut self, now: Instant) {
        let mut ready = Vec::new();
        for stream in self.streams.values_mut() {
            while let Some(pkt) = stream.pop_ready(now) {
                ready.push(pkt);
            }
        }
        for pkt in ready {
            if let Err(e) = self.inner.handle_read(pkt) {
                error!("jitter_buffer: inner.handle_read error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttributedPacket;
    use crate::{PassThroughInterceptor, Registry, Slot, stream_info::StreamInfo};
    use sansio::Protocol;
    use shared::{TransportContext, TransportMessage};

    fn make_stream_info(ssrc: u32, clock_rate: u32) -> StreamInfo {
        StreamInfo {
            ssrc,
            clock_rate,
            ..Default::default()
        }
    }

    fn make_rtp_at(ssrc: u32, seq: u16, ts: u32, now: Instant) -> TaggedPacket {
        TransportMessage {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc,
                    sequence_number: seq,
                    timestamp: ts,
                    ..Default::default()
                },
                ..Default::default()
            })),
        }
    }

    fn make_rtcp(ssrc: u32) -> TaggedPacket {
        TransportMessage {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                rtcp::receiver_report::ReceiverReport {
                    ssrc,
                    ..Default::default()
                },
            )])),
        }
    }

    /// Build a chain with a short initial delay for testing.
    fn make_chain(initial_ms: u64, max_ms: u64) -> impl crate::Interceptor {
        Registry::new()
            .with(
                Slot::JitterBuffer,
                PassThroughInterceptor::new().with(
                    JitterBufferBuilder::new()
                        .with_min_delay(Duration::from_millis(initial_ms))
                        .with_max_delay(Duration::from_millis(max_ms))
                        .with_initial_delay(Duration::from_millis(initial_ms))
                        .build(),
                ),
            )
            .build()
    }

    #[test]
    fn test_in_order_packets_released_after_delay() {
        let mut chain = make_chain(50, 500);
        let ssrc = 1111;
        chain.bind_remote_stream(&make_stream_info(ssrc, 90000));

        let base = Instant::now();
        for i in 0..3u16 {
            chain
                .handle_read(make_rtp_at(ssrc, i + 1, i as u32 * 3000, base))
                .unwrap();
        }

        // Before delay has elapsed — nothing ready.
        chain.handle_timeout(base).unwrap();
        assert!(chain.poll_read().is_none());

        // After delay has elapsed — packets should be available.
        chain
            .handle_timeout(base + Duration::from_millis(100))
            .unwrap();
        let mut released = 0u16;
        while chain.poll_read().is_some() {
            released += 1;
        }
        assert_eq!(released, 3);
    }

    #[test]
    fn test_out_of_order_reordered() {
        let mut chain = make_chain(50, 500);
        let ssrc = 2222;
        chain.bind_remote_stream(&make_stream_info(ssrc, 90000));

        let base = Instant::now();
        // Arrive as seq 1, 3, 2.
        chain.handle_read(make_rtp_at(ssrc, 1, 0, base)).unwrap();
        chain.handle_read(make_rtp_at(ssrc, 3, 6000, base)).unwrap();
        chain.handle_read(make_rtp_at(ssrc, 2, 3000, base)).unwrap();

        // Release all after the delay.
        chain
            .handle_timeout(base + Duration::from_millis(100))
            .unwrap();

        let mut seqs = Vec::new();
        while let Some(pkt) = chain.poll_read() {
            if let Packet::Rtp(rtp) = pkt.message.packet {
                seqs.push(rtp.header.sequence_number);
            }
        }
        // Must come out in sequence order.
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn test_force_release_at_max_delay() {
        let initial_ms = 50u64;
        let max_ms = 200u64;
        let mut chain = make_chain(initial_ms, max_ms);
        let ssrc = 3333;
        chain.bind_remote_stream(&make_stream_info(ssrc, 90000));

        let base = Instant::now();
        // Insert seq 1; seq 2 never arrives.
        chain.handle_read(make_rtp_at(ssrc, 1, 0, base)).unwrap();

        // At max_delay + 1ms: seq 1 must be force-released even without seq 2.
        let force_time = base + Duration::from_millis(max_ms + 1);
        chain.handle_timeout(force_time).unwrap();
        assert!(
            chain.poll_read().is_some(),
            "seq 1 should be force-released"
        );
    }

    #[test]
    fn test_rtcp_passes_through_immediately() {
        let mut chain = make_chain(50, 500);
        let ssrc = 4444;
        chain.bind_remote_stream(&make_stream_info(ssrc, 90000));

        chain.handle_read(make_rtcp(ssrc)).unwrap();
        // RTCP bypasses the buffer and should be visible to the inner chain.
        // (The noop inner doesn't surface it, but the call must not hang or panic.)
        // Verify by checking that poll_read doesn't return a buffered item.
        chain.handle_timeout(Instant::now()).unwrap();
        assert!(chain.poll_read().is_none());
    }

    #[test]
    fn test_unbind_clears_buffer() {
        let initial_ms = 50u64;
        let mut chain = make_chain(initial_ms, 500);
        let ssrc = 5555;
        let info = make_stream_info(ssrc, 90000);
        chain.bind_remote_stream(&info);

        let base = Instant::now();
        chain.handle_read(make_rtp_at(ssrc, 1, 0, base)).unwrap();

        // Unbind before the delay expires.
        chain.unbind_remote_stream(&info);

        // After the delay, nothing is released (buffer was dropped).
        chain
            .handle_timeout(base + Duration::from_millis(100))
            .unwrap();
        assert!(chain.poll_read().is_none());
    }

    #[test]
    fn test_unbound_ssrc_passes_through() {
        let mut chain = make_chain(50, 500);
        // Do NOT bind any stream.
        let ssrc = 6666;
        let base = Instant::now();

        // Packet from an unbound SSRC must not be buffered — forwarded immediately.
        chain.handle_read(make_rtp_at(ssrc, 1, 0, base)).unwrap();
        // handle_timeout at exactly base (no delay passed) should not hold the packet back.
        chain.handle_timeout(base).unwrap();
        // The packet should be immediately readable from the inner chain rather than buffered.
        assert!(
            chain.poll_read().is_some(),
            "unbound SSRC packets should pass through immediately"
        );
    }

    #[test]
    fn test_poll_timeout_returns_buffer_wake_time() {
        let initial_ms = 50u64;
        let mut chain = make_chain(initial_ms, 500);
        let ssrc = 7777;
        chain.bind_remote_stream(&make_stream_info(ssrc, 90000));

        let base = Instant::now();
        chain.handle_read(make_rtp_at(ssrc, 1, 0, base)).unwrap();

        let wake = chain.poll_timeout();
        assert!(
            wake.is_some(),
            "should have a wake time after buffering a packet"
        );
        // Wake time should be approximately base + initial_delay.
        let wake = wake.unwrap();
        assert!(wake > base, "wake time must be in the future");
        assert!(
            wake <= base + Duration::from_millis(initial_ms + 10),
            "wake time should be close to initial_delay"
        );
    }

    /// Whether a packet of `ssrc` held since `base` has come out by `base + after_ms`.
    fn released_by(chain: &mut impl crate::Interceptor, base: Instant, after_ms: u64) -> bool {
        chain
            .handle_timeout(base + Duration::from_millis(after_ms))
            .unwrap();
        chain.poll_read().is_some()
    }

    /// W3C webrtc 5.3 jitterBufferTarget: the application's target replaces the adaptive
    /// one for the SSRCs it names, clamped to the minimum and maximum delay; the control is
    /// consumed; a stream bound after it takes it too; `None` returns to the adaptive target.
    #[test]
    fn an_application_target_replaces_the_adaptive_one_within_the_bounds() {
        let mut chain = make_chain(50, 500);
        let ssrc = 4444;
        chain.bind_remote_stream(&make_stream_info(ssrc, 90000));
        let base = Instant::now();
        let control = |target: Option<u64>, ssrcs: Vec<u32>| {
            JitterBufferControl {
                ssrcs,
                target: target.map(Duration::from_millis),
            }
            .into_packet(base)
        };

        chain.handle_write(control(Some(300), vec![ssrc])).unwrap();
        assert!(chain.poll_write().is_none(), "the control is consumed");
        chain.handle_read(make_rtp_at(ssrc, 1, 0, base)).unwrap();
        assert!(!released_by(&mut chain, base, 299));
        assert!(released_by(&mut chain, base, 300), "held for the target");

        // Above the maximum: the maximum.
        chain.handle_write(control(Some(4000), vec![ssrc])).unwrap();
        let base2 = base + Duration::from_secs(1);
        chain
            .handle_read(make_rtp_at(ssrc, 2, 90_000, base2))
            .unwrap();
        assert!(!released_by(&mut chain, base2, 499));
        assert!(released_by(&mut chain, base2, 500));

        // Below the minimum: the minimum.
        chain.handle_write(control(Some(5), vec![ssrc])).unwrap();
        let base3 = base + Duration::from_secs(2);
        chain
            .handle_read(make_rtp_at(ssrc, 3, 180_000, base3))
            .unwrap();
        assert!(!released_by(&mut chain, base3, 49));
        assert!(released_by(&mut chain, base3, 50));

        // A stream bound later takes the target set for its SSRC.
        let later = 5555;
        chain.handle_write(control(Some(200), vec![later])).unwrap();
        chain.bind_remote_stream(&make_stream_info(later, 90000));
        chain.handle_read(make_rtp_at(later, 1, 0, base3)).unwrap();
        assert!(!released_by(&mut chain, base3, 199));
        assert!(released_by(&mut chain, base3, 200));

        // No preference: the adaptive target (50 ms here) again.
        chain.handle_write(control(None, vec![ssrc])).unwrap();
        let base4 = base + Duration::from_secs(3);
        chain
            .handle_read(make_rtp_at(ssrc, 4, 270_000, base4))
            .unwrap();
        assert!(!released_by(&mut chain, base4, 49));
        assert!(released_by(&mut chain, base4, 51));
    }
}
