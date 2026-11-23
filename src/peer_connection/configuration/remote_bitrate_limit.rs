//! The bitrate limit of the remote description (`b=TIAS` / `b=AS`, RFC 9429 section 5.10) as
//! the upper bound of the congestion controller's estimate.

use interceptor::{Attribute, AttributedPacket, Interceptor, Packet, StreamInfo, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

/// Where [`RemoteBitrateLimitInterceptor`] goes in a chain: between the congestion controller
/// ([`Slot::CongestionControl`](interceptor::Slot::CongestionControl), which announces the
/// estimate on the read leg) and the pacer ([`Slot::Pacer`](interceptor::Slot::Pacer), which
/// reads it), so that everything that reads the estimate reads the bounded one. Wire-ward of
/// the circuit breaker ([`Slot::CircuitBreaker`](interceptor::Slot::CircuitBreaker), 2_500):
/// a slot holds one interceptor, and at 2_500 this one and the breaker displaced each other.
pub const REMOTE_BITRATE_LIMIT_SLOT: usize = 2_250;

/// The most this endpoint may send, in bits per second, as the remote description says
/// (`None`: it sets no limit). The peer connection writes it into the chain when an answer is
/// applied, as an [`Attribute::Custom`] on an empty RTCP packet
/// ([`RemoteBitrateLimit::into_packet`]); [`RemoteBitrateLimitInterceptor`] takes it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RemoteBitrateLimit(pub Option<f64>);

impl RemoteBitrateLimit {
    /// The packet that carries this to the interceptor when written into the chain at `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(self))),
        }
    }
}

/// Bounds the congestion controller's estimate ([`Attribute::TargetBitrateChanged`]) by what
/// the remote description allows this endpoint to send.
///
/// RFC 9429 section 5.10: a `b=TIAS` value of a remote media section (or the one derived from
/// its `b=AS`) is "a constraint on the maximum RTP bitrate to be used when sending media". The
/// estimate is one number for the transport, so its bound is the sum of the limits of the
/// sections this endpoint sends in, when each of them has one (RFC 8859 section 6: `b=AS` is
/// of the SUM category in a BUNDLE group, and `b=TIAS` values are added).
///
/// The estimator itself is not told: it goes on measuring the path, and its estimate is cut
/// to the limit on its way to the pacer and to the statistics. When the limit changes, the
/// bounded target is announced at once, without waiting for the next feedback packet.
///
/// Part of
/// [`configure_congestion_control`](super::interceptor_registry::configure_congestion_control);
/// a chain built by hand places it at [`REMOTE_BITRATE_LIMIT_SLOT`].
pub struct RemoteBitrateLimitInterceptor {
    limit: Option<f64>,
    /// The controller's estimate as it last arrived, unbounded. Until the first one, the
    /// rate the estimator starts at.
    estimate: f64,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl RemoteBitrateLimitInterceptor {
    /// `initial_estimate`: the rate the congestion controller's estimator starts at (the one
    /// the pacer is built with), in bits per second.
    pub fn new(initial_estimate: f64) -> Self {
        Self {
            limit: None,
            estimate: initial_estimate,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }

    fn bounded(&self) -> f64 {
        self.limit
            .map_or(self.estimate, |limit| self.estimate.min(limit))
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RemoteBitrateLimitInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        for attribute in &mut msg.message.attributes {
            if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                self.estimate = *bits_per_second;
                *bits_per_second = self.bounded();
            }
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Some(RemoteBitrateLimit(limit)) = msg.message.custom::<RemoteBitrateLimit>().copied()
        {
            let before = self.bounded();
            self.limit = limit.filter(|limit| limit.is_finite() && *limit >= 0.0);
            let bounded = self.bounded();
            if bounded != before {
                // What reads the estimate is application-ward of here and reads it on the
                // read leg: an attribute carrier takes the new target there.
                self.read_queue.push_back(TaggedPacket {
                    now: msg.now,
                    transport: msg.transport,
                    message: AttributedPacket::new(Packet::Rtcp(vec![])).with(
                        Attribute::TargetBitrateChanged {
                            bits_per_second: bounded,
                        },
                    ),
                });
            }
            msg.message.attributes.retain(
                |attribute| !matches!(attribute, Attribute::Custom(value) if value.is::<RemoteBitrateLimit>()),
            );
            if msg.message.attributes.is_empty()
                && matches!(&msg.message.packet, Packet::Rtcp(packets) if packets.is_empty())
            {
                return Ok(());
            }
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for RemoteBitrateLimitInterceptor {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use interceptor::{PacerBuilder, Registry, Slot};
    use std::time::Duration;

    fn feedback_with_estimate(now: Instant, bits_per_second: f64) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::TargetBitrateChanged { bits_per_second }),
        }
    }

    /// The targets that come out of the chain's read side, in order.
    fn targets(chain: &mut impl Interceptor) -> Vec<f64> {
        let mut out = vec![];
        while let Some(packet) = chain.poll_read() {
            for attribute in &packet.message.attributes {
                if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                    out.push(*bits_per_second);
                }
            }
        }
        out
    }

    fn chain() -> impl Interceptor {
        Registry::new()
            .with(
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                RemoteBitrateLimitInterceptor::new(1_000_000.0),
            )
            .build()
    }

    #[test]
    fn an_estimate_above_the_limit_is_cut_to_it_and_one_below_passes() {
        let now = Instant::now();
        let mut chain = chain();

        // No limit: the estimate as it is.
        chain
            .handle_read(feedback_with_estimate(now, 3_000_000.0))
            .unwrap();
        assert_eq!(targets(&mut chain), vec![3_000_000.0]);

        // A limit below the estimate takes effect at once, without new feedback.
        chain
            .handle_write(RemoteBitrateLimit(Some(500_000.0)).into_packet(now))
            .unwrap();
        assert_eq!(targets(&mut chain), vec![500_000.0]);
        assert!(chain.poll_write().is_none(), "the control is not sent");

        chain
            .handle_read(feedback_with_estimate(now, 4_000_000.0))
            .unwrap();
        chain
            .handle_read(feedback_with_estimate(now, 200_000.0))
            .unwrap();
        assert_eq!(targets(&mut chain), vec![500_000.0, 200_000.0]);

        // The limit lifted: the last estimate is the target again.
        chain
            .handle_read(feedback_with_estimate(now, 4_000_000.0))
            .unwrap();
        assert_eq!(targets(&mut chain), vec![500_000.0]);
        chain
            .handle_write(RemoteBitrateLimit(None).into_packet(now))
            .unwrap();
        assert_eq!(targets(&mut chain), vec![4_000_000.0]);
    }

    #[test]
    fn a_limit_below_the_starting_rate_is_announced_before_any_feedback() {
        let now = Instant::now();
        let mut chain = chain();
        // Above the starting rate: nothing changes, nothing is announced.
        chain
            .handle_write(RemoteBitrateLimit(Some(2_000_000.0)).into_packet(now))
            .unwrap();
        assert!(targets(&mut chain).is_empty());
        chain
            .handle_write(RemoteBitrateLimit(Some(300_000.0)).into_packet(now))
            .unwrap();
        assert_eq!(targets(&mut chain), vec![300_000.0]);
    }

    /// With the pacer application-ward of it, as `configure_congestion_control` builds the
    /// chain: the pacer releases at the bounded rate, not at the estimate.
    #[test]
    fn the_pacer_follows_the_bounded_target() {
        let base = Instant::now();
        let released_in_a_second = |limit: Option<f64>| {
            let mut chain = Registry::new()
                .with(
                    Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                    RemoteBitrateLimitInterceptor::new(8_000_000.0),
                )
                .with(
                    Slot::Pacer,
                    // Without the queue time limit, which would drain the two seconds offered
                    // below within two seconds whatever the bound.
                    PacerBuilder::new()
                        .with_target_bitrate(8_000_000.0)
                        .with_queue_time_limit(None)
                        .build(),
                )
                .build();
            chain
                .handle_write(RemoteBitrateLimit(limit).into_packet(base))
                .unwrap();
            while chain.poll_read().is_some() {}
            // 2000 packets of 1000 bytes: 16 Mbit, two seconds' worth at the starting rate.
            for sequence_number in 0..2000u16 {
                chain
                    .handle_write(TaggedPacket {
                        now: base,
                        transport: TransportContext::default(),
                        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                            header: rtp::header::Header {
                                version: 2,
                                payload_type: 96,
                                sequence_number,
                                ssrc: 1,
                                ..Default::default()
                            },
                            payload: vec![0u8; 1000].into(),
                        })),
                    })
                    .unwrap();
            }
            let mut released = 0usize;
            let mut now = base;
            while now <= base + Duration::from_secs(1) {
                chain.handle_timeout(now).unwrap();
                while let Some(packet) = chain.poll_write() {
                    if matches!(packet.message.packet, Packet::Rtp(_)) {
                        released += 1;
                    }
                }
                now += Duration::from_millis(5);
            }
            released
        };

        let unbounded = released_in_a_second(None);
        let bounded = released_in_a_second(Some(800_000.0));
        // 8 Mbit/s is about 1000 such packets a second, 800 kbit/s about 100.
        assert!(unbounded > 700, "unbounded: {unbounded}");
        assert!(bounded < 200, "bounded: {bounded}");
        assert!(bounded > 50, "bounded: {bounded}");
    }
}
