//! The last step of a snapshot: the ids and the timestamps as the report gives them.
//!
//! The accumulators name their objects by what they are (`RTCInboundRTPStream_video_1234`,
//! `RTCTransport`): that is what makes an id stable from one report to the next and lets every
//! reference be written without a lookup. An application must not be able to predict an id
//! though (webrtc 8.4: "Stats IDs MUST NOT be predictable by an application"), so a report
//! carries, for each of them, a hash of that name keyed with a salt drawn once per peer
//! connection. The same name always gives the same id on a connection, so ids stay stable and
//! references keep resolving; the same name gives another id on another connection.
//!
//! The timestamps are sealed here too. An accumulator stamps an object with the monotonic
//! instant it describes: the caller's `now`, the arrival of the RTCP report a remote object was
//! built from, the last packet of a stream. All of them become wall-clock times on one anchor,
//! taken at the connection's first report, so the difference between two timestamps of a report
//! (or of two reports) is exactly the time between the two instants.

use crate::statistics::report::RTCStatsReportEntry;
use crate::statistics::stats::RTCStats;
use shared::time::SystemInstant;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

/// What turns the accumulators' names and instants into a report's ids and timestamps.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Seal {
    /// The connection's id salt; `None` leaves the names as they are (an accumulator built
    /// outside a peer connection).
    salt: Option<[u64; 2]>,
    /// The instant the anchor was taken at.
    anchor_instant: Instant,
    /// The wall-clock time at that instant.
    anchor_epoch: Duration,
}

impl Seal {
    pub(crate) fn new(salt: Option<[u64; 2]>, anchor: SystemInstant) -> Self {
        let anchor_epoch = anchor.duration_since_unix_epoch();
        Self {
            salt,
            anchor_instant: anchor.instant(anchor_epoch),
            anchor_epoch,
        }
    }

    /// The id the report gives the object the accumulators call `name`.
    pub(crate) fn id_of(&self, name: &str) -> String {
        let Some(salt) = self.salt else {
            return name.to_owned();
        };
        // SipHash over the salt, then the name: without the salt the output cannot be told
        // from random, which is all "not predictable" asks for.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        salt.hash(&mut hasher);
        name.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Seals an id or a reference; an empty one means "none" and stays empty.
    fn id(&self, name: &mut String) {
        if !name.is_empty() {
            *name = self.id_of(name);
        }
    }

    fn optional_id(&self, name: &mut Option<String>) {
        if let Some(name) = name {
            self.id(name);
        }
    }

    /// The wall-clock time of `instant` on the anchor.
    fn epoch_of(&self, instant: Instant) -> Duration {
        match instant.checked_duration_since(self.anchor_instant) {
            Some(after) => self.anchor_epoch + after,
            None => self
                .anchor_epoch
                .saturating_sub(self.anchor_instant.duration_since(instant)),
        }
    }

    /// Seals a timestamp an accumulator built with `SystemInstant::now(instant)`.
    fn timestamp(&self, stamp: &mut SystemInstant) {
        let instant = stamp.instant(stamp.duration_since_unix_epoch());
        *stamp = SystemInstant::at(instant, self.epoch_of(instant));
    }

    fn optional_timestamp(&self, stamp: &mut Option<SystemInstant>) {
        if let Some(stamp) = stamp {
            self.timestamp(stamp);
        }
    }

    fn stats(&self, stats: &mut RTCStats) {
        self.timestamp(&mut stats.timestamp);
        self.id(&mut stats.id);
    }

    /// Seals every id, reference and timestamp of `entry`.
    ///
    /// A remote-outbound object's `remoteTimestamp` is left alone: it is the remote clock's
    /// reading, taken from the sender report, not an instant of ours.
    pub(crate) fn entry(&self, entry: &mut RTCStatsReportEntry) {
        match entry {
            RTCStatsReportEntry::PeerConnection(s) => self.stats(&mut s.stats),
            RTCStatsReportEntry::Transport(s) => {
                self.stats(&mut s.stats);
                self.id(&mut s.selected_candidate_pair_id);
                self.id(&mut s.local_certificate_id);
                self.id(&mut s.remote_certificate_id);
            }
            RTCStatsReportEntry::IceCandidatePair(s) => {
                self.stats(&mut s.stats);
                self.id(&mut s.transport_id);
                self.id(&mut s.local_candidate_id);
                self.id(&mut s.remote_candidate_id);
                self.optional_timestamp(&mut s.last_packet_sent_timestamp);
                self.optional_timestamp(&mut s.last_packet_received_timestamp);
            }
            RTCStatsReportEntry::LocalCandidate(s) | RTCStatsReportEntry::RemoteCandidate(s) => {
                self.stats(&mut s.stats);
                self.id(&mut s.transport_id);
            }
            RTCStatsReportEntry::Certificate(s) => {
                self.stats(&mut s.stats);
                self.id(&mut s.issuer_certificate_id);
            }
            RTCStatsReportEntry::Codec(s) => {
                self.stats(&mut s.stats);
                self.id(&mut s.transport_id);
            }
            RTCStatsReportEntry::DataChannel(s) => self.stats(&mut s.stats),
            RTCStatsReportEntry::InboundRtp(s) => {
                let stream = &mut s.received_rtp_stream_stats.rtp_stream_stats;
                self.stats(&mut stream.stats);
                self.id(&mut stream.transport_id);
                self.id(&mut stream.codec_id);
                self.optional_id(&mut s.remote_id);
                self.optional_id(&mut s.playout_id);
                self.optional_timestamp(&mut s.last_packet_received_timestamp);
            }
            RTCStatsReportEntry::OutboundRtp(s) => {
                let stream = &mut s.sent_rtp_stream_stats.rtp_stream_stats;
                self.stats(&mut stream.stats);
                self.id(&mut stream.transport_id);
                self.id(&mut stream.codec_id);
                self.id(&mut s.media_source_id);
                self.optional_id(&mut s.remote_id);
            }
            RTCStatsReportEntry::RemoteInboundRtp(s) => {
                let stream = &mut s.received_rtp_stream_stats.rtp_stream_stats;
                self.stats(&mut stream.stats);
                self.id(&mut stream.transport_id);
                self.id(&mut stream.codec_id);
                self.id(&mut s.local_id);
            }
            RTCStatsReportEntry::RemoteOutboundRtp(s) => {
                let stream = &mut s.sent_rtp_stream_stats.rtp_stream_stats;
                self.stats(&mut stream.stats);
                self.id(&mut stream.transport_id);
                self.id(&mut stream.codec_id);
                self.id(&mut s.local_id);
            }
            RTCStatsReportEntry::AudioSource(s) => self.stats(&mut s.media_source_stats.stats),
            RTCStatsReportEntry::VideoSource(s) => self.stats(&mut s.media_source_stats.stats),
            RTCStatsReportEntry::AudioPlayout(s) => self.stats(&mut s.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_salted_id_is_stable_on_a_connection_and_differs_between_connections() {
        let anchor = SystemInstant::now(Instant::now());
        let one = Seal::new(Some([1, 2]), anchor);
        let other = Seal::new(Some([3, 4]), anchor);
        assert_eq!(one.id_of("RTCTransport"), one.id_of("RTCTransport"));
        assert_ne!(one.id_of("RTCTransport"), other.id_of("RTCTransport"));
        assert_ne!(one.id_of("RTCTransport"), one.id_of("RTCPeerConnection"));
        assert!(!one.id_of("RTCTransport").contains("RTC"));
        assert_eq!(
            Seal::new(None, anchor).id_of("RTCTransport"),
            "RTCTransport"
        );
    }

    #[test]
    fn timestamps_keep_the_distance_between_their_instants() {
        let t0 = Instant::now();
        let anchor = SystemInstant::now(t0 + Duration::from_secs(10));
        let seal = Seal::new(None, anchor);
        let mut before = SystemInstant::now(t0);
        let mut after = SystemInstant::now(t0 + Duration::from_secs(25));
        seal.timestamp(&mut before);
        seal.timestamp(&mut after);
        assert_eq!(
            after.duration_since_unix_epoch() - before.duration_since_unix_epoch(),
            Duration::from_secs(25)
        );
        assert_eq!(
            anchor.duration_since_unix_epoch() - before.duration_since_unix_epoch(),
            Duration::from_secs(10),
            "an instant before the anchor is that much earlier, not clamped to it"
        );
        assert_eq!(before.instant(before.duration_since_unix_epoch()), t0);
    }
}
