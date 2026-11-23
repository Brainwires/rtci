//! Statistics accumulator module.
//!
//! This module provides incremental statistics accumulation for WebRTC
//! peer connections. The accumulators are updated as events occur in the
//! handler pipeline, and snapshots can be taken at any time to produce
//! immutable stats reports.

mod ccfb;
mod certificate;
mod codec;
mod data_channel;
mod ice_candidate;
mod ice_candidate_pair;
mod media;
mod peer_connection;
#[cfg(test)]
mod retire_test;
mod rtcp_reports;
#[cfg(test)]
mod rtcp_reports_test;
mod rtp_stream;
mod seal;
mod transport;

pub(crate) use ccfb::CcfbTally;
pub(crate) use certificate::{CertificateStatsAccumulator, base64_encode};
pub(crate) use codec::{CodecDirection, CodecStatsAccumulator};
pub(crate) use data_channel::DataChannelStatsAccumulator;
pub(crate) use ice_candidate::IceCandidateAccumulator;
pub(crate) use ice_candidate_pair::IceCandidatePairAccumulator;
pub use media::app_provided::*;
pub(crate) use media::audio_playout::AudioPlayoutStatsAccumulator;
pub(crate) use media::media_source::{MediaSourceStatsAccumulator, media_source_stats_id};
pub(crate) use peer_connection::PeerConnectionStatsAccumulator;
pub(crate) use rtp_stream::inbound::InboundRtpStreamAccumulator;
pub(crate) use rtp_stream::outbound::OutboundRtpStreamAccumulator;
pub(crate) use seal::Seal;
pub(crate) use transport::TransportStatsAccumulator;

use crate::data_channel::RTCDataChannelId;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use crate::rtp_transceiver::{PayloadType, RTCRtpTransceiverId, SSRC};
use crate::statistics::StatsSelector;
use crate::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use ice::CandidatePairStats;
use sctp::StreamId;
use shared::time::SystemInstant;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Instant;

/// Master statistics accumulator for a peer connection.
///
/// This struct aggregates all category-specific accumulators and provides
/// a unified interface for updating stats and generating snapshots.
///
/// # Design
///
/// The accumulator follows the "incremental accumulation + snapshot" pattern:
/// - Handler code calls methods like `on_rtp_received()` as events occur
/// - The `snapshot()` method produces an immutable `RTCStatsReport`
/// - All timestamps are provided explicitly for deterministic testing
///
/// # Thread Safety
///
/// This struct is not thread-safe. It is designed to be owned by the
/// pipeline context and accessed only from the handler thread.
/// How many closed data channels keep their stats object (webrtc-stats lifetime, bounded).
pub(crate) const MAX_CLOSED_DATA_CHANNEL_STATS: usize = 64;

#[derive(Debug, Default)]
pub(crate) struct RTCStatsAccumulator {
    /// Peer connection level stats.
    pub(crate) peer_connection: PeerConnectionStatsAccumulator,

    /// Transport stats (typically one per peer connection).
    pub(crate) transport: TransportStatsAccumulator,

    /// ICE candidate pairs keyed by pair ID.
    pub(crate) ice_candidate_pairs: HashMap<String, IceCandidatePairAccumulator>,

    /// Local ICE candidates keyed by candidate ID.
    pub(crate) local_candidates: HashMap<String, IceCandidateAccumulator>,

    /// Remote ICE candidates keyed by candidate ID.
    pub(crate) remote_candidates: HashMap<String, IceCandidateAccumulator>,

    /// Certificate stats keyed by fingerprint.
    pub(crate) certificates: HashMap<String, CertificateStatsAccumulator>,

    /// Codec stats keyed by codec ID.
    pub(crate) codecs: HashMap<String, CodecStatsAccumulator>,

    /// Data channel stats keyed by channel ID.
    pub(crate) data_channels: HashMap<RTCDataChannelId, DataChannelStatsAccumulator>,

    /// The closed channels whose stats objects are kept, oldest first (at most
    /// [`MAX_CLOSED_DATA_CHANNEL_STATS`]).
    pub(crate) closed_data_channels: std::collections::VecDeque<RTCDataChannelId>,

    /// Inbound RTP stream accumulators keyed by SSRC.
    pub(crate) inbound_rtp_streams: HashMap<SSRC, InboundRtpStreamAccumulator>,

    /// Outbound RTP stream accumulators keyed by SSRC.
    pub(crate) outbound_rtp_streams: HashMap<SSRC, OutboundRtpStreamAccumulator>,

    /// Media source stats keyed by track ID.
    pub(crate) media_sources: HashMap<String, MediaSourceStatsAccumulator>,

    /// Audio playout stats keyed by playout ID.
    pub(crate) audio_playouts: HashMap<String, AudioPlayoutStatsAccumulator>,

    // Reverse lookup maps for O(1) RTX/FEC SSRC detection. Each holds at most one entry per
    // stream: an entry goes when its stream goes, or when the stream is given another RTX / FEC
    // SSRC.
    /// Maps an inbound RTX SSRC to its primary SSRC.
    inbound_rtx_ssrc_to_primary: HashMap<SSRC, SSRC>,

    /// Maps an outbound RTX SSRC to its primary SSRC. Kept apart from the inbound map: the
    /// remote's SSRCs and ours are chosen independently and may coincide.
    outbound_rtx_ssrc_to_primary: HashMap<SSRC, SSRC>,

    /// Maps an inbound FEC SSRC to its primary SSRC.
    fec_ssrc_to_primary: HashMap<SSRC, SSRC>,

    /// The application's socket layer carries ECN (`SettingEngineBuilder::with_ecn`): RTP
    /// streams report their ECN counts.
    pub(crate) ecn: bool,
    /// How a stream with ECN on starts marking (`SettingEngineBuilder::with_ecn_initiation`).
    pub(crate) ecn_initiation: interceptor::EcnInitiation,

    /// How many RTP stream objects have been deleted. A stream object created now carries it in
    /// its id, so that id differs from the id of every deleted object with the same SSRC
    /// (webrtc-stats 4.3: the id of a deleted object is never reused). One counter rather than
    /// a memory of the SSRCs that went: a peer can go through any number of those.
    streams_retired: u64,

    /// The salt the report's ids are hashed with, drawn once per peer connection (webrtc 8.4:
    /// an id must not be predictable by an application). `None` (an accumulator built outside
    /// a peer connection) leaves the ids as the accumulators name them.
    id_salt: Option<[u64; 2]>,

    /// The wall-clock anchor of the report timestamps, taken at the first report (see
    /// [`Seal`]). A `OnceLock` rather than a `OnceCell`: the accumulator stays `Sync`.
    anchor: OnceLock<SystemInstant>,
}

/// Asserts a stats record was stamped with `expected`, ignoring the wall-clock half.
///
/// A [`SystemInstant`] pairs a monotonic instant with a wall-clock reading taken beside it, and
/// `PartialEq` compares both. Rebuilding one in a test — `SystemInstant::now(now)` — reproduces
/// the monotonic half exactly but takes a *fresh* wall-clock reading, so the two are never equal:
/// they differ by however long the test took to get there, typically a few hundred microseconds.
///
/// The monotonic half is the part under test: it says the snapshot stamped the record with the
/// instant the caller supplied rather than one it went and read. Recover it via the round-trip
/// `instant(duration_since_unix_epoch())`, which cancels the anchor and returns the instant the
/// `SystemInstant` was built from.
#[cfg(test)]
pub(crate) fn assert_stamped_at(stamp: shared::time::SystemInstant, expected: Instant) {
    assert_eq!(
        stamp.instant(stamp.duration_since_unix_epoch()),
        expected,
        "stats must be stamped with the caller's instant"
    );
}

impl RTCStatsAccumulator {
    /// Creates a new empty stats accumulator.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// An empty accumulator whose RTP streams report ECN counts when `ecn` is on
    /// (`SettingEngineBuilder::with_ecn`).
    pub(crate) fn with_ecn(ecn: bool) -> Self {
        Self {
            ecn,
            ..Self::default()
        }
    }

    /// The accumulator of a peer connection: [`with_ecn`](Self::with_ecn), and report ids
    /// hashed with `id_salt`, which the connection draws at random.
    pub(crate) fn for_connection(
        ecn: bool,
        ecn_initiation: interceptor::EcnInitiation,
        id_salt: [u64; 2],
    ) -> Self {
        Self {
            ecn,
            ecn_initiation,
            id_salt: Some(id_salt),
            ..Self::default()
        }
    }

    /// What seals a report taken at `now`: the connection's id salt and the timestamp anchor,
    /// which the first report sets.
    fn seal(&self, now: Instant) -> Seal {
        Seal::new(
            self.id_salt,
            *self.anchor.get_or_init(|| SystemInstant::now(now)),
        )
    }

    /// The report holding `entries`, with their ids and timestamps sealed.
    fn report(&self, now: Instant, mut entries: Vec<RTCStatsReportEntry>) -> RTCStatsReport {
        let seal = self.seal(now);
        for entry in &mut entries {
            seal.entry(entry);
        }
        RTCStatsReport::new(entries)
    }

    /// The id a report gives the object the accumulators name `name` (for a test that looks
    /// an object up by what it is).
    #[cfg(test)]
    pub(crate) fn report_id(&self, now: Instant, name: &str) -> String {
        self.seal(now).id_of(name)
    }

    /// The outbound-rtp object of `stream`.
    ///
    /// Its `targetBitrate` is the encoder's target for the stream. The application supplies
    /// it; without that, the congestion controller's estimate stands in for it while the
    /// connection sends one stream, which then has the whole estimate. With several streams
    /// the estimate is not any one stream's target, and the member is left out.
    fn outbound_snapshot(
        &self,
        now: Instant,
        stream: &OutboundRtpStreamAccumulator,
    ) -> crate::statistics::stats::rtp_stream::sent::outbound::RTCOutboundRtpStreamStats {
        let mut stats = stream.snapshot(now, &stream.stats_id());
        if stream.encoder_stats.target_bitrate.is_none() && self.outbound_rtp_streams.len() > 1 {
            stats.target_bitrate = None;
        }
        stats
    }

    /// The remote-candidate entries.
    ///
    /// webrtc-stats `RTCIceCandidateStats.address`: a remote candidate's address is null
    /// unless the application supplied that address itself (`addIceCandidate`, or a candidate
    /// line of a remote description); then every remote candidate with that address shows it.
    /// A peer-reflexive candidate learned from a connectivity check is the case that matters:
    /// its address was never given to the application.
    fn remote_candidate_entries(&self, now: Instant) -> Vec<RTCStatsReportEntry> {
        let signalled: HashSet<&str> = self
            .remote_candidates
            .values()
            .filter(|candidate| candidate.signalled)
            .filter_map(|candidate| candidate.address.as_deref())
            .collect();
        self.remote_candidates
            .iter()
            .map(|(id, candidate)| {
                let mut stats = candidate.snapshot_remote(now, id);
                if !stats
                    .address
                    .as_deref()
                    .is_some_and(|address| signalled.contains(address))
                {
                    stats.address = None;
                }
                RTCStatsReportEntry::RemoteCandidate(stats)
            })
            .collect()
    }

    /// Creates a snapshot of all accumulated stats at the given timestamp.
    ///
    /// This method iterates through all accumulators and produces an
    /// immutable `RTCStatsReport` containing all current statistics.
    ///
    /// # Parameters
    ///
    /// * `now` - The timestamp to use for all stats in the report
    ///
    /// # Returns
    ///
    /// An `RTCStatsReport` containing snapshots of all accumulated stats.
    pub(crate) fn snapshot(&self, now: Instant) -> RTCStatsReport {
        let mut entries = Vec::new();

        // Peer connection stats
        entries.push(RTCStatsReportEntry::PeerConnection(
            self.peer_connection.snapshot(now),
        ));

        // Transport stats
        entries.push(RTCStatsReportEntry::Transport(self.transport.snapshot(now)));

        // ICE candidate pair stats
        for (id, pair) in &self.ice_candidate_pairs {
            entries.push(RTCStatsReportEntry::IceCandidatePair(
                pair.snapshot(now, id),
            ));
        }

        // Local ICE candidate stats
        for (id, candidate) in &self.local_candidates {
            entries.push(RTCStatsReportEntry::LocalCandidate(
                candidate.snapshot_local(now, id),
            ));
        }

        // Remote ICE candidate stats
        entries.extend(self.remote_candidate_entries(now));

        // Certificate stats
        for (id, cert) in &self.certificates {
            entries.push(RTCStatsReportEntry::Certificate(cert.snapshot(now, id)));
        }

        // Codec stats
        for (id, codec) in &self.codecs {
            entries.push(RTCStatsReportEntry::Codec(codec.snapshot(now, id)));
        }

        // Data channel stats
        for (id, channel) in &self.data_channels {
            entries.push(RTCStatsReportEntry::DataChannel(
                channel.snapshot(now, format!("RTCDataChannel_{}", id)),
            ));
        }

        // Inbound RTP stream stats, each with its remote-outbound object once an RTCP SR has
        // created it (webrtc-stats 6.1)
        for stream in self.inbound_rtp_streams.values() {
            let id = stream.stats_id();
            entries.push(RTCStatsReportEntry::InboundRtp(stream.snapshot(now, &id)));
            if stream.has_remote() {
                entries.push(RTCStatsReportEntry::RemoteOutboundRtp(
                    stream.snapshot_remote(now),
                ));
            }
        }

        // Outbound RTP stream stats, each with its remote-inbound object once a reception
        // report has created it (webrtc-stats 6.1)
        for stream in self.outbound_rtp_streams.values() {
            entries.push(RTCStatsReportEntry::OutboundRtp(
                self.outbound_snapshot(now, stream),
            ));
            if stream.has_remote() {
                entries.push(RTCStatsReportEntry::RemoteInboundRtp(
                    stream.snapshot_remote(now),
                ));
            }
        }

        // Media source stats
        for (track_id, source) in &self.media_sources {
            if let Some(entry) = Self::media_source_entry(now, track_id, source) {
                entries.push(entry);
            }
        }

        // Audio playout stats
        for (id, playout) in &self.audio_playouts {
            entries.push(RTCStatsReportEntry::AudioPlayout(playout.snapshot(now, id)));
        }

        self.report(now, entries)
    }

    /// The report entry of the media source for the track `track_id`.
    fn media_source_entry(
        now: Instant,
        track_id: &str,
        source: &MediaSourceStatsAccumulator,
    ) -> Option<RTCStatsReportEntry> {
        let id = media_source_stats_id(track_id);
        match source.kind {
            RtpCodecKind::Audio => Some(RTCStatsReportEntry::AudioSource(
                source.snapshot_audio(now, &id),
            )),
            RtpCodecKind::Video => Some(RTCStatsReportEntry::VideoSource(
                source.snapshot_video(now, &id),
            )),
            _ => None,
        }
    }

    /// Creates a snapshot of stats based on the provided selector.
    ///
    /// This method implements the W3C stats selection algorithm:
    /// - If selector is None, returns all stats
    /// - If selector is Sender, returns outbound RTP streams for that sender
    ///   and all stats referenced by those streams
    /// - If selector is Receiver, returns inbound RTP streams for that receiver
    ///   and all stats referenced by those streams
    ///
    /// # Parameters
    ///
    /// * `now` - The timestamp to use for all stats in the report
    /// * `selector` - Controls which statistics are included
    ///
    /// # Returns
    ///
    /// An `RTCStatsReport` containing the selected statistics.
    pub(crate) fn snapshot_with_selector(
        &self,
        now: Instant,
        selector: StatsSelector,
    ) -> RTCStatsReport {
        match selector {
            StatsSelector::None => self.snapshot(now),
            StatsSelector::Sender(sender_id) => self.snapshot_for_sender(now, sender_id.0),
            StatsSelector::Receiver(receiver_id) => self.snapshot_for_receiver(now, receiver_id.0),
        }
    }

    /// Creates a snapshot for a specific sender (outbound streams).
    fn snapshot_for_sender(
        &self,
        now: Instant,
        transceiver_id: RTCRtpTransceiverId,
    ) -> RTCStatsReport {
        let mut entries = Vec::new();
        let mut referenced_codec_ids = HashSet::new();
        let mut has_streams = false;

        // Collect outbound RTP streams for this sender
        for stream in self.outbound_rtp_streams.values() {
            if stream.transceiver_id == transceiver_id {
                has_streams = true;
                entries.push(RTCStatsReportEntry::OutboundRtp(
                    self.outbound_snapshot(now, stream),
                ));
                if stream.has_remote() {
                    entries.push(RTCStatsReportEntry::RemoteInboundRtp(
                        stream.snapshot_remote(now),
                    ));
                }
                // Track referenced codec
                if !stream.codec_id.is_empty() {
                    referenced_codec_ids.insert(stream.codec_id.clone());
                }
            }
        }

        // Add referenced stats if we have any streams
        if has_streams {
            // Transport stats (always included as streams reference it)
            entries.push(RTCStatsReportEntry::Transport(self.transport.snapshot(now)));

            // Referenced codec stats
            for (id, codec) in &self.codecs {
                if referenced_codec_ids.contains(id) {
                    entries.push(RTCStatsReportEntry::Codec(codec.snapshot(now, id)));
                }
            }

            // The media source of the sender's track (referenced by the outbound streams)
            for (track_id, source) in &self.media_sources {
                if source.transceiver_id == Some(transceiver_id)
                    && let Some(entry) = Self::media_source_entry(now, track_id, source)
                {
                    entries.push(entry);
                }
            }

            // ICE candidate pair stats (referenced by transport)
            for (id, pair) in &self.ice_candidate_pairs {
                entries.push(RTCStatsReportEntry::IceCandidatePair(
                    pair.snapshot(now, id),
                ));
            }

            // Local ICE candidate stats
            for (id, candidate) in &self.local_candidates {
                entries.push(RTCStatsReportEntry::LocalCandidate(
                    candidate.snapshot_local(now, id),
                ));
            }

            // Remote ICE candidate stats
            entries.extend(self.remote_candidate_entries(now));

            // Certificate stats (referenced by transport)
            for (id, cert) in &self.certificates {
                entries.push(RTCStatsReportEntry::Certificate(cert.snapshot(now, id)));
            }
        }

        self.report(now, entries)
    }

    /// Creates a snapshot for a specific receiver (inbound streams).
    fn snapshot_for_receiver(
        &self,
        now: Instant,
        transceiver_id: RTCRtpTransceiverId,
    ) -> RTCStatsReport {
        let mut entries = Vec::new();
        let mut referenced_codec_ids = HashSet::new();
        let mut referenced_playout_ids: HashSet<String> = HashSet::new();
        let mut has_streams = false;

        // Collect inbound RTP streams for this receiver
        for stream in self.inbound_rtp_streams.values() {
            if stream.transceiver_id == transceiver_id {
                has_streams = true;
                let id = stream.stats_id();
                entries.push(RTCStatsReportEntry::InboundRtp(stream.snapshot(now, &id)));
                if stream.has_remote() {
                    entries.push(RTCStatsReportEntry::RemoteOutboundRtp(
                        stream.snapshot_remote(now),
                    ));
                }
                // Track referenced codec
                if !stream.codec_id.is_empty() {
                    referenced_codec_ids.insert(stream.codec_id.clone());
                }
                if let Some(playout_id) = &stream.playout_id {
                    referenced_playout_ids.insert(playout_id.clone());
                }
            }
        }

        // Add referenced stats if we have any streams
        if has_streams {
            // Transport stats (always included as streams reference it)
            entries.push(RTCStatsReportEntry::Transport(self.transport.snapshot(now)));

            // Referenced codec stats
            for (id, codec) in &self.codecs {
                if referenced_codec_ids.contains(id) {
                    entries.push(RTCStatsReportEntry::Codec(codec.snapshot(now, id)));
                }
            }

            // Referenced audio playouts
            for (id, playout) in &self.audio_playouts {
                if referenced_playout_ids.contains(id) {
                    entries.push(RTCStatsReportEntry::AudioPlayout(playout.snapshot(now, id)));
                }
            }

            // ICE candidate pair stats (referenced by transport)
            for (id, pair) in &self.ice_candidate_pairs {
                entries.push(RTCStatsReportEntry::IceCandidatePair(
                    pair.snapshot(now, id),
                ));
            }

            // Local ICE candidate stats
            for (id, candidate) in &self.local_candidates {
                entries.push(RTCStatsReportEntry::LocalCandidate(
                    candidate.snapshot_local(now, id),
                ));
            }

            // Remote ICE candidate stats
            entries.extend(self.remote_candidate_entries(now));

            // Certificate stats (referenced by transport)
            for (id, cert) in &self.certificates {
                entries.push(RTCStatsReportEntry::Certificate(cert.snapshot(now, id)));
            }
        }

        self.report(now, entries)
    }

    // ========================================================================
    // Convenience methods for updating stats
    // ========================================================================

    /// Gets or creates an inbound stream accumulator for the given SSRC.
    ///
    /// # Parameters
    ///
    /// * `ssrc` - The SSRC identifier for this stream
    /// * `kind` - The media kind (audio/video)
    /// * `track_identifier` - The track identifier from MediaStreamTrack
    /// * `mid` - The media stream identification tag from SDP
    /// * `rtx_ssrc` - The RTX SSRC for retransmissions (if available)
    /// * `fec_ssrc` - The FEC SSRC for forward error correction (if available)
    /// * `transceiver_id` - The transceiver ID that owns this stream
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn get_or_create_inbound_rtp_streams(
        &mut self,
        ssrc: SSRC,
        kind: RtpCodecKind,
        track_identifier: &str,
        mid: &str,
        rtx_ssrc: Option<u32>,
        fec_ssrc: Option<u32>,
        transceiver_id: RTCRtpTransceiverId,
    ) -> &mut InboundRtpStreamAccumulator {
        // Populate reverse lookup maps for O(1) RTX/FEC detection, replacing the entry of a
        // repair SSRC the stream had before
        let existing = self.inbound_rtp_streams.get(&ssrc);
        let (old_rtx, old_fec) = (
            existing.and_then(|s| s.rtx_ssrc),
            existing.and_then(|s| s.fec_ssrc),
        );
        if let Some(rtx) = rtx_ssrc {
            associate(&mut self.inbound_rtx_ssrc_to_primary, old_rtx, rtx, ssrc);
        }
        if let Some(fec) = fec_ssrc {
            associate(&mut self.fec_ssrc_to_primary, old_fec, fec, ssrc);
        }

        let transport_id = self.transport.transport_id.clone();
        let stream =
            self.inbound_rtp_streams
                .entry(ssrc)
                .or_insert_with(|| InboundRtpStreamAccumulator {
                    ssrc,
                    kind,
                    transport_id,
                    track_identifier: track_identifier.to_string(),
                    mid: mid.to_string(),
                    rtx_ssrc,
                    fec_ssrc,
                    transceiver_id,
                    generation: self.streams_retired,
                    ecn: self.ecn,
                    ..Default::default()
                });
        // An existing stream takes the repair SSRCs it is given now, as the reverse maps did.
        if rtx_ssrc.is_some() {
            stream.rtx_ssrc = rtx_ssrc;
        }
        if fec_ssrc.is_some() {
            stream.fec_ssrc = fec_ssrc;
        }
        stream
    }

    /// Drops the inbound stream accumulator for `ssrc` (its remote-outbound object with it) and
    /// every RTX / FEC lookup that points at it, once the stream is no longer bound (its rid
    /// moved to another SSRC).
    pub(crate) fn remove_inbound_rtp_stream(&mut self, ssrc: SSRC) {
        if self.inbound_rtp_streams.remove(&ssrc).is_some() {
            self.streams_retired += 1;
        }
        self.inbound_rtx_ssrc_to_primary
            .retain(|_, primary| *primary != ssrc);
        self.fec_ssrc_to_primary
            .retain(|_, primary| *primary != ssrc);
    }

    /// Updates the RTX SSRC association for an existing inbound RTP stream.
    ///
    /// This is used when `rrid` (repaired RTP stream ID) arrives after the base
    /// stream's `InboundRtpStreamAccumulator` has already been created. It updates
    /// both the reverse-lookup map (`inbound_rtx_ssrc_to_primary`) and the inbound stream's
    /// `rtx_ssrc` field so that `on_rtx_packet_received_if_rtx()` can recognize
    /// these packets and `getStats()` reports the correct `rtxSsrc`.
    ///
    /// # Arguments
    ///
    /// * `primary_ssrc` - The SSRC of the base/primary stream
    /// * `rtx_ssrc` - The RTX SSRC to associate with the primary stream
    pub(crate) fn update_inbound_rtx_ssrc(&mut self, primary_ssrc: SSRC, rtx_ssrc: SSRC) {
        let old_rtx = self
            .inbound_rtp_streams
            .get(&primary_ssrc)
            .and_then(|s| s.rtx_ssrc);
        associate(
            &mut self.inbound_rtx_ssrc_to_primary,
            old_rtx,
            rtx_ssrc,
            primary_ssrc,
        );
        if let Some(stream) = self.inbound_rtp_streams.get_mut(&primary_ssrc) {
            stream.rtx_ssrc = Some(rtx_ssrc);
        }
    }

    /// Gets or creates an outbound stream accumulator for the given SSRC.
    ///
    /// # Parameters
    ///
    /// * `ssrc` - The SSRC identifier for this stream
    /// * `kind` - The media kind (audio/video)
    /// * `mid` - The media stream identification tag from SDP
    /// * `rid` - The RTP stream ID for simulcast (empty if not simulcast)
    /// * `encoding_index` - The index of this encoding in the simulcast layer order
    /// * `rtx_ssrc` - The RTX SSRC for retransmissions (if available)
    /// * `transceiver_id` - The transceiver ID that owns this stream
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn get_or_create_outbound_rtp_streams(
        &mut self,
        ssrc: SSRC,
        kind: RtpCodecKind,
        mid: &str,
        rid: &str,
        encoding_index: u32,
        rtx_ssrc: Option<u32>,
        transceiver_id: RTCRtpTransceiverId,
    ) -> &mut OutboundRtpStreamAccumulator {
        if let Some(rtx) = rtx_ssrc {
            let old_rtx = self
                .outbound_rtp_streams
                .get(&ssrc)
                .and_then(|s| s.rtx_ssrc);
            associate(&mut self.outbound_rtx_ssrc_to_primary, old_rtx, rtx, ssrc);
        }

        // A media source the application already reported for this sender's track.
        let media_source_id = self
            .media_sources
            .iter()
            .find(|(_, source)| source.transceiver_id == Some(transceiver_id))
            .map(|(track_id, _)| media_source_stats_id(track_id))
            .unwrap_or_default();

        self.outbound_rtp_streams
            .entry(ssrc)
            .or_insert_with(|| OutboundRtpStreamAccumulator {
                ssrc,
                kind,
                transport_id: self.transport.transport_id.clone(),
                media_source_id,
                mid: mid.to_string(),
                rid: rid.to_string(),
                encoding_index,
                rtx_ssrc,
                transceiver_id,
                generation: self.streams_retired,
                active: true,
                ecn: self.ecn,
                ..Default::default()
            })
    }

    /// Gets or creates a data channel accumulator.
    ///
    /// # Parameters
    ///
    /// * `id` - The data channel identifier
    /// * `label` - The label assigned to the data channel
    /// * `protocol` - The sub-protocol name
    pub(crate) fn get_or_create_data_channel(
        &mut self,
        id: RTCDataChannelId,
        label: &str,
        protocol: &str,
    ) -> &mut DataChannelStatsAccumulator {
        self.data_channels
            .entry(id)
            .or_insert_with(|| DataChannelStatsAccumulator {
                // The wire value is filled in by `set_data_channel_stream_id` once the SCTP
                // connected procedure assigns one; the map itself is keyed by handle, so an
                // accumulator can exist before then.
                data_channel_identifier: None,
                label: label.to_string(),
                protocol: protocol.to_string(),
                ..Default::default()
            })
    }

    /// A data channel is gone for good. Its stats object stays, in the "closed" state
    /// (webrtc-stats section 3.3: a stats object outlives its closed object, its last values
    /// kept), for the [`MAX_CLOSED_DATA_CHANNEL_STATS`] channels closed last; an older one goes.
    /// If the channel had been open it is counted in `dataChannelsClosed` (webrtc-stats: the
    /// channels that "left the open state"; one that never opened, closed while connecting or
    /// by the handshake timeout, is not one of them).
    pub(crate) fn on_data_channel_gone(&mut self, id: RTCDataChannelId) {
        let Some(channel) = self.data_channels.get_mut(&id) else {
            return;
        };
        if channel.state == crate::data_channel::RTCDataChannelState::Closed
            && self.closed_data_channels.contains(&id)
        {
            return;
        }
        channel.state = crate::data_channel::RTCDataChannelState::Closed;
        if channel.opened {
            self.peer_connection.on_data_channel_closed();
        }
        self.closed_data_channels.push_back(id);
        while self.closed_data_channels.len() > MAX_CLOSED_DATA_CHANNEL_STATS {
            if let Some(oldest) = self.closed_data_channels.pop_front() {
                self.data_channels.remove(&oldest);
            }
        }
    }

    /// Records the SCTP stream identifier a data channel was assigned.
    ///
    /// The accumulator is keyed by the channel's handle, which exists from creation, but
    /// `data_channel_identifier` is the W3C-defined *wire* value and is only known once the
    /// SCTP connected procedure assigns one (RFC 8832 section 6). This fills it in at that
    /// point; until then the report leaves the member out.
    pub(crate) fn set_data_channel_stream_id(&mut self, id: RTCDataChannelId, stream_id: StreamId) {
        if let Some(dc) = self.data_channels.get_mut(&id) {
            dc.data_channel_identifier = Some(stream_id);
        }
    }

    /// Gets or creates an ICE candidate pair accumulator.
    pub(crate) fn get_or_create_candidate_pair(
        &mut self,
        local_id: &str,
        remote_id: &str,
    ) -> &mut IceCandidatePairAccumulator {
        self.ice_candidate_pairs
            .entry(candidate_pair_stats_id(local_id, remote_id))
            .or_insert_with(|| IceCandidatePairAccumulator {
                transport_id: self.transport.transport_id.clone(),
                // W3C RTCIceCandidatePairStats: localCandidateId / remoteCandidateId are the ids
                // of the local-candidate / remote-candidate stats objects, which are registered
                // under these names (`add_ice_local_candidate` / `add_ice_remote_candidate`).
                local_candidate_id: local_candidate_stats_id(local_id),
                remote_candidate_id: remote_candidate_stats_id(remote_id),
                ..Default::default()
            })
    }

    /// Registers a local ICE candidate.
    pub(crate) fn register_local_candidate(
        &mut self,
        id: String,
        candidate: IceCandidateAccumulator,
    ) {
        self.local_candidates.insert(id, candidate);
    }

    /// Registers a remote ICE candidate.
    pub(crate) fn register_remote_candidate(
        &mut self,
        id: String,
        candidate: IceCandidateAccumulator,
    ) {
        self.remote_candidates.insert(id, candidate);
    }

    /// Deletes the candidates that are gone: those the ICE agent no longer holds and no
    /// candidate pair object names.
    ///
    /// webrtc-stats 7.1: a candidate object is deleted when the ICE transport does an ICE
    /// restart and the candidate is no longer a member of any non-deleted candidate pair. A
    /// restart is when the agent lets go of its candidates; the selected pair's stay until
    /// another pair is selected, as that pair does.
    pub(crate) fn retain_candidates(
        &mut self,
        local_held: &HashSet<String>,
        remote_held: &HashSet<String>,
    ) {
        let (mut local_paired, mut remote_paired) = (HashSet::new(), HashSet::new());
        for pair in self.ice_candidate_pairs.values() {
            local_paired.insert(pair.local_candidate_id.clone());
            remote_paired.insert(pair.remote_candidate_id.clone());
        }
        self.local_candidates
            .retain(|id, _| local_held.contains(id) || local_paired.contains(id));
        self.remote_candidates
            .retain(|id, _| remote_held.contains(id) || remote_paired.contains(id));
    }

    /// Registers a certificate.
    pub(crate) fn register_certificate(
        &mut self,
        fingerprint: String,
        cert: CertificateStatsAccumulator,
    ) {
        self.certificates.insert(fingerprint, cert);
    }

    /// Gets or creates a media source accumulator.
    pub(crate) fn get_or_create_media_source(
        &mut self,
        track_id: &str,
        kind: RtpCodecKind,
    ) -> &mut MediaSourceStatsAccumulator {
        self.media_sources
            .entry(track_id.to_string())
            .or_insert_with(|| MediaSourceStatsAccumulator {
                track_id: track_id.to_string(),
                kind,
                ..Default::default()
            })
    }

    /// Gets or creates an audio playout accumulator.
    pub(crate) fn get_or_create_audio_playout(
        &mut self,
        playout_id: &str,
    ) -> &mut AudioPlayoutStatsAccumulator {
        self.audio_playouts
            .entry(playout_id.to_string())
            .or_insert_with(|| AudioPlayoutStatsAccumulator {
                kind: RtpCodecKind::Audio,
                ..Default::default()
            })
    }

    /// Notes that the application wrote an RTP packet for the stream `ssrc` at `now`, before
    /// the interceptor chain has it (`totalPacketSendDelay` runs from here).
    pub(crate) fn on_rtp_written(&mut self, ssrc: SSRC, sequence_number: u16, now: Instant) {
        if let Some(stream) = self.outbound_rtp_streams.get_mut(&ssrc) {
            stream.on_rtp_written(sequence_number, now);
        }
    }

    /// Counts an RTP packet going out on `ssrc`: `overhead_bytes` is its header and padding,
    /// `payload_bytes` its payload, and `retransmission` says it answers a NACK.
    ///
    /// * On a stream's own SSRC it is a packet of the stream, and with `retransmission` (the
    ///   stream has no RTX stream, so the packet is sent again as it was, RFC 4585) one of its
    ///   retransmitted packets too.
    /// * On a stream's RTX SSRC it is a packet of that stream as well (webrtc-stats 7.1: an
    ///   RTX stream is no object of its own and counts in `packetsSent` / `bytesSent`). One
    ///   that repeats a packet is a retransmitted packet whose bytes are the repeated payload;
    ///   the original sequence number in front of it (RFC 4588 section 4) is header. One too
    ///   short to repeat anything (padding only: a bandwidth probe) is header and padding and
    ///   no retransmission.
    pub(crate) fn on_rtp_sent(
        &mut self,
        ssrc: SSRC,
        sequence_number: u16,
        overhead_bytes: usize,
        payload_bytes: usize,
        retransmission: bool,
        now: Instant,
    ) {
        if let Some(stream) = self.outbound_rtp_streams.get_mut(&ssrc) {
            stream.on_rtp_sent(overhead_bytes, payload_bytes, now);
            stream.on_sequence_number_sent(sequence_number);
            if retransmission {
                stream.on_rtx_sent(payload_bytes);
            } else {
                stream.on_written_rtp_sent(sequence_number, now);
            }
        } else if let Some(primary_ssrc) = self.outbound_rtx_ssrc_to_primary.get(&ssrc)
            && let Some(stream) = self.outbound_rtp_streams.get_mut(primary_ssrc)
        {
            match payload_bytes.checked_sub(RTX_OSN_BYTES) {
                Some(repeated_bytes) => {
                    stream.on_rtp_sent(overhead_bytes + RTX_OSN_BYTES, repeated_bytes, now);
                    stream.on_rtx_sent(repeated_bytes);
                }
                None => stream.on_rtp_sent(overhead_bytes + payload_bytes, 0, now),
            }
        }
    }

    /// The ECN codepoint to send an outgoing RTP packet `sequence_number` of `ssrc` with at
    /// `now`: ECT(1) or Not-ECT (`None`) as the stream's ECN validation decides (RFC 8888
    /// section 7, RFC 6679 sections 7.2-7.4: probes while initiating, every packet once
    /// confirmed, none after a failure), for a stream that marks at all
    /// ([`OutboundRtpStreamAccumulator::ect1_marking`]). An RTX packet is marked only while
    /// the stream it repairs marks every packet. ECT(1) packets are counted on the stream.
    pub(crate) fn ecn_for_rtp_sent(
        &mut self,
        ssrc: SSRC,
        sequence_number: u16,
        now: Instant,
    ) -> Option<shared::EcnCodepoint> {
        if !self.ecn {
            return None;
        }
        let (primary, own) = if self.outbound_rtp_streams.contains_key(&ssrc) {
            (ssrc, true)
        } else {
            (*self.outbound_rtx_ssrc_to_primary.get(&ssrc)?, false)
        };
        let stream = self.outbound_rtp_streams.get_mut(&primary)?;
        if !stream.ect1_marking {
            return None;
        }
        let validation = stream.ecn_validation.as_deref_mut()?;
        let marked = if own {
            validation.on_send(now, sequence_number)
        } else {
            validation.marks_all()
        };
        if !marked {
            return None;
        }
        // The codepoint the peer asked for (`a=ecn-capable-rtp ... ect=`, RFC 6679 section
        // 6.1), ECT(1) unless negotiated otherwise.
        let codepoint = stream.ect_codepoint.unwrap_or(shared::EcnCodepoint::Ect1);
        if codepoint == shared::EcnCodepoint::Ect1 {
            stream.on_ect1_sent();
        }
        Some(codepoint)
    }

    /// Counts the ECN codepoint an RTP packet of the inbound stream `ssrc` arrived with.
    pub(crate) fn on_rtp_ecn_received(&mut self, ssrc: SSRC, ecn: Option<shared::EcnCodepoint>) {
        if self.ecn
            && let Some(stream) = self.inbound_rtp_streams.get_mut(&ssrc)
        {
            stream.on_ecn_received(ecn);
        }
    }

    /// Records whether the inbound stream `ssrc`'s codec negotiated RFC 8888 feedback.
    pub(crate) fn set_inbound_ccfb(&mut self, ssrc: SSRC, negotiated: bool) {
        if let Some(stream) = self.inbound_rtp_streams.get_mut(&ssrc) {
            stream.ccfb_negotiated = negotiated;
        }
    }

    /// Records whether the outbound stream `ssrc`'s codec negotiated RFC 8888 feedback, and
    /// whether its section negotiated ECN (`ecn`: the initiation, RFC 6679 section 6.1.1,
    /// `a=ecn-capable-rtp`); with ECN on and both negotiated, its packets are sent ECT(1).
    pub(crate) fn set_outbound_ccfb(
        &mut self,
        ssrc: SSRC,
        negotiated: bool,
        ecn_negotiated: Option<crate::peer_connection::sdp::ecn::NegotiatedEcn>,
    ) {
        let ecn = self.ecn && ecn_negotiated.is_some();
        let initiation = ecn_negotiated.map_or(self.ecn_initiation, |n| n.initiation);
        if let Some(stream) = self.outbound_rtp_streams.get_mut(&ssrc) {
            stream.ect_codepoint = ecn_negotiated.map(|n| n.codepoint);
            stream.ccfb_negotiated = negotiated;
            stream.ect1_marking = ecn && negotiated;
            // A renegotiation that keeps `ack ccfb` keeps where the stream is in the
            // procedure; one that drops it ends it.
            if !stream.ect1_marking {
                stream.ecn_validation = None;
            } else if stream.ecn_validation.is_none() {
                stream.ecn_validation = Some(Box::new(interceptor::EcnValidation::new(initiation)));
            }
        }
    }

    /// Counts an RTP packet that arrived on `ssrc` as it is (not a retransmission that was
    /// taken out of its RTX packet:
    /// [`on_retransmission_received`](Self::on_retransmission_received) counts that):
    /// `overhead_bytes` is its header and padding, `payload_bytes` its payload.
    ///
    /// * On a stream's own SSRC it is a packet of the stream.
    /// * On a stream's FEC SSRC it is a packet of that stream too, and a FEC packet
    ///   (webrtc-stats 7.1: a FEC stream is no object of its own; `fecBytesReceived` is a
    ///   subset of `bytesReceived`).
    /// * On a stream's RTX SSRC, still there because it repeats no packet (padding only, a
    ///   bandwidth probe: RFC 4588 section 4), it is a packet of the stream made of header and
    ///   padding, and not a retransmission.
    ///
    /// Returns whether a stream counted it.
    pub(crate) fn on_rtp_received(
        &mut self,
        ssrc: SSRC,
        overhead_bytes: usize,
        payload_bytes: usize,
        now: Instant,
    ) -> bool {
        if let Some(stream) = self.inbound_rtp_streams.get_mut(&ssrc) {
            stream.on_rtp_received(overhead_bytes, payload_bytes, now);
            return true;
        }
        if let Some(primary_ssrc) = self.fec_ssrc_to_primary.get(&ssrc)
            && let Some(stream) = self.inbound_rtp_streams.get_mut(primary_ssrc)
        {
            stream.on_fec_received(overhead_bytes, payload_bytes, now);
            return true;
        }
        if let Some(primary_ssrc) = self.inbound_rtx_ssrc_to_primary.get(&ssrc)
            && let Some(stream) = self.inbound_rtp_streams.get_mut(primary_ssrc)
        {
            stream.on_rtx_padding_received(overhead_bytes + payload_bytes, now);
            return true;
        }
        false
    }

    /// Counts a retransmission that arrived in an RTX packet for the stream `primary_ssrc`:
    /// `overhead_bytes` is the RTX packet's header and padding, `payload_bytes` its payload,
    /// which starts with the original sequence number (RFC 4588 section 4).
    ///
    /// It is a packet of the stream (`packetsReceived` includes retransmissions) and one of
    /// its retransmitted packets, whose bytes are the repeated payload; the original sequence
    /// number is header. Returns whether the stream exists.
    pub(crate) fn on_retransmission_received(
        &mut self,
        primary_ssrc: SSRC,
        overhead_bytes: usize,
        payload_bytes: usize,
        now: Instant,
    ) -> bool {
        let Some(stream) = self.inbound_rtp_streams.get_mut(&primary_ssrc) else {
            return false;
        };
        let repeated_bytes = payload_bytes.saturating_sub(RTX_OSN_BYTES);
        stream.on_rtp_received(
            overhead_bytes + (payload_bytes - repeated_bytes),
            repeated_bytes,
            now,
        );
        stream.on_rtx_received(repeated_bytes);
        true
    }

    /// Counts a datagram of `bytes` bytes the application's socket refused to send, on the
    /// candidate pair in use (`packetsDiscardedOnSend`, `bytesDiscardedOnSend`). Returns
    /// `false`, and counts nothing, while no pair is selected.
    pub(crate) fn on_send_discarded(&mut self, bytes: usize) -> bool {
        match self
            .ice_candidate_pairs
            .get_mut(&self.transport.selected_candidate_pair_id)
        {
            Some(pair) => {
                pair.on_packet_discarded(bytes);
                true
            }
            None => false,
        }
    }

    // ========================================================================
    // Application-provided stats updates
    // ========================================================================

    /// Merges application-provided decoder stats into an inbound stream; `false` when no
    /// inbound stream has that SSRC.
    pub(crate) fn update_decoder_stats(&mut self, ssrc: SSRC, stats: DecoderStatsUpdate) -> bool {
        match self.inbound_rtp_streams.get_mut(&ssrc) {
            Some(stream) => {
                stream.decoder_stats.merge(stats);
                true
            }
            None => false,
        }
    }

    /// Merges application-provided encoder stats into an outbound stream; `false` when no
    /// outbound stream has that SSRC.
    pub(crate) fn update_encoder_stats(&mut self, ssrc: SSRC, stats: EncoderStatsUpdate) -> bool {
        match self.outbound_rtp_streams.get_mut(&ssrc) {
            Some(stream) => {
                stream.encoder_stats.merge(stats);
                true
            }
            None => false,
        }
    }

    /// Merges application-provided audio receiver stats into an inbound stream; `false` when
    /// no inbound stream has that SSRC.
    pub(crate) fn update_audio_receiver_stats(
        &mut self,
        ssrc: SSRC,
        stats: AudioReceiverStatsUpdate,
    ) -> bool {
        match self.inbound_rtp_streams.get_mut(&ssrc) {
            Some(stream) => {
                stream.audio_receiver_stats.merge(stats);
                true
            }
            None => false,
        }
    }

    /// Makes the media sources those of `attached`: the (transceiver, track id, kind) of every
    /// sender that has a track.
    ///
    /// webrtc-stats 8.11: a media-source object exists from the time its track is attached to
    /// a sender until it is attached to none. A track newly attached gets an object, which has
    /// the track's id and kind until the application supplies what it captured; the object of
    /// a track no sender has any more is deleted. Each sender's outbound streams name their
    /// track's object (`mediaSourceId`).
    pub(crate) fn sync_media_sources(
        &mut self,
        attached: &[(RTCRtpTransceiverId, String, RtpCodecKind)],
    ) {
        self.media_sources.retain(|track_id, _| {
            attached
                .iter()
                .any(|(_, attached_id, _)| attached_id == track_id)
        });
        for stream in self.outbound_rtp_streams.values_mut() {
            stream.media_source_id.clear();
        }
        for (transceiver_id, track_id, kind) in attached {
            if !matches!(kind, RtpCodecKind::Audio | RtpCodecKind::Video) {
                continue;
            }
            let source = self.get_or_create_media_source(track_id, *kind);
            source.transceiver_id = Some(*transceiver_id);
            self.link_media_source(track_id, *transceiver_id);
        }
    }

    /// Names the media source for `track_id` as the source of the outbound streams of
    /// `transceiver_id` (`mediaSourceId`).
    fn link_media_source(&mut self, track_id: &str, transceiver_id: RTCRtpTransceiverId) {
        let id = media_source_stats_id(track_id);
        for stream in self.outbound_rtp_streams.values_mut() {
            if stream.transceiver_id == transceiver_id {
                stream.media_source_id = id.clone();
            }
        }
    }

    /// Merges application-provided capture stats into the audio media source of the track
    /// `track_id`, which the sender of `transceiver_id` sends.
    pub(crate) fn update_audio_source_stats(
        &mut self,
        track_id: &str,
        transceiver_id: RTCRtpTransceiverId,
        stats: AudioSourceStatsUpdate,
    ) {
        self.link_media_source(track_id, transceiver_id);
        let source = self.get_or_create_media_source(track_id, RtpCodecKind::Audio);
        source.transceiver_id = Some(transceiver_id);
        if stats.audio_level.is_some() {
            source.audio_level = stats.audio_level;
        }
        if stats.total_audio_energy.is_some() {
            source.total_audio_energy = stats.total_audio_energy;
        }
        if stats.total_samples_duration.is_some() {
            source.total_samples_duration = stats.total_samples_duration;
        }
        if stats.echo_return_loss.is_some() {
            source.echo_return_loss = stats.echo_return_loss;
        }
        if stats.echo_return_loss_enhancement.is_some() {
            source.echo_return_loss_enhancement = stats.echo_return_loss_enhancement;
        }
    }

    /// Merges application-provided capture stats into the video media source of the track
    /// `track_id`, which the sender of `transceiver_id` sends.
    pub(crate) fn update_video_source_stats(
        &mut self,
        track_id: &str,
        transceiver_id: RTCRtpTransceiverId,
        stats: VideoSourceStatsUpdate,
    ) {
        self.link_media_source(track_id, transceiver_id);
        let source = self.get_or_create_media_source(track_id, RtpCodecKind::Video);
        source.transceiver_id = Some(transceiver_id);
        if stats.width.is_some() {
            source.width = stats.width;
        }
        if stats.height.is_some() {
            source.height = stats.height;
        }
        if stats.frames.is_some() {
            source.frames = stats.frames;
        }
        if stats.frames_per_second.is_some() {
            source.frames_per_second = stats.frames_per_second;
        }
    }

    /// Merges application-provided playout stats into an audio playout object, creating it on
    /// first use, and names it as the playout of each inbound stream in `inbound_ssrcs`.
    pub(crate) fn update_audio_playout_stats(
        &mut self,
        playout_id: &str,
        inbound_ssrcs: &[SSRC],
        stats: AudioPlayoutStatsUpdate,
    ) {
        let playout = self.get_or_create_audio_playout(playout_id);
        if stats.synthesized_samples_duration.is_some() {
            playout.synthesized_samples_duration = stats.synthesized_samples_duration;
        }
        if stats.synthesized_samples_events.is_some() {
            playout.synthesized_samples_events = stats.synthesized_samples_events;
        }
        if stats.total_samples_duration.is_some() {
            playout.total_samples_duration = stats.total_samples_duration;
        }
        if stats.total_playout_delay.is_some() {
            playout.total_playout_delay = stats.total_playout_delay;
        }
        if stats.total_samples_count.is_some() {
            playout.total_samples_count = stats.total_samples_count;
        }
        for ssrc in inbound_ssrcs {
            if let Some(stream) = self.inbound_rtp_streams.get_mut(ssrc) {
                stream.playout_id = Some(playout_id.to_string());
            }
        }
    }

    /// Syncs the candidate pair stats with the ICE agent's pairs: each pair's STUN transaction
    /// counters, round trip times, state and nomination come from the agent, while the packet
    /// and byte counters are the ones the pipeline counts on the selected pair.
    ///
    /// A pair the agent no longer holds (an ICE restart drops its pairs) is dropped from the
    /// stats too, except the transport's selected pair, whose counters describe the path still
    /// in use until another is selected.
    pub(crate) fn sync_ice_candidate_pairs(&mut self, pairs: &[CandidatePairStats]) {
        let held: std::collections::HashSet<String> = pairs
            .iter()
            .map(|cp| candidate_pair_stats_id(&cp.local_candidate_id, &cp.remote_candidate_id))
            .collect();
        let selected = self.transport.selected_candidate_pair_id.clone();
        self.ice_candidate_pairs
            .retain(|id, _| held.contains(id) || *id == selected);

        for cp in pairs {
            let pair =
                self.get_or_create_candidate_pair(&cp.local_candidate_id, &cp.remote_candidate_id);
            pair.requests_sent = cp.requests_sent;
            pair.requests_received = cp.requests_received;
            pair.responses_sent = cp.responses_sent;
            pair.responses_received = cp.responses_received;
            pair.consent_requests_sent = cp.consent_requests_sent;
            pair.total_round_trip_time = cp.total_round_trip_time;
            pair.current_round_trip_time = cp.current_round_trip_time;
            pair.state = cp.state.into();
            pair.nominated = cp.nominated;
        }
    }

    /// Sets the congestion controller's estimate: the target bitrate of the outbound streams
    /// and the selected candidate pair's `availableOutgoingBitrate` (webrtc-stats: the bitrate
    /// the congestion control estimates for all the outgoing RTP streams on the pair).
    pub(crate) fn on_target_bitrate(&mut self, bits_per_second: f64) {
        // The estimate is one number for the connection, while `target_bitrate` is reported
        // per outbound stream — with a single stream they are the same thing. Splitting one
        // estimate across simulcast layers is an allocation problem, and belongs wherever that
        // allocation is made rather than here.
        for stream in self.outbound_rtp_streams.values_mut() {
            stream.target_bitrate = bits_per_second;
        }
        if let Some(pair) = self
            .ice_candidate_pairs
            .get_mut(&self.transport.selected_candidate_pair_id)
        {
            pair.available_outgoing_bitrate = bits_per_second;
        }
    }

    /// Sets the receive-side estimate the application's congestion control made for the
    /// incoming streams: the selected candidate pair's `availableIncomingBitrate`. Returns
    /// `false`, and sets nothing, while no pair is selected.
    pub(crate) fn on_available_incoming_bitrate(&mut self, bits_per_second: f64) -> bool {
        match self
            .ice_candidate_pairs
            .get_mut(&self.transport.selected_candidate_pair_id)
        {
            Some(pair) => {
                pair.available_incoming_bitrate = bits_per_second;
                true
            }
            None => false,
        }
    }

    /// The transport selected the candidate pair `pair_id` (`None`: it has none any more).
    ///
    /// The pair it leaves no longer carries the streams the bitrate estimates were made for
    /// (webrtc-stats: `availableOutgoingBitrate` / `availableIncomingBitrate` are those of a
    /// pair in use), so it gives them up.
    pub(crate) fn on_selected_candidate_pair(&mut self, pair_id: Option<String>) {
        let previous = self.transport.selected_candidate_pair_id.clone();
        if pair_id.as_deref() == Some(previous.as_str()) {
            return;
        }
        if let Some(pair) = self.ice_candidate_pairs.get_mut(&previous) {
            pair.available_outgoing_bitrate = 0.0;
            pair.available_incoming_bitrate = 0.0;
        }
        match pair_id {
            Some(pair_id) => self.transport.on_selected_candidate_pair_changed(pair_id),
            None => self.transport.on_selected_candidate_pair_lost(),
        }
    }

    // ========================================================================
    // Codec stats methods
    // ========================================================================

    /// Registers the codec `payload_type` means in `direction` on the transport, and returns
    /// the id of its stats object.
    ///
    /// A payload type has one codec object on a transport (webrtc-stats 8.3), which both
    /// directions share. Only when the two directions give it different parameters (another
    /// `sdpFmtpLine`) does the second one registered get an object of its own.
    fn register_codec(
        &mut self,
        direction: CodecDirection,
        codec: &RTCRtpCodec,
        payload_type: PayloadType,
    ) -> String {
        let transport_id = self.transport.transport_id.clone();
        let accumulator = CodecStatsAccumulator {
            transport_id: transport_id.clone(),
            ..CodecStatsAccumulator::from_codec(codec, payload_type)
        };
        let directional_id =
            CodecStatsAccumulator::generate_id(&transport_id, direction, payload_type);
        if self.codecs.contains_key(&directional_id) {
            return directional_id;
        }
        let shared_id = CodecStatsAccumulator::shared_id(&transport_id, payload_type);
        match self.codecs.get(&shared_id) {
            Some(shared) if !shared.same_codec(&accumulator) => {
                self.codecs.insert(directional_id.clone(), accumulator);
                directional_id
            }
            Some(_) => shared_id,
            None => {
                self.codecs.insert(shared_id.clone(), accumulator);
                shared_id
            }
        }
    }

    /// Registers a codec for an inbound RTP stream and sets the codec_id.
    ///
    /// Per W3C spec, codecs are only exposed when referenced by an RTP stream.
    /// This method registers the codec (if not already registered) and links it
    /// to the inbound RTP stream.
    pub(crate) fn register_inbound_codec(
        &mut self,
        ssrc: SSRC,
        codec: &RTCRtpCodec,
        payload_type: PayloadType,
    ) {
        if !self.inbound_rtp_streams.contains_key(&ssrc) {
            return;
        }
        let codec_id = self.register_codec(CodecDirection::Receive, codec, payload_type);
        // Link the codec to the inbound RTP stream; its clock rate is what the RTCP jitter is
        // counted in
        if let Some(stream) = self.inbound_rtp_streams.get_mut(&ssrc) {
            stream.codec_id = codec_id;
            stream.clock_rate = codec.clock_rate;
        }
    }

    /// Registers a codec for an outbound RTP stream and sets the codec_id.
    ///
    /// Per W3C spec, codecs are only exposed when referenced by an RTP stream.
    /// This method registers the codec (if not already registered) and links it
    /// to the outbound RTP stream.
    pub(crate) fn register_outbound_codec(
        &mut self,
        ssrc: SSRC,
        codec: &RTCRtpCodec,
        payload_type: PayloadType,
    ) {
        if !self.outbound_rtp_streams.contains_key(&ssrc) {
            return;
        }
        let codec_id = self.register_codec(CodecDirection::Send, codec, payload_type);
        // Link the codec to the outbound RTP stream; its clock rate is what the RTCP jitter is
        // counted in
        if let Some(stream) = self.outbound_rtp_streams.get_mut(&ssrc) {
            stream.codec_id = codec_id;
            stream.clock_rate = codec.clock_rate;
        }
    }

    /// A transceiver was removed from the peer connection's set of transceivers: the streams
    /// and media sources of the transceivers after it follow their ids down by one. The
    /// removed transceiver's own (stopped) streams keep their stats in the full report but
    /// no longer answer to a sender or receiver selector, which names a live transceiver.
    pub(crate) fn transceiver_removed(&mut self, removed: RTCRtpTransceiverId) {
        let remap = |id: &mut RTCRtpTransceiverId| {
            if *id == removed {
                *id = RTCRtpTransceiverId::MAX;
            } else if *id > removed && *id != RTCRtpTransceiverId::MAX {
                *id -= 1;
            }
        };
        for stream in self.inbound_rtp_streams.values_mut() {
            remap(&mut stream.transceiver_id);
        }
        for stream in self.outbound_rtp_streams.values_mut() {
            remap(&mut stream.transceiver_id);
        }
        for source in self.media_sources.values_mut() {
            if let Some(id) = source.transceiver_id.as_mut() {
                remap(id);
            }
        }
    }

    /// A sender's stream moved from SSRC `old` to `new` after a collision (RFC 3550 section
    /// 8.2): the old stream's stats go, and a new stream with the same identity (kind, mid,
    /// rid, encoding, RTX SSRC, transceiver) starts under `new`. Nothing when `old` has none.
    pub(crate) fn replace_outbound_rtp_stream(&mut self, old: SSRC, new: SSRC) {
        let Some(stream) = self.outbound_rtp_streams.get(&old) else {
            return;
        };
        let (kind, mid, rid, encoding_index, rtx_ssrc, transceiver_id) = (
            stream.kind,
            stream.mid.clone(),
            stream.rid.clone(),
            stream.encoding_index,
            stream.rtx_ssrc,
            stream.transceiver_id,
        );
        self.remove_outbound_rtp_stream(old);
        self.get_or_create_outbound_rtp_streams(
            new,
            kind,
            &mid,
            &rid,
            encoding_index,
            rtx_ssrc,
            transceiver_id,
        );
    }

    /// Removes an outbound stream's stats, its remote-inbound object with them, and its RTX
    /// reverse-lookup entry.
    pub(crate) fn remove_outbound_rtp_stream(&mut self, ssrc: SSRC) {
        if let Some(stream) = self.outbound_rtp_streams.remove(&ssrc) {
            self.streams_retired += 1;
            dissociate(
                &mut self.outbound_rtx_ssrc_to_primary,
                stream.rtx_ssrc,
                ssrc,
            );
        }
    }

    /// Drops the stats of every RTP stream whose SSRC is no longer bound: inbound streams not
    /// in `inbound_live`, outbound streams not in `outbound_live`.
    ///
    /// webrtc-stats ties an RTP stream's stats objects to the SSRC being in use; without this
    /// the per-SSRC maps only ever grew, one entry for every SSRC a peer ever had bound.
    pub(crate) fn retire_rtp_streams(
        &mut self,
        inbound_live: &std::collections::HashSet<SSRC>,
        outbound_live: &std::collections::HashSet<SSRC>,
    ) {
        let retired_inbound: Vec<SSRC> = self
            .inbound_rtp_streams
            .keys()
            .filter(|ssrc| !inbound_live.contains(ssrc))
            .copied()
            .collect();
        for ssrc in retired_inbound {
            self.remove_inbound_rtp_stream(ssrc);
        }
        let retired_outbound: Vec<SSRC> = self
            .outbound_rtp_streams
            .keys()
            .filter(|ssrc| !outbound_live.contains(ssrc))
            .copied()
            .collect();
        for ssrc in retired_outbound {
            self.remove_outbound_rtp_stream(ssrc);
        }
        // And any entry left naming a stream that is not there (an RTX SSRC announced for a
        // stream that never got stats, or one that has gone).
        let inbound = &self.inbound_rtp_streams;
        self.inbound_rtx_ssrc_to_primary
            .retain(|_, primary| inbound.contains_key(primary));
        self.fec_ssrc_to_primary
            .retain(|_, primary| inbound.contains_key(primary));
        let outbound = &self.outbound_rtp_streams;
        self.outbound_rtx_ssrc_to_primary
            .retain(|_, primary| outbound.contains_key(primary));
    }

    /// Removes codecs that are no longer referenced by any RTP stream.
    ///
    /// Per W3C spec, when there is no longer any reference to an RTCCodecStats,
    /// the stats object should be deleted.
    pub(crate) fn cleanup_unreferenced_codecs(&mut self) {
        // Collect all referenced codec IDs
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();

        for stream in self.inbound_rtp_streams.values() {
            if !stream.codec_id.is_empty() {
                referenced.insert(stream.codec_id.clone());
            }
        }

        for stream in self.outbound_rtp_streams.values() {
            if !stream.codec_id.is_empty() {
                referenced.insert(stream.codec_id.clone());
            }
        }

        // Remove codecs that are not referenced
        self.codecs.retain(|id, _| referenced.contains(id));
    }
}

/// Maps `repair_ssrc` to `primary`, dropping the entry of `previous`, the repair SSRC
/// `primary` had before: a stream has one RTX (or FEC) SSRC at a time, so the map holds no more
/// entries than there are streams.
fn associate(
    map: &mut HashMap<SSRC, SSRC>,
    previous: Option<SSRC>,
    repair_ssrc: SSRC,
    primary: SSRC,
) {
    if let Some(previous) = previous
        && previous != repair_ssrc
    {
        dissociate(map, Some(previous), primary);
    }
    map.insert(repair_ssrc, primary);
}

/// Drops `repair_ssrc`'s entry if it still names `primary`.
fn dissociate(map: &mut HashMap<SSRC, SSRC>, repair_ssrc: Option<SSRC>, primary: SSRC) {
    if let Some(repair_ssrc) = repair_ssrc
        && map.get(&repair_ssrc) == Some(&primary)
    {
        map.remove(&repair_ssrc);
    }
}

/// The two bytes an RTX packet's payload starts with: the original sequence number (RFC 4588
/// section 4).
const RTX_OSN_BYTES: usize = 2;

/// The stats id of the candidate-pair object for the ICE agent's candidates `local_id` and
/// `remote_id`.
pub(crate) fn candidate_pair_stats_id(local_id: &str, remote_id: &str) -> String {
    format!("RTCIceCandidatePair_{local_id}_{remote_id}")
}

/// The stats id of the local-candidate object for the ICE agent's candidate `id`.
pub(crate) fn local_candidate_stats_id(id: &str) -> String {
    format!("RTCLocalIceCandidate_{id}")
}

/// The stats id of the remote-candidate object for the ICE agent's candidate `id`.
pub(crate) fn remote_candidate_stats_id(id: &str) -> String {
    format!("RTCRemoteIceCandidate_{id}")
}
