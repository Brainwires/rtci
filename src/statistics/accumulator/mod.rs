//! Statistics accumulator module.
//!
//! This module provides incremental statistics accumulation for WebRTC
//! peer connections. The accumulators are updated as events occur in the
//! handler pipeline, and snapshots can be taken at any time to produce
//! immutable stats reports.

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
mod transport;

pub(crate) use certificate::{CertificateStatsAccumulator, base64_encode};
pub(crate) use codec::{CodecDirection, CodecStatsAccumulator};
pub(crate) use data_channel::DataChannelStatsAccumulator;
pub(crate) use ice_candidate::IceCandidateAccumulator;
pub(crate) use ice_candidate_pair::IceCandidatePairAccumulator;
pub use media::app_provided::*;
pub(crate) use media::audio_playout::AudioPlayoutStatsAccumulator;
pub(crate) use media::media_source::{MediaSourceStatsAccumulator, media_source_stats_id};
pub(crate) use peer_connection::PeerConnectionStatsAccumulator;
pub(crate) use rtp_stream::inbound::{InboundRtpStreamAccumulator, inbound_stats_id};
pub(crate) use rtp_stream::outbound::{OutboundRtpStreamAccumulator, outbound_stats_id};
pub(crate) use transport::TransportStatsAccumulator;

use crate::data_channel::RTCDataChannelId;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use crate::rtp_transceiver::{PayloadType, RTCRtpTransceiverId, SSRC};
use crate::statistics::StatsSelector;
use crate::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use ice::CandidatePairStats;
use sctp::StreamId;
use std::collections::HashMap;
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
        for (id, candidate) in &self.remote_candidates {
            entries.push(RTCStatsReportEntry::RemoteCandidate(
                candidate.snapshot_remote(now, id),
            ));
        }

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
        for (ssrc, stream) in &self.inbound_rtp_streams {
            let id = inbound_stats_id(stream.kind, *ssrc);
            entries.push(RTCStatsReportEntry::InboundRtp(stream.snapshot(now, &id)));
            if stream.has_remote() {
                entries.push(RTCStatsReportEntry::RemoteOutboundRtp(
                    stream.snapshot_remote(now),
                ));
            }
        }

        // Outbound RTP stream stats, each with its remote-inbound object once a reception
        // report has created it (webrtc-stats 6.1)
        for (ssrc, stream) in &self.outbound_rtp_streams {
            let id = outbound_stats_id(stream.kind, *ssrc);
            entries.push(RTCStatsReportEntry::OutboundRtp(stream.snapshot(now, &id)));
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

        RTCStatsReport::new(entries)
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
        use std::collections::HashSet;

        let mut entries = Vec::new();
        let mut referenced_codec_ids = HashSet::new();
        let mut has_streams = false;

        // Collect outbound RTP streams for this sender
        for (ssrc, stream) in &self.outbound_rtp_streams {
            if stream.transceiver_id == transceiver_id {
                has_streams = true;
                let id = outbound_stats_id(stream.kind, *ssrc);
                entries.push(RTCStatsReportEntry::OutboundRtp(stream.snapshot(now, &id)));
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
            for (id, candidate) in &self.remote_candidates {
                entries.push(RTCStatsReportEntry::RemoteCandidate(
                    candidate.snapshot_remote(now, id),
                ));
            }

            // Certificate stats (referenced by transport)
            for (id, cert) in &self.certificates {
                entries.push(RTCStatsReportEntry::Certificate(cert.snapshot(now, id)));
            }
        }

        RTCStatsReport::new(entries)
    }

    /// Creates a snapshot for a specific receiver (inbound streams).
    fn snapshot_for_receiver(
        &self,
        now: Instant,
        transceiver_id: RTCRtpTransceiverId,
    ) -> RTCStatsReport {
        use std::collections::HashSet;

        let mut entries = Vec::new();
        let mut referenced_codec_ids = HashSet::new();
        let mut referenced_playout_ids: HashSet<String> = HashSet::new();
        let mut has_streams = false;

        // Collect inbound RTP streams for this receiver
        for (ssrc, stream) in &self.inbound_rtp_streams {
            if stream.transceiver_id == transceiver_id {
                has_streams = true;
                let id = inbound_stats_id(stream.kind, *ssrc);
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
            for (id, candidate) in &self.remote_candidates {
                entries.push(RTCStatsReportEntry::RemoteCandidate(
                    candidate.snapshot_remote(now, id),
                ));
            }

            // Certificate stats (referenced by transport)
            for (id, cert) in &self.certificates {
                entries.push(RTCStatsReportEntry::Certificate(cert.snapshot(now, id)));
            }
        }

        RTCStatsReport::new(entries)
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

    /// Drops the inbound stream accumulator for `ssrc` and the RTX / FEC lookups that point at
    /// it, once the stream is no longer bound (its rid moved to another SSRC).
    pub(crate) fn remove_inbound_rtp_stream(&mut self, ssrc: SSRC) {
        self.inbound_rtp_streams.remove(&ssrc);
        self.rtx_ssrc_to_primary
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
                active: true,
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
                data_channel_identifier: 0,
                label: label.to_string(),
                protocol: protocol.to_string(),
                ..Default::default()
            })
    }

    /// Records the SCTP stream identifier a data channel was assigned.
    ///
    /// The accumulator is keyed by the channel's handle, which exists from creation, but
    /// `data_channel_identifier` is the W3C-defined *wire* value and is only known once the
    /// SCTP connected procedure assigns one (RFC 8832 section 6). This fills it in at that
    /// point; until then it reads 0.
    pub(crate) fn set_data_channel_stream_id(&mut self, id: RTCDataChannelId, stream_id: StreamId) {
        if let Some(dc) = self.data_channels.get_mut(&id) {
            dc.data_channel_identifier = stream_id;
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

    pub(crate) fn on_rtx_packet_sent_if_rtx(
        &mut self,
        rtx_ssrc: SSRC,
        payload_bytes: usize,
    ) -> bool {
        if let Some(primary_ssrc) = self.outbound_rtx_ssrc_to_primary.get(&rtx_ssrc)
            && let Some(stream) = self.outbound_rtp_streams.get_mut(primary_ssrc)
        {
            stream.on_rtx_sent(payload_bytes);
            return true;
        }
        false
    }

    /// Tracks an RTX packet received for an inbound stream.
    ///
    /// Call this when an RTP packet is received with an SSRC that matches
    /// a stream's `rtx_ssrc`. This updates the retransmission stats.
    ///
    /// Returns `true` if the RTX packet was tracked, `false` if no matching stream found.
    pub(crate) fn on_rtx_packet_received_if_rtx(
        &mut self,
        rtx_ssrc: SSRC,
        payload_bytes: usize,
    ) -> bool {
        if let Some(primary_ssrc) = self.inbound_rtx_ssrc_to_primary.get(&rtx_ssrc)
            && let Some(stream) = self.inbound_rtp_streams.get_mut(primary_ssrc)
        {
            stream.on_rtx_received(payload_bytes);
            return true;
        }
        false
    }

    /// Tracks a FEC packet received for an inbound stream.
    ///
    /// Call this when an RTP packet is received with an SSRC that matches
    /// a stream's `fec_ssrc`. This updates the FEC stats.
    ///
    /// Returns `true` if the FEC packet was tracked, `false` if no matching stream found.
    pub(crate) fn on_fec_packet_received_if_fec(
        &mut self,
        fec_ssrc: SSRC,
        payload_bytes: usize,
    ) -> bool {
        if let Some(primary_ssrc) = self.fec_ssrc_to_primary.get(&fec_ssrc)
            && let Some(stream) = self.inbound_rtp_streams.get_mut(primary_ssrc)
        {
            stream.on_fec_received(payload_bytes);
            return true;
        }
        false
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

    // ========================================================================
    // Codec stats methods
    // ========================================================================

    /// Registers a codec for an inbound RTP stream and sets the codec_id.
    ///
    /// Per W3C spec, codecs are only exposed when referenced by an RTP stream.
    /// This method registers the codec (if not already registered) and links it
    /// to the inbound RTP stream.
    ///
    /// # Parameters
    ///
    /// * `ssrc` - The SSRC of the inbound RTP stream
    /// * `codec` - The codec information
    /// * `payload_type` - The payload type for this codec
    pub(crate) fn register_inbound_codec(
        &mut self,
        ssrc: SSRC,
        codec: &RTCRtpCodec,
        payload_type: PayloadType,
    ) {
        let transport_id = self.transport.transport_id.clone();
        let codec_id = CodecStatsAccumulator::generate_id(
            &transport_id,
            CodecDirection::Receive,
            payload_type,
        );

        // Register the codec if not already present
        self.codecs
            .entry(codec_id.clone())
            .or_insert_with(|| CodecStatsAccumulator {
                transport_id: transport_id.clone(),
                ..CodecStatsAccumulator::from_codec(codec, payload_type)
            });

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
    ///
    /// # Parameters
    ///
    /// * `ssrc` - The SSRC of the outbound RTP stream
    /// * `codec` - The codec information
    /// * `payload_type` - The payload type for this codec
    pub(crate) fn register_outbound_codec(
        &mut self,
        ssrc: SSRC,
        codec: &RTCRtpCodec,
        payload_type: PayloadType,
    ) {
        let transport_id = self.transport.transport_id.clone();
        let codec_id =
            CodecStatsAccumulator::generate_id(&transport_id, CodecDirection::Send, payload_type);

        // Register the codec if not already present
        self.codecs
            .entry(codec_id.clone())
            .or_insert_with(|| CodecStatsAccumulator {
                transport_id: transport_id.clone(),
                ..CodecStatsAccumulator::from_codec(codec, payload_type)
            });

        // Link the codec to the outbound RTP stream; its clock rate is what the RTCP jitter is
        // counted in
        if let Some(stream) = self.outbound_rtp_streams.get_mut(&ssrc) {
            stream.codec_id = codec_id;
            stream.clock_rate = codec.clock_rate;
        }
    }

    /// Removes an inbound stream's stats, its remote-outbound object with them, and its RTX /
    /// FEC reverse-lookup entries.
    pub(crate) fn remove_inbound_rtp_stream(&mut self, ssrc: SSRC) {
        if let Some(stream) = self.inbound_rtp_streams.remove(&ssrc) {
            dissociate(&mut self.inbound_rtx_ssrc_to_primary, stream.rtx_ssrc, ssrc);
            dissociate(&mut self.fec_ssrc_to_primary, stream.fec_ssrc, ssrc);
        }
    }

    /// Removes an outbound stream's stats, its remote-inbound object with them, and its RTX
    /// reverse-lookup entry.
    pub(crate) fn remove_outbound_rtp_stream(&mut self, ssrc: SSRC) {
        if let Some(stream) = self.outbound_rtp_streams.remove(&ssrc) {
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
