//! MediaStream API
//!
//! This module implements the Media Capture and Streams API as defined in the
//! [W3C Media Capture and Streams specification](https://www.w3.org/TR/mediacapture-streams/).
//!
//! The API provides the means to access media streams from local or remote media devices,
//! including audio and video tracks. Each [`MediaStream`] can contain multiple
//! [`MediaStreamTrack`] objects representing individual media sources.
//!
//! # Core Concepts
//!
//! - **[`MediaStream`]**: A container for one or more [`MediaStreamTrack`] objects
//! - **[`MediaStreamTrack`]**: Represents a single media track (audio or video)
//! - **[`MediaTrackCapabilities`]**: The inherent capabilities of a track
//! - **[`MediaTrackConstraints`]**: Constraints to apply to a track
//! - **[`MediaStreamTrackState`]**: The lifecycle state of a track (live or ended)
//! - **[`MediaTrackSettings`]**: Current settings of a track
//! - **[`MediaTrackSupportConstraints`]**: Indicates which constraints are supported by the user agent
//!
//! # Examples
//!
//! ## Creating a media stream with tracks
//!
//! ```
//! use rtc::media_stream::{MediaStream, MediaStreamId};
//! use rtc::media_stream::MediaStreamTrack;
//! use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
//! use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RTCRtpCodingParameters};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create audio track
//! let audio_track = MediaStreamTrack::new(
//!     "stream-id".to_string(),
//!     "audio-track-id".to_string(),
//!     "Microphone".to_string(),
//!     RtpCodecKind::Audio,
//!     vec![RTCRtpEncodingParameters {
//!         rtp_coding_parameters: RTCRtpCodingParameters {
//!             ssrc: Some(12345),
//!             ..Default::default()
//!         },
//!         codec: RTCRtpCodec::default(),
//!         ..Default::default()
//!     }],
//! );
//!
//! // Create video track
//! let video_track = MediaStreamTrack::new(
//!     "stream-id".to_string(),
//!     "video-track-id".to_string(),
//!     "Camera".to_string(),
//!     RtpCodecKind::Video,
//!     vec![RTCRtpEncodingParameters {
//!         rtp_coding_parameters: RTCRtpCodingParameters {
//!             ssrc: Some(67890),
//!             ..Default::default()
//!         },
//!         codec: RTCRtpCodec::default(),
//!         ..Default::default()
//!     }],
//! );
//!
//! // Create stream with both tracks
//! let stream = MediaStream::new(
//!     "my-stream-id".to_string(),
//!     vec![audio_track, video_track],
//! );
//!
//! assert_eq!(stream.stream_id(), "my-stream-id");
//! assert!(stream.active());
//! # Ok(())
//! # }
//! ```
//!
//! ## Filtering tracks by type
//!
//! ```
//! # use rtc::media_stream::{MediaStream, MediaStreamId};
//! # use rtc::media_stream::MediaStreamTrack;
//! # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
//! # fn example(stream: MediaStream) {
//! // Get all audio tracks
//! for audio_track in stream.get_audio_tracks() {
//!     println!("Audio track: {}", audio_track.label());
//! }
//!
//! // Get all video tracks
//! for video_track in stream.get_video_tracks() {
//!     println!("Video track: {}", video_track.label());
//! }
//! # }
//! ```
//!
//! ## Managing tracks
//!
//! ```
//! # use rtc::media_stream::{MediaStream, MediaStreamId};
//! # use rtc::media_stream::MediaStreamTrack;
//! # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
//! # use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RTCRtpCodingParameters};
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut stream = MediaStream::new("stream-id".to_string(), vec![]);
//!
//! // Add a track
//! let track = MediaStreamTrack::new(
//!     "stream-id".to_string(),
//!     "track-id".to_string(),
//!     "My Track".to_string(),
//!     RtpCodecKind::Audio,
//!     vec![RTCRtpEncodingParameters {
//!         rtp_coding_parameters: RTCRtpCodingParameters {
//!             ssrc: Some(12345),
//!             ..Default::default()
//!         },
//!         codec: RTCRtpCodec::default(),
//!         ..Default::default()
//!     }],
//! );
//! stream.add_track(track);
//!
//! // Retrieve track by ID
//! if let Some(track) = stream.get_track_by_id(&"track-id".to_string()) {
//!     println!("Found track: {}", track.label());
//! }
//!
//! // Remove track
//! let removed_track = stream.remove_track(&"track-id".to_string());
//! assert!(removed_track.is_some());
//! # Ok(())
//! # }
//! ```
//!
//! # Specification
//!
//! - [W3C Media Capture and Streams](https://www.w3.org/TR/mediacapture-streams/)
//! - [W3C MediaStream](https://www.w3.org/TR/mediacapture-streams/#mediastream)
//! - [W3C MediaStreamTrack](https://www.w3.org/TR/mediacapture-streams/#mediastreamtrack)
//! - [MDN MediaStream API](https://developer.mozilla.org/en-US/docs/Web/API/MediaStream)

pub(crate) mod track;
pub(crate) mod track_capabilities;
pub(crate) mod track_constraints;
pub(crate) mod track_settings;
pub(crate) mod track_state;
pub(crate) mod track_supported_constraints;

use crate::rtp_transceiver::rtp_sender::RtpCodecKind;

pub use track::{MediaStreamTrack, MediaStreamTrackId};
pub use track_capabilities::MediaTrackCapabilities;
pub use track_constraints::{
    Constrain, ConstrainRange, MediaTrackConstraintSet, MediaTrackConstraints,
};
pub use track_settings::MediaTrackSettings;
pub use track_state::MediaStreamTrackState;
pub use track_supported_constraints::MediaTrackSupportConstraints;

/// A new identifier for a stream or a track, generated as mediacapture-main 4.2 and 4.3 ask:
/// a UUID (RFC 9562 version 4, random), 36 characters.
pub fn generate_id() -> String {
    let bits: u128 = rand::random();
    // Version 4 and the RFC 9562 variant.
    let bits = (bits & !(0xf << 76) | (0x4 << 76)) & !(0x3 << 62) | (0x2 << 62);
    let hex = format!("{bits:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// mediacapture-main 4.4 `MediaStreamTrackEvent`: a track added to or removed from a
/// stream, for that stream's `addtrack` or `removetrack` event. A remote stream's are derived
/// from [`RTCRemoteStreamsChange`](crate::peer_connection::event::RTCRemoteStreamsChange)
/// (`media_stream_track_events`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaStreamTrackEvent {
    /// `addtrack` or `removetrack`.
    pub kind: MediaStreamTrackEventKind,
    /// The stream the event fires at.
    pub stream_id: MediaStreamId,
    /// The event's `track`.
    pub track_id: MediaStreamTrackId,
}

/// The type of a [`MediaStreamTrackEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaStreamTrackEventKind {
    /// `addtrack`.
    AddTrack,
    /// `removetrack`.
    RemoveTrack,
}

/// Unique identifier for a media stream.
///
/// As defined in [MediaStream.id](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-id).
pub type MediaStreamId = String;

/// Represents a stream of media content.
///
/// A `MediaStream` is a collection of zero or more [`MediaStreamTrack`] objects,
/// representing audio or video tracks. Each stream has a unique identifier and can
/// be in an active or inactive state.
///
/// # Specification
///
/// See [MediaStream](https://www.w3.org/TR/mediacapture-streams/#mediastream) in the
/// W3C Media Capture and Streams specification.
///
/// # Examples
///
/// ```
/// use rtc::media_stream::{MediaStream, MediaStreamId};
/// use rtc::media_stream::MediaStreamTrack;
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RTCRtpCodingParameters};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let track = MediaStreamTrack::new(
///     "stream-id".to_string(),
///     "track-id".to_string(),
///     "My Track".to_string(),
///     RtpCodecKind::Audio,
///     vec![RTCRtpEncodingParameters {
///         rtp_coding_parameters: RTCRtpCodingParameters {
///             ssrc: Some(12345),
///             ..Default::default()
///         },
///         codec: RTCRtpCodec::default(),
///         ..Default::default()
///     }],
/// );
///
/// let stream = MediaStream::new("my-stream".to_string(), vec![track]);
/// assert_eq!(stream.stream_id(), "my-stream");
/// # Ok(())
/// # }
/// ```
#[derive(Default, Debug, Clone)]
pub struct MediaStream {
    stream_id: MediaStreamId,
    /// The track set, in the order the tracks were added; a track id is in it at most once.
    tracks: Vec<MediaStreamTrack>,
}

impl MediaStream {
    /// Creates a new media stream with the given ID and tracks.
    ///
    /// # Parameters
    ///
    /// * `stream_id` - A unique identifier for this stream
    /// * `tracks` - A vector of tracks to add to the stream
    ///
    /// # Specification
    ///
    /// See [MediaStream constructor](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-constructor).
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::media_stream::{MediaStream, MediaStreamId};
    /// use rtc::media_stream::MediaStreamTrack;
    /// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RTCRtpCodingParameters};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let track = MediaStreamTrack::new(
    ///     "stream-1".to_string(),
    ///     "track-1".to_string(),
    ///     "Microphone".to_string(),
    ///     RtpCodecKind::Audio,
    ///     vec![RTCRtpEncodingParameters {
    ///         rtp_coding_parameters: RTCRtpCodingParameters {
    ///             ssrc: Some(12345),
    ///             ..Default::default()
    ///         },
    ///         codec: RTCRtpCodec::default(),
    ///         ..Default::default()
    ///     }],
    /// );
    ///
    /// let stream = MediaStream::new("stream-1".to_string(), vec![track]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(stream_id: MediaStreamId, tracks: Vec<MediaStreamTrack>) -> Self {
        Self {
            stream_id,
            tracks: vec![],
        }
        .with_tracks(tracks)
    }

    /// mediacapture-main 4.2 constructor: a new stream with a generated id
    /// ([`generate_id`]) and the given tracks.
    pub fn with_generated_id(tracks: Vec<MediaStreamTrack>) -> Self {
        Self::new(generate_id(), tracks)
    }

    /// mediacapture-main 4.2 `clone()`: a new stream with a new id whose tracks are clones
    /// of this stream's ([`MediaStreamTrack::clone_track`]), in the same order.
    pub fn clone_stream(&self) -> Self {
        let id = generate_id();
        let tracks = self
            .tracks
            .iter()
            .map(|track| track.clone_track_into(id.clone()))
            .collect();
        Self::new(id, tracks)
    }

    fn with_tracks(mut self, tracks: Vec<MediaStreamTrack>) -> Self {
        for track in tracks {
            self.add_track(track);
        }
        self
    }

    /// Returns the unique identifier of this stream.
    ///
    /// The identifier is a 36-character Universally Unique Identifier (UUID) generated
    /// when the stream is created.
    ///
    /// # Specification
    ///
    /// See [MediaStream.id](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-id).
    pub fn stream_id(&self) -> &MediaStreamId {
        &self.stream_id
    }

    /// Returns whether this stream is active.
    ///
    /// A stream is active if it has at least one track that is not in the "ended" state.
    ///
    /// # Specification
    ///
    /// See [MediaStream.active](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-active).
    pub fn active(&self) -> bool {
        self.tracks
            .iter()
            .any(|track| track.ready_state() != track_state::MediaStreamTrackState::Ended)
    }

    /// Returns an iterator over all audio tracks in this stream.
    ///
    /// # Specification
    ///
    /// See [MediaStream.getAudioTracks()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-getaudiotracks).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::{MediaStream, MediaStreamId};
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(stream: MediaStream) {
    /// for track in stream.get_audio_tracks() {
    ///     println!("Audio track: {} ({})", track.label(), track.track_id());
    /// }
    /// # }
    /// ```
    pub fn get_audio_tracks(&self) -> impl Iterator<Item = &MediaStreamTrack> {
        self.tracks
            .iter()
            .filter(|track| track.kind() == RtpCodecKind::Audio)
    }

    /// Returns a mutable iterator over all audio tracks in this stream.
    ///
    /// # Specification
    ///
    /// See [MediaStream.getAudioTracks()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-getaudiotracks).
    pub fn get_audio_tracks_mut(&mut self) -> impl Iterator<Item = &mut MediaStreamTrack> {
        self.tracks
            .iter_mut()
            .filter(|track| track.kind() == RtpCodecKind::Audio)
    }

    /// Returns an iterator over all video tracks in this stream.
    ///
    /// # Specification
    ///
    /// See [MediaStream.getVideoTracks()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-getvideotracks).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::{MediaStream, MediaStreamId};
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(stream: MediaStream) {
    /// for track in stream.get_video_tracks() {
    ///     println!("Video track: {} ({})", track.label(), track.track_id());
    /// }
    /// # }
    /// ```
    pub fn get_video_tracks(&self) -> impl Iterator<Item = &MediaStreamTrack> {
        self.tracks
            .iter()
            .filter(|track| track.kind() == RtpCodecKind::Video)
    }

    /// Returns a mutable iterator over all video tracks in this stream.
    ///
    /// # Specification
    ///
    /// See [MediaStream.getVideoTracks()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-getvideotracks).
    pub fn get_video_tracks_mut(&mut self) -> impl Iterator<Item = &mut MediaStreamTrack> {
        self.tracks
            .iter_mut()
            .filter(|track| track.kind() == RtpCodecKind::Video)
    }

    /// Returns an iterator over all tracks in this stream.
    ///
    /// # Specification
    ///
    /// See [MediaStream.getTracks()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-gettracks).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::{MediaStream, MediaStreamId};
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(stream: MediaStream) {
    /// println!("Stream has {} tracks", stream.get_tracks().count());
    /// # }
    /// ```
    pub fn get_tracks(&self) -> impl Iterator<Item = &MediaStreamTrack> {
        self.tracks.iter()
    }

    /// Returns a mutable iterator over all tracks in this stream.
    ///
    /// # Specification
    ///
    /// See [MediaStream.getTracks()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-gettracks).
    pub fn get_tracks_mut(&mut self) -> impl Iterator<Item = &mut MediaStreamTrack> {
        self.tracks.iter_mut()
    }

    /// Returns a reference to the track with the specified ID, if it exists.
    ///
    /// # Parameters
    ///
    /// * `track_id` - The unique identifier of the track to retrieve
    ///
    /// # Returns
    ///
    /// Returns `Some(&MediaStreamTrack)` if a track with the given ID exists,
    /// or `None` otherwise.
    ///
    /// # Specification
    ///
    /// See [MediaStream.getTrackById()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-gettrackbyid).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::{MediaStream, MediaStreamId};
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(stream: MediaStream) {
    /// if let Some(track) = stream.get_track_by_id(&"track-id".to_string()) {
    ///     println!("Found track: {}", track.label());
    /// } else {
    ///     println!("Track not found");
    /// }
    /// # }
    /// ```
    pub fn get_track_by_id(&self, track_id: &MediaStreamTrackId) -> Option<&MediaStreamTrack> {
        self.tracks
            .iter()
            .find(|track| track.track_id() == track_id)
    }

    /// Returns a mutable reference to the track with the specified ID, if it exists.
    ///
    /// # Parameters
    ///
    /// * `track_id` - The unique identifier of the track to retrieve
    ///
    /// # Returns
    ///
    /// Returns `Some(&mut MediaStreamTrack)` if a track with the given ID exists,
    /// or `None` otherwise.
    ///
    /// # Specification
    ///
    /// See [MediaStream.getTrackById()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-gettrackbyid).
    pub fn get_track_by_id_mut(
        &mut self,
        track_id: &MediaStreamTrackId,
    ) -> Option<&mut MediaStreamTrack> {
        self.tracks
            .iter_mut()
            .find(|track| track.track_id() == track_id)
    }

    /// Adds a track to this stream.
    ///
    /// If a track with the same ID already exists, it will be replaced.
    ///
    /// # Parameters
    ///
    /// * `track` - The track to add to the stream
    ///
    /// # Specification
    ///
    /// See [MediaStream.addTrack()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-addtrack).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::{MediaStream, MediaStreamId};
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RTCRtpCodingParameters};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut stream = MediaStream::new("stream-id".to_string(), vec![]);
    ///
    /// let track = MediaStreamTrack::new(
    ///     "stream-id".to_string(),
    ///     "track-id".to_string(),
    ///     "Microphone".to_string(),
    ///     RtpCodecKind::Audio,
    ///     vec![RTCRtpEncodingParameters {
    ///         rtp_coding_parameters: RTCRtpCodingParameters {
    ///             ssrc: Some(12345),
    ///             ..Default::default()
    ///         },
    ///         codec: RTCRtpCodec::default(),
    ///         ..Default::default()
    ///     }],
    /// );
    ///
    /// stream.add_track(track);
    /// assert_eq!(stream.get_tracks().count(), 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_track(&mut self, track: MediaStreamTrack) {
        // mediacapture-main 4.2 addTrack: a track already in the set is not added again.
        if self.get_track_by_id(track.track_id()).is_none() {
            self.tracks.push(track);
        }
    }

    /// Removes a track from this stream and returns it.
    ///
    /// # Parameters
    ///
    /// * `track_id` - The unique identifier of the track to remove
    ///
    /// # Returns
    ///
    /// Returns `Some(MediaStreamTrack)` if the track was found and removed,
    /// or `None` if no track with the given ID exists.
    ///
    /// # Specification
    ///
    /// See [MediaStream.removeTrack()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-removetrack).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::{MediaStream, MediaStreamId};
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RTCRtpCodingParameters};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut stream = MediaStream::new("stream-id".to_string(), vec![]);
    /// # let track = MediaStreamTrack::new(
    /// #     "stream-id".to_string(), "track-id".to_string(), "Microphone".to_string(),
    /// #     RtpCodecKind::Audio, vec![RTCRtpEncodingParameters {
    /// #         rtp_coding_parameters: RTCRtpCodingParameters {
    /// #             ssrc: Some(12345), ..Default::default()
    /// #         },
    /// #         codec: RTCRtpCodec::default(),
    /// #         ..Default::default()
    /// #     }],
    /// # );
    /// # stream.add_track(track);
    /// let removed_track = stream.remove_track(&"track-id".to_string());
    /// assert!(removed_track.is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn remove_track(&mut self, track_id: &MediaStreamTrackId) -> Option<MediaStreamTrack> {
        let index = self
            .tracks
            .iter()
            .position(|track| track.track_id() == track_id)?;
        Some(self.tracks.remove(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn track(id: &str, kind: RtpCodecKind) -> MediaStreamTrack {
        MediaStreamTrack::new("s".to_owned(), id.to_owned(), id.to_owned(), kind, vec![])
    }

    /// mediacapture-main 4.2: the track set holds every track of the stream, by track id, once.
    #[test]
    fn a_streams_tracks_of_one_stream_id_are_all_kept() {
        let mut stream = MediaStream::new(
            "s".to_owned(),
            vec![
                track("a", RtpCodecKind::Audio),
                track("v", RtpCodecKind::Video),
            ],
        );
        assert_eq!(stream.stream_id(), "s");
        assert_eq!(stream.get_tracks().count(), 2);
        assert_eq!(stream.get_audio_tracks().count(), 1);
        assert_eq!(stream.get_video_tracks().count(), 1);
        assert!(stream.get_track_by_id(&"v".to_owned()).is_some());
        assert!(stream.get_track_by_id(&"x".to_owned()).is_none());

        let mut again = track("a", RtpCodecKind::Audio);
        again.set_enabled(false);
        stream.add_track(again);
        assert_eq!(stream.get_tracks().count(), 2, "a track already in the set");
        assert!(
            stream
                .get_track_by_id(&"a".to_owned())
                .is_some_and(|t| t.enabled()),
            "is not added again"
        );
        assert!(stream.remove_track(&"a".to_owned()).is_some());
        assert!(stream.remove_track(&"a".to_owned()).is_none());
        assert_eq!(
            stream
                .get_tracks()
                .map(|t| t.track_id().as_str())
                .collect::<Vec<_>>(),
            vec!["v"]
        );
    }

    /// mediacapture-main 4.2: a stream is active while one of its tracks has not ended.
    #[test]
    fn a_stream_is_active_while_a_track_has_not_ended() {
        let mut stream = MediaStream::new(
            "s".to_owned(),
            vec![
                track("a", RtpCodecKind::Audio),
                track("v", RtpCodecKind::Video),
            ],
        );
        assert!(stream.active());
        if let Some(track) = stream.get_tracks_mut().next() {
            track.stop();
        }
        assert!(stream.active(), "one track is still live");
        for track in stream.get_tracks_mut() {
            track.stop();
        }
        assert!(!stream.active());
        assert!(!MediaStream::new("e".to_owned(), vec![]).active());
    }
}
