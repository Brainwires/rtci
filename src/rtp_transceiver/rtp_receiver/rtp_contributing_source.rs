use std::time::Duration;

/// Information about a contributing source (CSRC) or synchronization source (SSRC).
///
/// The `RTCRtpContributingSource` and `RTCRtpSynchronizationSource` dictionaries contain
/// information about a given contributing source (CSRC) or synchronization source (SSRC)
/// respectively. These sources are identified by their source identifiers and are used
/// in the RTP header to identify the sources of the media in an RTP stream.
///
/// # Specification
/// Corresponds to the `RTCRtpContributingSource` dictionary in the
/// [WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource).
#[derive(Default, Debug, Clone)]
pub struct RTCRtpContributingSource {
    /// The timestamp indicating the most recent time a frame originating from this source
    /// was delivered to the receiver. The timestamp is relative to the system clock.
    ///
    /// # Specification
    /// Corresponds to the `timestamp` attribute in
    /// [RTCRtpContributingSource](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource-timestamp).
    pub timestamp: Duration,

    /// The CSRC or SSRC identifier of the contributing or synchronization source.
    ///
    /// # Specification
    /// Corresponds to the `source` attribute in
    /// [RTCRtpContributingSource](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource-source).
    pub source: u32,

    /// The audio level of the contributing source, ranging from 0 to 1.
    /// A value of 0 indicates silence, and 1 indicates the maximum audio level.
    ///
    /// `None` when the packet carried no level for the source: for a synchronization source
    /// the RFC 6464 client-to-mixer extension, for a contributing source the RFC 6465
    /// mixer-to-client extension (each has to be negotiated). A level `l` in -dBov is
    /// `10^(-l/20)`, and 127 (digital silence) is 0.
    ///
    /// # Specification
    /// Corresponds to the `audioLevel` attribute in
    /// [RTCRtpContributingSource](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource-audiolevel).
    pub audio_level: Option<f64>,

    /// The RTP timestamp of the media. This is the timestamp at which the media was sampled,
    /// as defined in RFC 3550 section 5.1.
    ///
    /// # Specification
    /// Corresponds to the `rtpTimestamp` attribute in
    /// [RTCRtpContributingSource](https://www.w3.org/TR/webrtc/#dom-rtcrtpcontributingsource-rtptimestamp).
    pub rtp_timestamp: u32,

    /// webrtc-extensions 8 `captureTimestamp`: when the most recent frame from this source
    /// was captured, in milliseconds on the capture system's NTP clock (since 1900): the
    /// packet's absolute capture time (`abs-capture-time` header extension), or one
    /// interpolated from an earlier packet's by the RTP timestamps; `None` without either.
    pub capture_timestamp: Option<f64>,

    /// webrtc-extensions 8 `senderCaptureTimeOffset`: the sender's estimate of its NTP
    /// clock's offset from the capture system's, in milliseconds, from the packet's
    /// extension or else the most recent one that carried it; `None` without either.
    pub sender_capture_time_offset: Option<f64>,
}

/// Synchronization source information.
///
/// This is a type alias for `RTCRtpContributingSource` because both CSRC and SSRC
/// share the same structure and attributes.
///
/// # Specification
/// Corresponds to the `RTCRtpSynchronizationSource` dictionary in the
/// [WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpsynchronizationsource).
pub type RTCRtpSynchronizationSource = RTCRtpContributingSource;
