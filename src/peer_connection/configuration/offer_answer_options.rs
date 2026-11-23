/// Options for creating SDP answers.
///
/// Controls various aspects of the answer creation process, particularly
/// voice activity detection settings.
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::RTCAnswerOptions;
///
/// let options = RTCAnswerOptions {
///     voice_activity_detection: true,
/// };
/// ```
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct RTCAnswerOptions {
    /// RFC 9429 section 5.3.3.1 `VoiceActivityDetection`, applied when the options are given
    /// to `create_answer`: `true` keeps silence suppression where the offer indicated support
    /// for it (its `CN` formats, an Opus `usedtx=1`), and answers the rest as `false` does;
    /// `false` answers without `CN` formats and with Opus `usedtx=0`, and then the
    /// application's encoder must not use silence suppression. Without options the answer is
    /// left as the media engine has it.
    ///
    /// **Default:** `false`
    pub voice_activity_detection: bool,
}

/// Options for creating SDP offers.
///
/// Controls various aspects of the offer creation process, particularly
/// ICE restart behavior.
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::RTCOfferOptions;
///
/// // Create offer with ICE restart
/// let options = RTCOfferOptions {
///     ice_restart: true,
///     ..Default::default()
/// };
/// ```
///
/// ## Specifications
///
/// * [W3C RTCOfferOptions](https://www.w3.org/TR/webrtc/#dictionary-rtcofferoptions-members)
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct RTCOfferOptions {
    /// Force ICE restart with new credentials.
    ///
    /// When `true`, the generated offer will contain new ICE credentials,
    /// forcing the ICE agent to restart the gathering process. This is useful
    /// when network conditions change or to recover from connection failures.
    ///
    /// **Use when:**
    /// - Network conditions have changed (WiFi to cellular, VPN changes)
    /// - Connection has failed and needs recovery
    /// - Switching between networks
    ///
    /// **Default:** `false`
    pub ice_restart: bool,

    /// RFC 9429 section 5.2.3.2 `VoiceActivityDetection`, when specified: `Some(true)` asks
    /// for silence suppression in the audio this endpoint receives (comfort noise formats are
    /// kept, Opus is offered with `usedtx=1`); `Some(false)` asks for none (no `CN` format,
    /// Opus with `usedtx=0`), and then the application's encoder must not use it either.
    /// `None` (the default) leaves the offer as the media engine has it.
    pub voice_activity_detection: Option<bool>,
}
