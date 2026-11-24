//! When to ask the sender for a key frame.
//!
//! The triggers and waits are libwebrtc's (a222406d; no RFC fixes a number):
//!
//! - the first frame assembled is not a key frame (`video/rtp_video_stream_receiver2.cc:
//!   1067-1072`);
//! - the packet buffer emptied itself because it was full (`:1054-1058`);
//! - a Dependency Descriptor arrived before any structure, at most once a second (`:808-814`);
//! - no picture became decodable within the wait: 200 ms while a key frame is needed, 3 s
//!   otherwise (`video/video_receive_stream2.h:74-75`), only when a packet arrived in the last
//!   5 s (`video_receive_stream2.cc:1033-1037`) and no key frame is arriving
//!   (`IsReceivingKeyFrame`, `:1216-1226`);
//! - the decoder failed (`:1098-1102`);
//! - and, once a key frame is needed, again every wait until one is decoded
//!   (`HandleKeyFrameGeneration`, `:1187-1213`).
//!
//! The request itself is a PLI (RFC 4585 6.3.1): RFC 5104 4.3.1.2, "FIR SHALL NOT be sent as
//! a reaction to picture losses -- it is RECOMMENDED to use PLI [RFC4585] instead".

use std::time::{Duration, Instant};

/// libwebrtc `kMaxWaitForKeyFrame` (`video/video_receive_stream2.h:74`).
pub const MAX_WAIT_FOR_KEY_FRAME: Duration = Duration::from_millis(200);
/// libwebrtc `kMaxWaitForFrame` (`video/video_receive_stream2.h:75`).
pub const MAX_WAIT_FOR_FRAME: Duration = Duration::from_secs(3);
/// No request for a stream without a packet for this long (libwebrtc `kInactiveDuration`).
pub const INACTIVE_DURATION: Duration = Duration::from_secs(5);

/// Why a key frame was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFrameReason {
    /// The first frame of the stream was not a key frame.
    FirstFrameNotKey,
    /// The packet buffer was full and emptied itself.
    BufferCleared,
    /// A Dependency Descriptor referred to a structure never received.
    MissingStructure,
    /// No picture became decodable within the wait.
    Timeout,
    /// The decoder failed or asked for one.
    DecoderError,
    /// A key frame is still needed: the request repeated.
    Repeat,
    /// A frame did not depacketize.
    Unparsable,
}

/// The waits, derived from the sender's `rtx-time` as libwebrtc does
/// (`DetermineMaxWaitForFrame`, `video_receive_stream2.cc:218-229`): with an RTX time `t`
/// under a third of 3 s, `t` for a key frame and `3 t` otherwise.
pub fn waits_for(rtx_time: Option<Duration>) -> (Duration, Duration) {
    match rtx_time {
        Some(t) if !t.is_zero() && 3 * t < MAX_WAIT_FOR_FRAME => (t, 3 * t),
        _ => (MAX_WAIT_FOR_KEY_FRAME, MAX_WAIT_FOR_FRAME),
    }
}

/// The key-frame request state of one stream.
#[derive(Debug, Clone)]
pub struct KeyFramePolicy {
    wait_for_key_frame: Duration,
    wait_for_frame: Duration,
    /// A key frame is needed before anything can be decoded.
    keyframe_required: bool,
    /// A key frame was asked for and not yet decoded: ask again every wait.
    requested: bool,
    last_request: Option<Instant>,
    /// The decode timeout started here (the last picture released, or the start).
    waiting_since: Instant,
    last_packet: Option<Instant>,
    last_keyframe_packet: Option<Instant>,
    last_missing_structure_request: Option<Instant>,
    first_frame_seen: bool,
    pending: Option<KeyFrameReason>,
}

impl KeyFramePolicy {
    /// A policy starting at `now` with the waits `(for a key frame, for any frame)`.
    pub fn new(now: Instant, waits: (Duration, Duration)) -> Self {
        Self {
            wait_for_key_frame: waits.0,
            wait_for_frame: waits.1,
            keyframe_required: true,
            requested: false,
            last_request: None,
            waiting_since: now,
            last_packet: None,
            last_keyframe_packet: None,
            last_missing_structure_request: None,
            first_frame_seen: false,
            pending: None,
        }
    }

    /// Whether only a key frame can be decoded next.
    pub fn keyframe_required(&self) -> bool {
        self.keyframe_required
    }

    fn wait(&self) -> Duration {
        if self.keyframe_required {
            self.wait_for_key_frame
        } else {
            self.wait_for_frame
        }
    }

    fn receiving_keyframe(&self, now: Instant) -> bool {
        self.last_keyframe_packet
            .is_some_and(|t| now.saturating_duration_since(t) < self.wait_for_key_frame)
    }

    fn active(&self, now: Instant) -> bool {
        self.last_packet
            .is_some_and(|t| now.saturating_duration_since(t) < INACTIVE_DURATION)
    }

    fn request(&mut self, now: Instant, reason: KeyFrameReason) {
        self.pending.get_or_insert(reason);
        self.requested = true;
        self.last_request = Some(now);
    }

    /// A media packet arrived; `keyframe` when it carries part of a key frame.
    pub fn on_packet(&mut self, now: Instant, keyframe: bool) {
        self.last_packet = Some(now);
        if keyframe {
            self.last_keyframe_packet = Some(now);
        }
    }

    /// A frame was assembled.
    pub fn on_frame_assembled(&mut self, now: Instant, keyframe: bool) {
        if !self.first_frame_seen {
            self.first_frame_seen = true;
            if !keyframe {
                self.request(now, KeyFrameReason::FirstFrameNotKey);
            }
        }
    }

    /// The packet buffer emptied itself.
    pub fn on_buffer_cleared(&mut self, now: Instant) {
        self.keyframe_required = true;
        self.request(now, KeyFrameReason::BufferCleared);
    }

    /// A frame's packets did not depacketize.
    pub fn on_unparsable(&mut self, now: Instant) {
        self.request(now, KeyFrameReason::Unparsable);
    }

    /// A Dependency Descriptor referred to an unknown structure.
    pub fn on_missing_structure(&mut self, now: Instant) {
        if self
            .last_missing_structure_request
            .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1))
        {
            self.last_missing_structure_request = Some(now);
            self.request(now, KeyFrameReason::MissingStructure);
        }
    }

    /// A picture was released for decoding: the decode timeout starts again.
    pub fn on_released(&mut self, now: Instant) {
        self.waiting_since = now;
    }

    /// The decoder's verdict on a picture.
    pub fn on_decoded(&mut self, now: Instant, ok: bool, keyframe: bool, decoder_asks: bool) {
        let due = self
            .last_request
            .is_none_or(|t| now >= t + self.wait_for_key_frame);
        if ok {
            self.keyframe_required = false;
            if keyframe {
                self.requested = false;
            }
            if decoder_asks {
                self.request(now, KeyFrameReason::DecoderError);
            }
        } else {
            self.keyframe_required = true;
            if due || !self.requested {
                self.request(now, KeyFrameReason::DecoderError);
            }
        }
        if self.requested && !keyframe && due && !self.receiving_keyframe(now) && ok {
            self.request(now, KeyFrameReason::Repeat);
        }
    }

    /// Runs the timeout at `now`.
    pub fn on_timeout(&mut self, now: Instant) {
        if now < self.waiting_since + self.wait() {
            return;
        }
        self.waiting_since = now;
        if self.active(now) && !self.receiving_keyframe(now) {
            self.request(now, KeyFrameReason::Timeout);
        }
    }

    /// When the decode timeout runs out.
    pub fn deadline(&self) -> Instant {
        self.waiting_since + self.wait()
    }

    /// The request to send, if one is due.
    pub fn poll_request(&mut self) -> Option<KeyFrameReason> {
        self.pending.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtx_time_shortens_the_waits() {
        assert_eq!(
            waits_for(None),
            (MAX_WAIT_FOR_KEY_FRAME, MAX_WAIT_FOR_FRAME)
        );
        let t = Duration::from_millis(300);
        assert_eq!(waits_for(Some(t)), (t, 3 * t));
        assert_eq!(
            waits_for(Some(Duration::from_secs(2))),
            (MAX_WAIT_FOR_KEY_FRAME, MAX_WAIT_FOR_FRAME)
        );
    }

    #[test]
    fn a_delta_frame_first_asks_for_a_key_frame_once() {
        let t0 = Instant::now();
        let mut p = KeyFramePolicy::new(t0, waits_for(None));
        p.on_frame_assembled(t0, false);
        assert_eq!(p.poll_request(), Some(KeyFrameReason::FirstFrameNotKey));
        p.on_frame_assembled(t0, false);
        assert_eq!(p.poll_request(), None);
    }

    #[test]
    fn the_timeout_asks_only_for_an_active_stream_not_receiving_a_key_frame() {
        let t0 = Instant::now();
        let mut p = KeyFramePolicy::new(t0, waits_for(None));
        p.on_timeout(t0 + Duration::from_millis(250));
        assert_eq!(p.poll_request(), None, "no packet yet: inactive");
        p.on_packet(t0 + Duration::from_millis(300), false);
        p.on_timeout(t0 + Duration::from_millis(460));
        assert_eq!(p.poll_request(), Some(KeyFrameReason::Timeout));
        // Receiving key frame packets holds the next request back.
        p.on_packet(t0 + Duration::from_millis(600), true);
        p.on_timeout(t0 + Duration::from_millis(700));
        assert_eq!(p.poll_request(), None);
    }

    #[test]
    fn a_decoder_error_requires_a_key_frame() {
        let t0 = Instant::now();
        let mut p = KeyFramePolicy::new(t0, waits_for(None));
        p.on_decoded(t0, true, true, false);
        assert!(!p.keyframe_required());
        p.on_decoded(t0 + Duration::from_millis(33), false, false, false);
        assert!(p.keyframe_required());
        assert_eq!(p.poll_request(), Some(KeyFrameReason::DecoderError));
    }
}
