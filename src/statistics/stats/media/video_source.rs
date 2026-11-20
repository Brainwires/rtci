//! Video source statistics.
//!
//! This module contains the [`RTCVideoSourceStats`] type which provides
//! information about video capture sources.

use super::media_source::RTCMediaSourceStats;
use serde::{Deserialize, Serialize};

/// Statistics for a video source.
///
/// This struct corresponds to the `RTCVideoSourceStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about the video
/// capture source, including resolution and frame rate metrics.
///
/// # Specification
///
/// See [RTCVideoSourceStats](https://www.w3.org/TR/webrtc-stats/#videosourcestats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCVideoSourceStats {
    /// Base media source statistics.
    #[serde(flatten)]
    pub media_source_stats: RTCMediaSourceStats,

    /// The width of video frames in pixels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,

    /// The height of video frames in pixels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,

    /// Total number of frames captured from this source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames: Option<u32>,

    /// Current frame rate in frames per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames_per_second: Option<f64>,
}
