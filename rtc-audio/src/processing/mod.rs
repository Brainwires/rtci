//! Capture-side audio processing (the equivalent of libwebrtc's audio processing module):
//! high-pass filter, acoustic echo cancellation with render-to-capture delay estimation,
//! noise suppression, residual echo suppression, automatic gain control and voice activity
//! detection, each switchable on its own.
//!
//! Two streams pass through it, 10 ms frames of 48 kHz mono each:
//!
//! - the **render** (far-end) stream: every frame about to be played goes to
//!   [`AudioProcessing::process_render`] first;
//! - the **capture** (near-end) stream: every microphone frame goes through
//!   [`AudioProcessing::process_capture`], in the order the frames were recorded.
//!
//! The capture chain is HPF, AEC (linear filter), suppressor (residual echo and noise), VAD,
//! AGC, as in libwebrtc. The echo canceller finds the delay between the streams itself
//! ([`delay::DelayEstimator`]); [`AudioProcessing::set_stream_delay`] gives it a starting
//! point.
//!
//! Stereo capture is mixed to mono before processing (the send pipeline does it); the
//! processing is mono, as libwebrtc's is by default.

pub mod aec;
pub mod agc;
pub mod delay;
pub mod suppressor;

use std::time::Duration;

use crate::dsp::filter::HighPassFilter;
use crate::dsp::level::rfc6464_level;
use crate::dsp::vad::VoiceActivityDetector;
use aec::EchoCanceller;
use agc::GainController;
use delay::DelayEstimator;
pub use suppressor::NoiseSuppressionLevel;
use suppressor::Suppressor;

/// The samples of one frame (10 ms at 48 kHz).
pub const FRAME: usize = 480;

/// Which stages run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessingConfig {
    /// Remove DC and rumble below 80 Hz.
    pub high_pass: bool,
    /// Cancel the echo of the render stream (linear filter and residual suppression).
    pub echo_cancellation: bool,
    /// Suppress stationary noise, at this level.
    pub noise_suppression: Option<NoiseSuppressionLevel>,
    /// Bring speech to RFC 7874's level, with a limiter.
    pub gain_control: bool,
    /// Detect voice activity (for the RFC 6464 flag, DTX and the gain control).
    pub voice_detection: bool,
}

impl ProcessingConfig {
    /// Everything on: what a call uses (noise suppression moderate).
    pub const CALL: Self = Self {
        high_pass: true,
        echo_cancellation: true,
        noise_suppression: Some(NoiseSuppressionLevel::Moderate),
        gain_control: true,
        voice_detection: true,
    };

    /// Nothing but voice activity detection.
    pub const OFF: Self = Self {
        high_pass: false,
        echo_cancellation: false,
        noise_suppression: None,
        gain_control: false,
        voice_detection: true,
    };
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self::CALL
    }
}

/// What processing found out about a capture frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CaptureInfo {
    /// The voice activity decision (true when detection is off).
    pub voice: bool,
    /// The processed frame's RFC 6464 level (-dBov).
    pub level: u8,
}

/// Echo measurements, for the W3C `echoReturnLoss` / `echoReturnLossEnhancement` of the
/// `RTCAudioSourceStats`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ProcessingStats {
    /// Echo return loss, dB.
    pub echo_return_loss: Option<f64>,
    /// Echo return loss enhancement of the linear filter, dB.
    pub echo_return_loss_enhancement: Option<f64>,
    /// The render-to-capture delay found, if one was.
    pub delay: Option<Duration>,
    /// The gain control's gain, dB.
    pub gain_db: Option<f64>,
}

/// The processing of one call's audio.
#[derive(Debug, Clone)]
pub struct AudioProcessing {
    config: ProcessingConfig,
    hpf: HighPassFilter,
    aec: Option<EchoCanceller>,
    delay: DelayEstimator,
    suppressor: Option<Suppressor>,
    agc: GainController,
    vad: VoiceActivityDetector,
    render_vad: VoiceActivityDetector,
    render_active: bool,
}

impl AudioProcessing {
    /// Processing with the stages `config` turns on.
    pub fn new(config: ProcessingConfig) -> Self {
        let suppressor = (config.echo_cancellation || config.noise_suppression.is_some())
            .then(|| Suppressor::new(config.noise_suppression, config.echo_cancellation));
        Self {
            config,
            hpf: HighPassFilter::new(48_000, 1),
            aec: config.echo_cancellation.then(EchoCanceller::new),
            delay: DelayEstimator::new(),
            suppressor,
            agc: GainController::default(),
            vad: VoiceActivityDetector::new(),
            render_vad: VoiceActivityDetector::new(),
            render_active: false,
        }
    }

    /// The stages that run.
    pub fn config(&self) -> ProcessingConfig {
        self.config
    }

    /// Takes a render frame (480 samples about to be played).
    pub fn process_render(&mut self, frame: &[f32]) {
        if frame.len() != FRAME {
            return;
        }
        self.render_active = self.render_vad.process(frame);
        if let Some(aec) = self.aec.as_mut() {
            aec.push_render(frame);
            self.delay.push_render(frame);
        }
    }

    /// A hint of the render-to-capture delay (playout buffer, device latencies), used until
    /// the estimator finds it.
    pub fn set_stream_delay(&mut self, delay: Duration) {
        if let Some(aec) = self.aec.as_mut()
            && self.delay.estimate().is_none()
        {
            aec.set_bulk_delay((delay.as_secs_f64() * 48_000.0) as usize);
        }
    }

    /// Processes a capture frame (480 samples) in place.
    pub fn process_capture(&mut self, frame: &mut [f32]) -> CaptureInfo {
        if frame.len() != FRAME {
            return CaptureInfo {
                voice: true,
                level: rfc6464_level(frame),
            };
        }
        if self.config.high_pass {
            self.hpf.process(frame);
        }
        let raw = frame.to_vec();
        let mut echo = None;
        if let Some(aec) = self.aec.as_mut() {
            self.delay.push_capture(frame);
            if let Some(d) = self.delay.estimate() {
                aec.set_bulk_delay(d);
            }
            aec.process(frame);
            echo = Some(aec.echo_estimate().to_vec());
        }
        // Far end alone: render active and the capture mostly its echo (the canceller took
        // more than 3 dB out).
        let far_end_only = self.aec.is_some() && self.render_active && {
            let e: f32 = frame.iter().map(|v| v * v).sum();
            let d: f32 = raw.iter().map(|v| v * v).sum();
            e < 0.5 * d
        };
        if let Some(s) = self.suppressor.as_mut() {
            s.process(frame, echo.as_deref(), far_end_only);
        }
        let voice = if self.config.voice_detection {
            self.vad.process(frame)
        } else {
            true
        };
        if self.config.gain_control {
            // Not on echo: the level the gain follows is the near end's.
            self.agc.process(frame, voice && !far_end_only);
        }
        CaptureInfo {
            voice,
            level: rfc6464_level(frame),
        }
    }

    /// The echo and gain measurements.
    pub fn stats(&self) -> ProcessingStats {
        let (erl, erle) = self
            .aec
            .as_ref()
            .map(|a| {
                let (erl, erle) = a.erl_erle();
                (Some(erl), Some(erle))
            })
            .unwrap_or((None, None));
        ProcessingStats {
            echo_return_loss: erl,
            echo_return_loss_enhancement: erle,
            delay: self
                .delay
                .estimate()
                .map(|s| Duration::from_secs_f64(s as f64 / 48_000.0)),
            gain_db: self.config.gain_control.then(|| self.agc.gain_db()),
        }
    }
}

#[cfg(test)]
mod processing_test;
