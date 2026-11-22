use shared::error::{Error, Result};
use shared::replay_detector::*;

/// A factory for the [`ReplayDetector`] a context
/// should use.
///
/// A factory rather than a value because each SSRC in a session needs its own detector
/// state. A context given no factory uses a sliding window of
/// [`DEFAULT_REPLAY_PROTECTION_WINDOW`] packets; pass another factory to widen it, or
/// [`srtp_no_replay_protection`] / [`srtcp_no_replay_protection`] to go without.
pub type ContextOption = Box<dyn Fn() -> Box<dyn ReplayDetector> + Send + Sync>;

pub(crate) const MAX_SEQUENCE_NUMBER: u16 = 65535;
pub(crate) const MAX_SRTCP_INDEX: usize = 0x7FFFFFFF;

/// The smallest replay window RFC 3711 section 3.3.2 allows: "SRTP-WINDOW-SIZE ... MUST be at
/// least 64".
pub const MIN_REPLAY_PROTECTION_WINDOW: usize = 64;
/// The replay window of a context created without replay options.
pub const DEFAULT_REPLAY_PROTECTION_WINDOW: usize = 64;

fn check_window(window_size: usize) -> Result<()> {
    if window_size < MIN_REPLAY_PROTECTION_WINDOW {
        return Err(Error::Other(format!(
            "SRTP replay window of {window_size} packets is below the minimum of \
             {MIN_REPLAY_PROTECTION_WINDOW} (RFC 3711 section 3.3.2)"
        )));
    }
    Ok(())
}

pub(crate) fn srtp_window(window_size: usize) -> ContextOption {
    Box::new(move || -> Box<dyn ReplayDetector> {
        Box::new(WrappedSlidingWindowDetector::new(
            window_size,
            MAX_SEQUENCE_NUMBER as u64,
        ))
    })
}

pub(crate) fn srtcp_window(window_size: usize) -> ContextOption {
    Box::new(move || -> Box<dyn ReplayDetector> {
        Box::new(WrappedSlidingWindowDetector::new(
            window_size,
            MAX_SRTCP_INDEX as u64,
        ))
    })
}

/// srtp_replay_protection sets SRTP replay protection window size.
///
/// # Errors
///
/// A window below [`MIN_REPLAY_PROTECTION_WINDOW`] (64) is refused (RFC 3711 section 3.3.2):
/// it would drop packets that ordinary reordering delivers late.
pub fn srtp_replay_protection(window_size: usize) -> Result<ContextOption> {
    check_window(window_size)?;
    Ok(srtp_window(window_size))
}

/// Sets SRTCP replay protection window size.
///
/// # Errors
///
/// A window below [`MIN_REPLAY_PROTECTION_WINDOW`] (64) is refused (RFC 3711 section 3.3.2).
pub fn srtcp_replay_protection(window_size: usize) -> Result<ContextOption> {
    check_window(window_size)?;
    Ok(srtcp_window(window_size))
}

/// srtp_no_replay_protection disables SRTP replay protection.
///
/// RFC 3711 section 3.3.2 recommends replay protection wherever packets are authenticated; go
/// without only where something else rejects replays, or for a context that only protects.
pub fn srtp_no_replay_protection() -> ContextOption {
    Box::new(|| -> Box<dyn ReplayDetector> { Box::<NoOpReplayDetector>::default() })
}

/// srtcp_no_replay_protection disables SRTCP replay protection.
pub fn srtcp_no_replay_protection() -> ContextOption {
    Box::new(|| -> Box<dyn ReplayDetector> { Box::<NoOpReplayDetector>::default() })
}
