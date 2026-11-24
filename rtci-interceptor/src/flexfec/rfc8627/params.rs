//! The payload format parameters of `flexfec` (RFC 8627 section 5.1) as an `a=fmtp` line.

use std::time::Duration;

/// The parameters of an RFC 8627 `flexfec` payload type beyond its clock rate.
///
/// RFC 8627 registers one: the required `repair-window`. (`L`, `D` and `ToP` were optional
/// parameters of draft-03 and did not survive into the RFC; a line that carries them is
/// accepted and they are ignored, as any unknown parameter is: section 5.2.1.)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlexFecParameters {
    /// `repair-window`: "the time that spans the source packets and the corresponding repair
    /// packets", in microseconds on the wire. `None` when the line does not carry a usable one.
    pub repair_window: Option<Duration>,
}

impl FlexFecParameters {
    /// Parameters with the given repair window.
    pub fn with_repair_window(repair_window: Duration) -> Self {
        Self {
            repair_window: Some(repair_window),
        }
    }

    /// Read the parameters from the value of an `a=fmtp` line (what follows the payload type),
    /// a semicolon-separated list of `name=value` pairs (section 5.2).
    ///
    /// Names are compared without case; unknown parameters are ignored. `repair-window:200000`,
    /// the spelling of the RFC's second SDP example (section 7.1.2), is read as well.
    pub fn parse(fmtp: &str) -> Self {
        let mut parameters = Self::default();
        for pair in fmtp.split(';') {
            let pair = pair.trim();
            let Some((name, value)) = pair.split_once('=').or_else(|| pair.split_once(':')) else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("repair-window")
                && let Ok(microseconds) = value.trim().parse::<u64>()
            {
                parameters.repair_window = Some(Duration::from_micros(microseconds));
            }
        }
        parameters
    }

    /// The `a=fmtp` value for these parameters: `repair-window=<microseconds>`, or the empty
    /// string when there is no repair window to state.
    pub fn to_fmtp(&self) -> String {
        match self.repair_window {
            Some(repair_window) => format!("repair-window={}", repair_window.as_micros()),
            None => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Section 7.1.1: `a=fmtp:98; repair-window=200000` is a 200 ms repair window.
    #[test]
    fn the_repair_window_is_read_in_microseconds() {
        assert_eq!(
            Some(Duration::from_millis(200)),
            FlexFecParameters::parse("repair-window=200000").repair_window
        );
        assert_eq!(
            Some(Duration::from_millis(200)),
            FlexFecParameters::parse("; repair-window=200000").repair_window,
            "as section 7.1.1 writes it, after the payload type"
        );
        assert_eq!(
            Some(Duration::from_millis(200)),
            FlexFecParameters::parse(" repair-window:200000").repair_window,
            "as section 7.1.2 writes it"
        );
        assert_eq!(
            Some(Duration::from_secs(10)),
            FlexFecParameters::parse("Repair-Window = 10000000 ").repair_window
        );
    }

    /// Section 5.2.1: any unknown option is ignored.
    #[test]
    fn unknown_parameters_are_ignored() {
        let parameters = FlexFecParameters::parse("L=4; D=3;ToP=2;repair-window=5000;x-future=1");
        assert_eq!(Some(Duration::from_millis(5)), parameters.repair_window);
        assert_eq!(
            "repair-window=5000",
            parameters.to_fmtp(),
            "and not written back"
        );
    }

    #[test]
    fn a_line_without_a_usable_repair_window_has_none() {
        for line in [
            "",
            "repair-window",
            "repair-window=",
            "repair-window=soon",
            "L=4",
        ] {
            assert_eq!(
                None,
                FlexFecParameters::parse(line).repair_window,
                "{line:?}"
            );
        }
        assert_eq!("", FlexFecParameters::default().to_fmtp());
    }

    #[test]
    fn the_repair_window_is_written_in_microseconds() {
        assert_eq!(
            "repair-window=200000",
            FlexFecParameters::with_repair_window(Duration::from_millis(200)).to_fmtp()
        );
    }
}
