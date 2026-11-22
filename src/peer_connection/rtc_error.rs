//! `RTCError` and `RTCErrorDetailType` (W3C webrtc-pc section 11): the WebRTC-specific detail an
//! API layer attaches to an `OperationError`, and that error events carry.
//!
//! The engine reports failures as [`shared::error::Error`] values. Where the W3C API asks for
//! an `RTCError`, the engine gives one: [`RTCError::from_error`] maps an error a method
//! returned (a description that does not parse is `sdp-syntax-error`, with its line), and the
//! error events carry one built where the failure happened (a DTLS transport's `error` event,
//! with the alert sent or received; a data channel's `error`, with the SCTP cause code).

use shared::error::Error;
use std::fmt;

/// W3C `RTCErrorDetailType`: which WebRTC failure an [`RTCError`] reports.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RTCErrorDetailType {
    /// `data-channel-failure`: the data channel has failed.
    DataChannelFailure,
    /// `dtls-failure`: the DTLS negotiation failed or the connection ended with a fatal error;
    /// [`RTCError::received_alert`] / [`RTCError::sent_alert`] say which alert.
    DtlsFailure,
    /// `fingerprint-failure`: the remote certificate matched none of the fingerprints the
    /// remote description gave.
    FingerprintFailure,
    /// `sctp-failure`: the SCTP negotiation failed or the association ended with a fatal error;
    /// [`RTCError::sctp_cause_code`] says why.
    SctpFailure,
    /// `sdp-syntax-error`: the session description does not parse;
    /// [`RTCError::sdp_line_number`] says where.
    SdpSyntaxError,
    /// `hardware-encoder-not-available`: no hardware encoder for the operation.
    HardwareEncoderNotAvailable,
    /// `hardware-encoder-error`: the hardware encoder does not support the parameters.
    HardwareEncoderError,
}

impl RTCErrorDetailType {
    /// The enum value as the W3C IDL spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataChannelFailure => "data-channel-failure",
            Self::DtlsFailure => "dtls-failure",
            Self::FingerprintFailure => "fingerprint-failure",
            Self::SctpFailure => "sctp-failure",
            Self::SdpSyntaxError => "sdp-syntax-error",
            Self::HardwareEncoderNotAvailable => "hardware-encoder-not-available",
            Self::HardwareEncoderError => "hardware-encoder-error",
        }
    }
}

impl fmt::Display for RTCErrorDetailType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// W3C `RTCError`: an `OperationError` with WebRTC detail (webrtc-pc section 11.1).
///
/// Each optional member is set only for the [`error_detail`](Self::error_detail) the spec
/// gives it to, and is `None` (the IDL's null) otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RTCError {
    /// `errorDetail`.
    pub error_detail: RTCErrorDetailType,
    /// The error's message.
    pub message: String,
    /// `sdpLineNumber`: for `sdp-syntax-error`, the line (from 1) the error is on.
    pub sdp_line_number: Option<u32>,
    /// `sctpCauseCode`: for `sctp-failure`, the SCTP cause code (RFC 9260 section 3.3.10) of
    /// the failure.
    pub sctp_cause_code: Option<u16>,
    /// `receivedAlert`: for `dtls-failure`, the fatal DTLS alert received.
    pub received_alert: Option<u8>,
    /// `sentAlert`: for `dtls-failure`, the fatal DTLS alert sent.
    pub sent_alert: Option<u8>,
}

impl RTCError {
    /// An error of `error_detail` with no optional member set.
    pub fn new(error_detail: RTCErrorDetailType, message: impl Into<String>) -> Self {
        Self {
            error_detail,
            message: message.into(),
            sdp_line_number: None,
            sctp_cause_code: None,
            received_alert: None,
            sent_alert: None,
        }
    }

    /// The `RTCError` an API layer rejects with for `error`, when it is one the W3C reports
    /// as an `RTCError`; `None` for an error the W3C reports otherwise (a `TypeError`, an
    /// `InvalidStateError`, ...).
    ///
    /// A description that does not parse ([`Error::SdpSyntaxError`]) is `sdp-syntax-error`
    /// with its line number.
    pub fn from_error(error: &Error) -> Option<Self> {
        match error {
            Error::SdpSyntaxError { line_number, error } => Some(Self {
                sdp_line_number: line_number.and_then(|n| u32::try_from(n).ok()),
                ..Self::new(RTCErrorDetailType::SdpSyntaxError, error.to_string())
            }),
            _ => None,
        }
    }
}

impl fmt::Display for RTCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_detail, self.message)
    }
}

impl std::error::Error for RTCError {}
