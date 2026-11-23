//! The crate's error type.

/// What can go wrong in the audio pipeline.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// A codec refused the input or failed (the backend's message).
    #[error("codec: {0}")]
    Codec(String),
    /// A frame or packet of the wrong size, rate or channel count.
    #[error("format: {0}")]
    Format(String),
    /// A configuration value outside what the stage supports.
    #[error("configuration: {0}")]
    Config(String),
    /// A payload type or codec the pipeline has no decoder or encoder for.
    #[error("unsupported codec: {0}")]
    Unsupported(String),
    /// The peer connection refused an operation (the engine's message).
    #[error("engine: {0}")]
    Engine(String),
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;
