/// Serializes a `SystemInstant` as epoch time in milliseconds, an `f64` with sub-millisecond
/// precision: W3C stats timestamps are `DOMHighResTimeStamp`s, milliseconds that "SHOULD be
/// accurate to 5 microseconds".
pub mod instant_to_epoch {
    use crate::time::SystemInstant;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    /// Serializes an [`SystemInstant`] as a duration relative to the process's reference instant.
    ///
    /// [`SystemInstant`] has no absolute representation, so this encodes the offset instead. Use
    /// with `#[serde(with = "...")]`.
    ///
    /// # Errors
    ///
    /// Propagates any failure from the underlying serializer.
    pub fn serialize<S>(instant: &SystemInstant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let epoch = instant.duration_since_unix_epoch();
        let epoch_ms = epoch.as_secs_f64() * 1000.0;
        epoch_ms.serialize(serializer)
    }

    /// Deserializes an [`SystemInstant`] from the relative offset written by [`serialize`].
    ///
    /// # Errors
    ///
    /// Propagates any failure from the underlying deserializer.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemInstant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let epoch_ms = f64::deserialize(deserializer)?;
        let epoch_duration = Duration::from_secs_f64(epoch_ms / 1000.0);
        Ok(SystemInstant::from_epoch(epoch_duration))
    }
}

#[cfg(test)]
mod tests {
    use super::instant_to_epoch;
    use crate::time::SystemInstant;
    use std::time::Duration;

    // Milliseconds, with the sub-millisecond part kept (it was seconds truncated to whole
    // milliseconds), and the same value read back.
    #[test]
    fn instant_to_epoch_is_milliseconds_with_sub_millisecond_precision() {
        let at = SystemInstant::from_epoch(Duration::from_micros(1_794_904_159_643_250));
        let json = instant_to_epoch::serialize(&at, serde_json::value::Serializer).unwrap();
        let ms = json.as_f64().unwrap();
        assert!((ms - 1_794_904_159_643.25).abs() < 0.001, "{ms}");
        let back = instant_to_epoch::deserialize(json).unwrap();
        let diff = back
            .duration_since_unix_epoch()
            .abs_diff(at.duration_since_unix_epoch());
        assert!(diff < Duration::from_micros(1), "{diff:?}");
    }
}
