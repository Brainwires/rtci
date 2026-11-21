/// `ICE-CONTROLLING` and `ICE-CONTROLLED`, which resolve role conflicts.
pub mod control;
/// libwebrtc's `NOMINATION` attribute, by which a controlling agent renominates.
pub mod nomination;
/// The `PRIORITY` attribute carried in connectivity checks.
pub mod priority;
/// The `USE-CANDIDATE` flag, by which the controlling agent nominates a pair.
pub mod use_candidate;
