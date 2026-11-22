#[cfg(test)]
mod audit_bugs_test;
#[cfg(test)]
mod browser_test;
#[cfg(test)]
mod description_test;
#[cfg(test)]
mod grammar_test;

/// Field types shared by session and media descriptions (`c=`, `b=`, `a=`).
pub mod common;
/// The `m=` media description and its fields.
pub mod media;
/// The whole session description, plus the well-known attribute keys.
pub mod session;
