//! The OpaqueString profile of the PRECIS framework (RFC 8265 section 4.2), which RFC 8489
//! applies to user names, realms and passwords before they are compared, hashed or used as a
//! key (sections 9.1.1, 9.2.2, 14.3, 14.4 and 14.9).
//!
//! The profile leaves case alone, maps every non-ASCII space to U+0020, applies Unicode
//! Normalization Form C, and refuses the code points the PRECIS FreeformClass disallows
//! (control characters, unassigned code points, default-ignorable ones such as U+00AD) and the
//! empty string.

use shared::error::*;
use std::borrow::Cow;

use precis_profiles::OpaqueString;
use precis_profiles::precis_core::profile::PrecisFastInvocation;

/// Applies the OpaqueString profile to `s`.
///
/// Printable ASCII is returned as it is, which covers ICE user fragments and passwords and
/// most TURN credentials.
///
/// # Errors
///
/// Fails when `s` is empty or holds a code point the profile disallows.
pub fn opaque_string(s: &str) -> Result<Cow<'_, str>> {
    // Space and the visible ASCII characters are all in the FreeformClass and already
    // normalized, so the Unicode tables are not needed for them.
    if !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Ok(Cow::Borrowed(s));
    }
    // The string may be a password: the error says nothing about its content.
    OpaqueString::enforce(s)
        .map_err(|_| Error::Other("not an OpaqueString (RFC 8265 section 4.2)".to_owned()))
}

#[cfg(test)]
mod opaque_test {
    use super::*;

    /// RFC 8265 section 4.2.2: case is preserved, non-ASCII spaces become U+0020, and the
    /// result is in Normalization Form C.
    #[test]
    fn test_opaque_string_maps_spaces_and_normalizes_to_nfc() -> Result<()> {
        // Examples of RFC 8265 section 4.2.3 (Table 2).
        assert_eq!(
            opaque_string("correct horse battery staple")?,
            "correct horse battery staple"
        );
        assert_eq!(
            opaque_string("Correct Horse Battery Staple")?,
            "Correct Horse Battery Staple"
        );
        assert_eq!(opaque_string("\u{3c0}\u{df}\u{e5}")?, "\u{3c0}\u{df}\u{e5}");
        assert_eq!(opaque_string("Jack of \u{2666}s")?, "Jack of \u{2666}s");
        // OGHAM SPACE MARK is mapped to SPACE.
        assert_eq!(opaque_string("foo\u{1680}bar")?, "foo bar");
        // "a" followed by COMBINING RING ABOVE composes to U+00E5.
        assert_eq!(opaque_string("a\u{30a}")?, "\u{e5}");
        // The user name of RFC 8489 appendix B.1 is unaffected.
        let matrix = "\u{30de}\u{30c8}\u{30ea}\u{30c3}\u{30af}\u{30b9}";
        assert_eq!(opaque_string(matrix)?, matrix);
        Ok(())
    }

    /// RFC 8265 section 4.2.3: the empty string and control characters are refused.
    #[test]
    fn test_opaque_string_refuses_empty_and_disallowed_code_points() {
        assert!(opaque_string("").is_err());
        assert!(opaque_string("my cat is a \u{9}by").is_err());
        assert!(opaque_string("nul\u{0}").is_err());
        // SOFT HYPHEN is a default-ignorable code point, which the FreeformClass disallows.
        assert!(opaque_string("The\u{ad}M").is_err());
    }
}
