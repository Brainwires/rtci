//! The informational attributes of RFC 8866 section 6: `tool`, `type`, `orient` and
//! `quality`. WebRTC gives them no meaning; they are read and written with their grammar so
//! an application that uses them gets them checked.

use crate::attribute::string_attribute;
use crate::grammar;

string_attribute!(
    /// `a=tool:<name and version>` (RFC 8866 section 6.3, session level): the tool that
    /// created the description. `text`, any `byte-string`.
    Tool,
    "tool",
    "a=tool",
    |v| grammar::is_byte_string(v)
);

string_attribute!(
    /// `a=type:<conference type>` (RFC 8866 section 6.9, session level): `broadcast`,
    /// `meeting`, `moderated`, `test` or `H332`, case-sensitive.
    ConferenceType,
    "type",
    "a=type",
    |v| matches!(v, "broadcast" | "meeting" | "moderated" | "test" | "H332")
);

string_attribute!(
    /// `a=orient:<orientation>` (RFC 8866 section 6.8, media level): the orientation of a
    /// whiteboard or presentation workspace, `portrait`, `landscape` or `seascape`,
    /// case-sensitive.
    Orient,
    "orient",
    "a=orient",
    |v| matches!(v, "portrait" | "landscape" | "seascape")
);

string_attribute!(
    /// `a=quality:<quality>` (RFC 8866 section 6.14, media level): a suggested encoding
    /// quality, `zero-based-integer` (0 to 10 for video, 5 being the default behaviour).
    Quality,
    "quality",
    "a=quality",
    |v| v == "0" || (grammar::is_integer(v) && v.parse::<u32>().is_ok())
);

impl Quality {
    /// The value as a number.
    pub fn value(&self) -> u32 {
        // Checked by `parse`: `0` or an integer that fits.
        self.as_str().parse().unwrap_or(0)
    }
}
