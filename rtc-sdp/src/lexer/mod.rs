//! Splitting a description into `<type>=<value>` lines, and writing them back.

use core::fmt;
use std::fmt::Display;

use shared::error::{Error, Result};

pub(crate) const END_LINE: &str = "\r\n";

/// One `<type>=<value>` line. The value is the text between `=` and the line ending,
/// unchanged: RFC 8866 section 9 values are byte-strings, and white space is part of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Line<'a> {
    /// The type letter.
    pub(crate) kind: u8,
    /// Everything after the `=`.
    pub(crate) value: &'a str,
}

/// Splits `text` into lines.
///
/// A line ends in CRLF, or in a bare LF (RFC 8866 section 5: "parsers SHOULD be tolerant and
/// also accept lines terminated with a single newline character"); the last line may lack
/// its ending. A CR anywhere else, or a NUL, is refused: neither can be part of a value.
///
/// An empty line is not SDP. Empty lines after the last line are skipped whatever
/// `blank_lines` says (a description that went through a text field often ends in one);
/// empty lines before or between lines are skipped only when `blank_lines` is set.
pub(crate) fn lines(text: &str, blank_lines: bool, max_lines: usize) -> Result<Vec<Line<'_>>> {
    let mut out = Vec::new();
    let mut pending_blank = false;
    let mut count = 0usize;

    let mut rest = text;
    while !rest.is_empty() {
        let (raw, next) = match rest.find('\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        rest = next;
        let line = raw.strip_suffix('\r').unwrap_or(raw);

        count += 1;
        if count > max_lines {
            return Err(Error::SdpInvalidValue(format!(
                "session description has more than {max_lines} lines"
            )));
        }

        if line.is_empty() {
            pending_blank = true;
            continue;
        }
        if pending_blank && !blank_lines {
            return Err(Error::SdpInvalidSyntax(
                "an empty line inside the description".to_owned(),
            ));
        }
        pending_blank = false;

        if line.bytes().any(|b| b == 0 || b == b'\r') {
            return Err(Error::SdpInvalidSyntax(
                "a line contains NUL or a bare CR".to_owned(),
            ));
        }

        let bytes = line.as_bytes();
        if bytes.len() < 2 || bytes[1] != b'=' || !bytes[0].is_ascii() {
            return Err(Error::SdpInvalidSyntax(quote(line)));
        }
        out.push(Line {
            kind: bytes[0],
            value: &line[2..],
        });
    }

    Ok(out)
}

/// The start of a line, for an error message.
fn quote(line: &str) -> String {
    let mut end = line.len().min(32);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("`{}`", &line[..end])
}

pub(crate) fn write_key_value<W: fmt::Write, V: Display>(
    writer: &mut W,
    key: &str,
    value: Option<V>,
) -> fmt::Result {
    let Some(value) = value else {
        return Ok(());
    };

    write!(writer, "{key}{value}{END_LINE}")
}

pub(crate) fn write_key_slice_of_values<W: fmt::Write, V: Display>(
    writer: &mut W,
    key: &str,
    value: &[V],
) -> fmt::Result {
    if value.is_empty() {
        return Ok(());
    }

    let mut first = true;

    write!(writer, "{key}")?;
    for val in value {
        if first {
            first = false;
            write!(writer, "{val}")?;
        } else {
            write!(writer, " {val}")?;
        }
    }
    write!(writer, "{END_LINE}")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str, blank: bool) -> Result<Vec<(char, String)>> {
        Ok(lines(text, blank, 100)?
            .into_iter()
            .map(|l| (l.kind as char, l.value.to_owned()))
            .collect())
    }

    #[test]
    fn crlf_and_bare_lf_end_a_line_and_the_last_line_needs_no_ending() {
        let want = vec![('v', "0".to_owned()), ('s', " ".to_owned())];
        assert_eq!(kinds("v=0\r\ns= \r\n", false).unwrap(), want);
        assert_eq!(kinds("v=0\ns= \n", false).unwrap(), want);
        assert_eq!(kinds("v=0\r\ns= ", false).unwrap(), want);
    }

    #[test]
    fn a_value_keeps_its_white_space_and_its_equal_signs() {
        assert_eq!(
            kinds("a= x = y \t\r\n", false).unwrap(),
            vec![('a', " x = y \t".to_owned())]
        );
    }

    #[test]
    fn a_bare_cr_or_a_nul_is_refused() {
        assert!(kinds("v=0\ro=x\r\n", false).is_err());
        assert!(kinds("s=a\rb\r\n", false).is_err());
        assert!(kinds("s=a\0b\r\n", false).is_err());
    }

    #[test]
    fn a_line_is_one_type_letter_then_an_equal_sign() {
        for bad in [
            "v\r\n", "v =0\r\n", " v=0\r\n", "vv=0\r\n", "=0\r\n", "é=0\r\n",
        ] {
            assert!(kinds(bad, true).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn empty_lines_are_skipped_at_the_end_and_elsewhere_only_on_request() {
        let want = vec![('v', "0".to_owned()), ('s', "-".to_owned())];
        assert_eq!(kinds("v=0\r\ns=-\r\n\r\n\n", false).unwrap(), want);
        assert!(kinds("v=0\r\n\r\ns=-\r\n", false).is_err());
        assert!(kinds("\r\nv=0\r\ns=-\r\n", false).is_err());
        assert_eq!(kinds("\r\nv=0\r\n\r\ns=-\r\n", true).unwrap(), want);
    }

    #[test]
    fn the_line_count_is_bounded() {
        assert!(lines("a=x\r\na=y\r\n", false, 2).is_ok());
        assert!(lines("a=x\r\na=y\r\na=z\r\n", false, 2).is_err());
    }
}
