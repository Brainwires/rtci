//! Video size negotiation with `a=imageattr` (RFC 6236; RFC 9429 section 3.6).
//!
//! The receiving side states the frame sizes it can decode in its descriptions (section
//! 3.6.1); the sending side keeps each encoding within what the remote description states
//! (section 3.6.2). The engine has no encoder: [`imageattr_send_resolution`] works out the
//! resolution an encoder producing a given resolution is to send, which
//! `RTCRtpSender::send_resolution` hands the application.

use sdp::attribute::{ImageAttr, ImageAttrList, ImageAttrRange, ImageAttrSet};

/// A range of video frame sizes, in pixels: what a receiver can decode (RFC 9429 section
/// 3.6.1). A range whose minimum exceeds its maximum permits no resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RTCVideoResolutionRange {
    /// The smallest width.
    pub min_width: u32,
    /// The smallest height.
    pub min_height: u32,
    /// The largest width.
    pub max_width: u32,
    /// The largest height.
    pub max_height: u32,
}

impl RTCVideoResolutionRange {
    /// Whether the range permits no resolution at all.
    pub fn is_empty(&self) -> bool {
        self.min_width > self.max_width
            || self.min_height > self.max_height
            || self.max_width == 0
            || self.max_height == 0
    }

    /// The `recv` set of an `a=imageattr` line for the range: `q=1.0` (section 3.6.1: "It
    /// SHOULD be set to '1.0'"), no `sar=` (square pixels only).
    fn recv_set(&self) -> String {
        format!(
            "[x=[{}:{}],y=[{}:{}],q=1.0]",
            self.min_width.max(1),
            self.max_width,
            self.min_height.max(1),
            self.max_height
        )
    }
}

/// The values of the `a=imageattr` lines a description's video section has (RFC 9429
/// section 3.6.1), for its media formats `formats` (payload type and MIME type; repair
/// formats left out by the caller), given the limits for every codec (`default`) and those of
/// particular codecs (`per_codec`, by MIME type). `Some(vec![])` when there are no limits;
/// `None` when they permit no resolution (no line, and the section does not receive).
///
/// One wildcard line when every format has the same limits (RECOMMENDED), else one line per
/// format that has limits.
pub(crate) fn imageattr_lines(
    formats: &[(u8, String)],
    default: Option<RTCVideoResolutionRange>,
    per_codec: &[(String, RTCVideoResolutionRange)],
) -> Option<Vec<String>> {
    if default.is_none() && per_codec.is_empty() {
        return Some(vec![]);
    }
    let limits: Vec<(u8, Option<RTCVideoResolutionRange>)> = formats
        .iter()
        .map(|(pt, mime)| {
            let limit = per_codec
                .iter()
                .find(|(codec, _)| codec.eq_ignore_ascii_case(mime))
                .map(|(_, range)| *range)
                .or(default);
            (*pt, limit)
        })
        .collect();
    if limits.is_empty() {
        return Some(vec![]);
    }
    if limits
        .iter()
        .all(|(_, limit)| limit.is_some_and(|range| range.is_empty()))
    {
        return None;
    }
    let first = limits[0].1;
    if first.is_some_and(|range| !range.is_empty()) && limits.iter().all(|(_, l)| *l == first) {
        let range = first.unwrap_or(RTCVideoResolutionRange {
            min_width: 1,
            min_height: 1,
            max_width: 1,
            max_height: 1,
        });
        return Some(vec![format!("* recv {}", range.recv_set())]);
    }
    Some(
        limits
            .iter()
            .filter_map(|(pt, limit)| {
                limit
                    .filter(|range| !range.is_empty())
                    .map(|range| format!("{pt} recv {}", range.recv_set()))
            })
            .collect(),
    )
}

/// The bounds of an `x=` or `y=` range (a step or a list is taken as its bounds).
fn bounds(range: &ImageAttrRange<u32>) -> (u32, u32) {
    match range {
        ImageAttrRange::Value(v) => (*v, *v),
        ImageAttrRange::Range { min, max, .. } => (*min, *max),
        ImageAttrRange::List(values) => (
            values.iter().copied().min().unwrap_or(0),
            values.iter().copied().max().unwrap_or(0),
        ),
    }
}

/// Whether a set's `sar=` admits square pixels (section 3.6.2: one that asks for non-square
/// pixels "cannot be satisfied and the attribute MUST NOT be used").
fn square_pixels(set: &ImageAttrSet) -> bool {
    let one = |v: &f64| (*v - 1.0).abs() < 1e-9;
    match &set.sar {
        None => true,
        Some(ImageAttrRange::Value(v)) => one(v),
        Some(ImageAttrRange::Range { min, max, .. }) => *min <= 1.0 && 1.0 <= *max,
        Some(ImageAttrRange::List(values)) => values.iter().any(one),
    }
}

/// RFC 9429 section 3.6.2: the resolution an encoder producing `width` x `height` with the
/// format `payload_type` sends, given the `a=imageattr` lines of the remote description's
/// section. `Some` of the input when no `recv` line applies (nothing limits it), the
/// downscaled resolution (same picture aspect ratio) when a set needs it, `None` when no set
/// can be satisfied: the encoding "MUST NOT be transmitted".
///
/// The sets are tried by `q=` (0.5 when absent), highest first, in their order otherwise;
/// a set with non-square pixels is not used, nor one whose minimum the input is below (no
/// upscaling) or whose minimum the downscaled resolution would fall below.
pub(crate) fn imageattr_send_resolution(
    attributes: &[ImageAttr],
    payload_type: u8,
    width: u32,
    height: u32,
) -> Option<(u32, u32)> {
    let mut sets: Vec<&ImageAttrSet> = vec![];
    for attribute in attributes
        .iter()
        .filter(|a| a.payload_type.is_none_or(|pt| pt == payload_type))
    {
        match &attribute.recv {
            None => {}
            // `*`: no restriction.
            Some(ImageAttrList::Any) => return Some((width, height)),
            Some(ImageAttrList::Sets(list)) => sets.extend(list.iter()),
        }
    }
    if sets.is_empty() {
        return Some((width, height));
    }
    // A stable sort keeps the order of sets with the same preference.
    sets.sort_by(|a, b| {
        b.q.unwrap_or(0.5)
            .partial_cmp(&a.q.unwrap_or(0.5))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for set in sets {
        if !square_pixels(set) {
            continue;
        }
        let (min_x, max_x) = bounds(&set.x);
        let (min_y, max_y) = bounds(&set.y);
        if width < min_x || height < min_y {
            continue;
        }
        if width <= max_x && height <= max_y {
            return Some((width, height));
        }
        // Downscale, keeping the picture aspect ratio.
        let scale = (f64::from(max_x) / f64::from(width)).min(f64::from(max_y) / f64::from(height));
        let scaled = (
            (f64::from(width) * scale).floor() as u32,
            (f64::from(height) * scale).floor() as u32,
        );
        if scaled.0 >= min_x.max(1) && scaled.1 >= min_y.max(1) {
            return Some(scaled);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdp::attribute::TypedAttribute;

    fn parse(lines: &[&str]) -> Vec<ImageAttr> {
        lines
            .iter()
            .map(|l| ImageAttr::parse(l).expect("a valid imageattr"))
            .collect()
    }

    fn range(min: (u32, u32), max: (u32, u32)) -> RTCVideoResolutionRange {
        RTCVideoResolutionRange {
            min_width: min.0,
            min_height: min.1,
            max_width: max.0,
            max_height: max.1,
        }
    }

    /// RFC 9429 section 3.6.1, its example: one wildcard line for limits every codec shares.
    #[test]
    fn one_wildcard_line_when_every_codec_has_the_same_limits() {
        let formats = [(96, "video/VP8".to_owned()), (98, "video/VP9".to_owned())];
        assert_eq!(
            imageattr_lines(&formats, Some(range((48, 48), (1280, 720))), &[]),
            Some(vec!["* recv [x=[48:1280],y=[48:720],q=1.0]".to_owned()])
        );
        assert_eq!(imageattr_lines(&formats, None, &[]), Some(vec![]));
    }

    /// "when the supported video codecs have different limitations, specific 'a=imageattr'
    /// attributes MUST be inserted for each payload type"; none permits nothing.
    #[test]
    fn per_payload_type_lines_when_codecs_differ_and_none_when_nothing_is_permitted() {
        let formats = [(96, "video/VP8".to_owned()), (98, "video/VP9".to_owned())];
        assert_eq!(
            imageattr_lines(
                &formats,
                Some(range((48, 48), (1280, 720))),
                &[("video/vp9".to_owned(), range((48, 48), (640, 360)))]
            ),
            Some(vec![
                "96 recv [x=[48:1280],y=[48:720],q=1.0]".to_owned(),
                "98 recv [x=[48:640],y=[48:360],q=1.0]".to_owned()
            ])
        );
        assert_eq!(
            imageattr_lines(&formats, Some(range((48, 48), (0, 0))), &[]),
            None
        );
    }

    /// RFC 9429 section 3.6.2, its example: 1280x720 under a 640x480 maximum is sent as
    /// 640x360; below the minimum, or with non-square pixels only, nothing is sent.
    #[test]
    fn the_send_resolution_follows_the_remote_recv_sets() {
        let attrs = parse(&["100 recv [x=[48:640],y=[48:480],q=1.0]"]);
        assert_eq!(
            imageattr_send_resolution(&attrs, 100, 1280, 720),
            Some((640, 360))
        );
        assert_eq!(
            imageattr_send_resolution(&attrs, 100, 320, 240),
            Some((320, 240))
        );
        assert_eq!(imageattr_send_resolution(&attrs, 100, 40, 40), None);
        assert_eq!(
            imageattr_send_resolution(&attrs, 101, 1280, 720),
            Some((1280, 720)),
            "another format is not limited"
        );
        let attrs = parse(&["* recv [x=[48:640],y=[48:480],sar=1.1]"]);
        assert_eq!(imageattr_send_resolution(&attrs, 100, 320, 240), None);
        // The higher q= is tried first; a set that cannot be satisfied gives way to the next.
        let attrs =
            parse(&["* recv [x=[48:320],y=[48:240],q=0.4] [x=[800:1920],y=[600:1080],q=0.9]"]);
        assert_eq!(
            imageattr_send_resolution(&attrs, 100, 640, 360),
            Some((320, 180))
        );
        assert_eq!(
            imageattr_send_resolution(&attrs, 100, 1920, 1080),
            Some((1920, 1080))
        );
    }
}
