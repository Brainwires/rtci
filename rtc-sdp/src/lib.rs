#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! SDP parsing and serialization.
//!
//! The Session Description Protocol ([RFC 8866], superseding [RFC 4566]) as WebRTC uses
//! it: offers and answers, media sections, and the attributes that carry codecs, ICE
//! candidates, DTLS fingerprints and header-extension mappings ([RFC 8285]).
//!
//! # Structure
//!
//! * [`SessionDescription`] — a whole session description: `unmarshal` one from a string,
//!   `marshal` it back, or build one up section by section. `unmarshal` is the RFC 8866
//!   section 9 grammar; [`ParseOptions`] names what else an application may ask it to
//!   accept.
//! * [`MediaDescription`] — one `m=` section, with its attributes, formats and connection
//!   data.
//! * [`attribute`] — typed, validated attributes: one type per attribute the WebRTC
//!   specifications use (`mid`, `msid`, `rid`, `simulcast`, `rtcp-fb`, `candidate`,
//!   `fingerprint`, ...), each parsed against the ABNF of its RFC, with an accessor on
//!   the two description types; [`SessionDescription::validate`] to check a whole
//!   description; and [`attribute::mux`], the RFC 8859 multiplexing category of every
//!   attribute.
//! * [`extmap`] — `a=extmap` header-extension declarations and the well-known extension
//!   URIs.
//! * [`direction`] — `sendrecv`/`sendonly`/`recvonly`/`inactive`.
//!
//! # Example
//!
//! ```
//! use rtc_sdp::SessionDescription;
//! use std::io::Cursor;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let sdp = "v=0\r\n\
//!            o=- 0 0 IN IP4 127.0.0.1\r\n\
//!            s=-\r\n\
//!            t=0 0\r\n\
//!            m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
//!            a=mid:0\r\n\
//!            a=sendrecv\r\n";
//!
//! let desc = SessionDescription::unmarshal(&mut Cursor::new(sdp))?;
//! for media in &desc.media_descriptions {
//!     assert_eq!(media.media_name.media, "audio");
//!     assert_eq!(media.attribute("mid").flatten(), Some("0"));
//! }
//!
//! // Printing it back yields valid SDP.
//! assert!(desc.marshal().starts_with("v=0"));
//! # Ok(())
//! # }
//! ```
//!
//! Attribute values are kept as text by the parser and get their grammar from the typed
//! accessors:
//!
//! ```
//! use rtc_sdp::SessionDescription;
//! use rtc_sdp::attribute::RtcpFbKind;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let desc: SessionDescription = "v=0\r\n\
//!     o=- 0 0 IN IP4 127.0.0.1\r\n\
//!     s=-\r\n\
//!     t=0 0\r\n\
//!     a=group:BUNDLE 0\r\n\
//!     m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
//!     c=IN IP4 0.0.0.0\r\n\
//!     a=mid:0\r\n\
//!     a=rtpmap:96 VP8/90000\r\n\
//!     a=rtcp-fb:96 nack pli\r\n\
//!     a=rid:hi send max-width=1280\r\n\
//!     a=simulcast:send hi\r\n"
//!     .parse()?;
//! desc.validate()?;
//! assert!(desc.bundle_groups()?[0].contains("0"));
//!
//! let video = &desc.media_descriptions[0];
//! assert_eq!(video.rtpmaps()?[0].clock_rate, 90000);
//! assert_eq!(video.rtcp_fbs()?[0].kind(), RtcpFbKind::NackPli);
//! assert_eq!(video.rids()?[0].max_width(), Some(1280));
//! assert!(video.simulcast()?.is_some());
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```
//!
//! This crate is deliberately a *syntax* layer: it parses, checks and prints SDP faithfully
//! and leaves negotiation semantics ([RFC 9429]) to the [`rtc`](https://docs.rs/rtc) crate,
//! which re-exports it as `rtc::sdp`.
//!
//! [RFC 8866]: https://datatracker.ietf.org/doc/html/rfc8866
//! [RFC 4566]: https://datatracker.ietf.org/doc/html/rfc4566
//! [RFC 8285]: https://datatracker.ietf.org/doc/html/rfc8285
//! [RFC 9429]: https://datatracker.ietf.org/doc/html/rfc9429

/// Typed, validated attributes, and the RFC 8859 multiplexing categories.
pub mod attribute;
/// Session and media descriptions — the `v=`/`m=` structure of an SDP document.
pub mod description;
/// Transmission direction (`sendrecv`, `sendonly`, `recvonly`, `inactive`).
pub mod direction;
/// `a=extmap` RTP header-extension declarations and the well-known extension URIs.
pub mod extmap;
/// Parsing helpers plus the codec and connection-role types shared across descriptions.
pub mod util;

pub(crate) mod grammar;
pub(crate) mod lexer;

pub use description::{
    media::MediaDescription,
    session::{ParseOptions, SessionDescription},
};
