#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! STUN for the Sans-I/O WebRTC stack.
//!
//! Session Traversal Utilities for NAT ([RFC 8489], which obsoletes [RFC 5389]), plus the
//! attributes ICE ([RFC 8445]) and TURN ([RFC 5766]) layer on top. In WebRTC, STUN does
//! double duty: it discovers a peer's server-reflexive address, and its binding
//! request/response exchange *is* the ICE connectivity check.
//!
//! # Structure
//!
//! * [`message`] — [`Message`](message::Message), the STUN message itself: build one from
//!   attributes, marshal it, unmarshal one off the wire.
//! * [`attributes`], [`textattrs`], [`uattrs`], [`xoraddr`], [`error_code`] — the attribute
//!   types, including `XOR-MAPPED-ADDRESS`, `USERNAME`, `REALM` and `ERROR-CODE`.
//! * [`integrity`], [`fingerprint`] — `MESSAGE-INTEGRITY` (HMAC-SHA1),
//!   `MESSAGE-INTEGRITY-SHA256` and `FINGERPRINT` (CRC-32), the attributes whose values depend
//!   on the encoded message.
//! * [`validated`] — **how a received message is checked and read**:
//!   [`Validator`](validated::Validator) runs the FINGERPRINT, integrity and unknown-attribute
//!   checks and returns a [`ValidatedMessage`](validated::ValidatedMessage) that shows only
//!   the attributes the integrity covers.
//! * [`long_term`], [`nonce_cookie`], [`password_algorithm`], [`userhash`], [`opaque`] — the
//!   long-term credential mechanism of RFC 8489: challenge processing with bid-down
//!   protection, `PASSWORD-ALGORITHM(S)`, `USERHASH`, and the OpaqueString profile.
//! * [`alternate`] — the client side of 300 (Try Alternate): `ALTERNATE-SERVER`,
//!   `ALTERNATE-DOMAIN` and the redirection-loop rule.
//! * [`agent`], [`client`] — transaction tracking and a Sans-I/O client for talking to a
//!   STUN server, with the retransmission timer of RFC 8489 section 6.2.1.
//! * [`uri`] — parsing `stun:`/`stuns:` URLs.
//! * [`checks`] — validation helpers for received messages.
//!
//! # Receiving a message
//!
//! An integrity attribute covers the message up to itself, so RFC 8489 section 9 has agents
//! ignore every attribute after it. Reading attributes off a [`Message`](message::Message)
//! that has only been through [`MessageIntegrity::check`](integrity::MessageIntegrity::check)
//! does not do that. Receivers go through [`validated`]:
//!
//! ```
//! # use rtc_stun::message::Message;
//! # use rtc_stun::attributes::{ATTR_USERNAME, STUN_ATTRIBUTES};
//! use rtc_stun::validated::{Rejection, Validator};
//! # fn receive(received: &Message, key: &[u8], crypto: &dyn rtc_stun::crypto::RTCCrypto) {
//! let validator = Validator::new().require_fingerprint().known_attributes(&STUN_ATTRIBUTES);
//! match validator.authenticate(received, key, crypto) {
//!     // Only attributes ahead of the integrity attribute can be read from `valid`.
//!     Ok(valid) => { let _ = valid.get(ATTR_USERNAME); }
//!     // A request: answer 420 with `validated::unknown_attributes_response`.
//!     Err(Rejection::UnknownAttributes(_unknown)) => {}
//!     // Anything else is dropped.
//!     Err(_) => {}
//! }
//! # }
//! ```
//!
//! # Example
//!
//! ```
//! use rtc_stun::attributes::ATTR_SOFTWARE;
//! use rtc_stun::message::{BINDING_REQUEST, Message, TransactionId};
//! use rtc_stun::textattrs::TextAttribute;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut msg = Message::new();
//! msg.build(&[
//!     Box::new(TransactionId::new()),
//!     Box::new(BINDING_REQUEST),
//!     Box::new(TextAttribute::new(ATTR_SOFTWARE, "webrtc-rs".to_owned())),
//! ])?;
//!
//! // `build` encodes as it goes, so `raw` is ready to send.
//! assert!(!msg.raw.is_empty());
//!
//! let mut decoded = Message::new();
//! decoded.raw = msg.raw.clone();
//! decoded.decode()?;
//! assert_eq!(decoded.typ, BINDING_REQUEST);
//! # Ok(())
//! # }
//! ```
//!
//! Most applications do not depend on this crate directly — [`rtc-ice`] and
//! [`rtc-turn`] build on it, and the [`rtc`](https://docs.rs/rtc) crate drives those.
//!
//! [RFC 8489]: https://datatracker.ietf.org/doc/html/rfc8489
//! [RFC 5389]: https://datatracker.ietf.org/doc/html/rfc5389
//! [RFC 3489]: https://datatracker.ietf.org/doc/html/rfc3489
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
//! [RFC 5766]: https://datatracker.ietf.org/doc/html/rfc5766
//! [`rtc-ice`]: https://docs.rs/rtc-ice
//! [`rtc-turn`]: https://docs.rs/rtc-turn

#[macro_use]
extern crate lazy_static;

/// The crypto provider API.
///
/// Re-exported because this crate's public constructors take an
/// [`Arc<dyn RTCCryptoProvider>`](crypto::RTCCryptoProvider), which a caller must be able to name
/// without adding — and version-matching — a direct `rtc-crypto` dependency.
pub use crypto;

/// Socket-address helpers shared by the address attributes.
pub mod addr;
/// Transaction tracking: which requests are outstanding and when they time out.
pub mod agent;
/// The client side of 300 (Try Alternate): `ALTERNATE-SERVER` and the redirection-loop rule.
pub mod alternate;
/// The STUN attribute types and the raw attribute representation.
pub mod attributes;
/// Validation helpers for received messages and attributes.
pub mod checks;
/// A Sans-I/O STUN client for talking to a STUN server.
pub mod client;
/// The `ERROR-CODE` attribute and the codes defined by STUN, TURN and ICE.
pub mod error_code;
/// The `FINGERPRINT` attribute, a CRC-32 over the message.
pub mod fingerprint;
/// The `MESSAGE-INTEGRITY` and `MESSAGE-INTEGRITY-SHA256` attributes, HMACs over the message.
pub mod integrity;
/// The client side of the long-term credential mechanism.
pub mod long_term;
/// The STUN message itself: header, attributes, and encoding.
pub mod message;
/// The nonce cookie and its STUN Security Feature bits.
pub mod nonce_cookie;
/// The OpaqueString profile (RFC 8265) for user names, realms and passwords.
pub mod opaque;
/// The `PASSWORD-ALGORITHM` and `PASSWORD-ALGORITHMS` attributes.
pub mod password_algorithm;
/// Text-valued attributes such as `USERNAME`, `REALM` and `SOFTWARE`.
pub mod textattrs;
/// The `UNKNOWN-ATTRIBUTES` attribute, listing attributes a server could not process.
pub mod uattrs;
/// Parsing `stun:` and `stuns:` URIs.
pub mod uri;
/// The `USERHASH` attribute.
pub mod userhash;
/// Checking a received message and reading only what its integrity covers.
pub mod validated;
/// The `XOR-MAPPED-ADDRESS` attribute, whose value is masked with the magic cookie.
pub mod xoraddr;

/// IANA assigned ports for "stun" protocol.
pub const DEFAULT_PORT: u16 = 3478;
/// The default port for `stuns:` (STUN over TLS/DTLS).
pub const DEFAULT_TLS_PORT: u16 = 5349;
