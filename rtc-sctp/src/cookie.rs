//! The State Cookie with a message authentication code (RFC 9260 5.1.3).
//!
//! A cookie made here holds everything the association needs from the INIT and the INIT ACK
//! (the two Verification Tags, the initial TSNs, the peer's window, the stream counts, the
//! extensions agreed on, the ports), when it was made, and an HMAC-SHA-256 over all of it
//! under a key only this endpoint has. An endpoint that gets it back in a COOKIE ECHO can
//! therefore build the association from the cookie alone, having kept nothing after the INIT
//! ACK (5.1 B: "MUST NOT allocate any resources or keep any states for the new association").
//!
//! The hash comes from the workspace's crypto provider (`rtc-crypto`), which the application
//! hands over: `rtc-sctp` names no cryptographic implementation of its own.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crypto::{HmacAlgorithm, RTCCryptoProvider, SecretVec};
use std::sync::Arc;
use std::time::{Duration, Instant};

const COOKIE_VERSION: u8 = 1;
const KEY_LENGTH: usize = 32;
const MAC_LENGTH: usize = 32;
/// The cookie without its MAC.
const BODY_LENGTH: usize = 48;
/// A State Cookie made by [`CookieSigner`].
pub(crate) const COOKIE_LENGTH: usize = BODY_LENGTH + MAC_LENGTH;

/// What a State Cookie says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CookieFields {
    /// Which of the endpoint's keys authenticates the cookie (RFC 9260 5.1.3: "the timestamp
    /// ... can be used to determine which key should be used").
    pub(crate) key_id: u8,
    /// When the cookie was made, in milliseconds of the endpoint's clock.
    pub(crate) created_ms: u64,
    /// This side's Initiate Tag and initial TSN, as the INIT ACK had them.
    pub(crate) my_tag: u32,
    pub(crate) my_initial_tsn: u32,
    /// The peer's, as its INIT had them.
    pub(crate) peer_tag: u32,
    pub(crate) peer_initial_tsn: u32,
    pub(crate) peer_rwnd: u32,
    pub(crate) inbound_streams: u16,
    pub(crate) outbound_streams: u16,
    pub(crate) use_forward_tsn: bool,
    pub(crate) use_interleaving: bool,
    pub(crate) reconfig: bool,
    /// This side's port and the peer's.
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    /// The Tie-Tags (RFC 9260 5.2.1, 5.2.2): the tags of the association that existed when
    /// the INIT arrived, 0 when there was none.
    pub(crate) local_tie_tag: u32,
    pub(crate) peer_tie_tag: u32,
}

impl CookieFields {
    fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(COOKIE_LENGTH);
        buf.put_u8(COOKIE_VERSION);
        buf.put_u8(self.key_id);
        buf.put_u8(
            u8::from(self.use_forward_tsn)
                | u8::from(self.use_interleaving) << 1
                | u8::from(self.reconfig) << 2,
        );
        buf.put_u8(0);
        buf.put_u64(self.created_ms);
        buf.put_u32(self.my_tag);
        buf.put_u32(self.my_initial_tsn);
        buf.put_u32(self.peer_tag);
        buf.put_u32(self.peer_initial_tsn);
        buf.put_u32(self.peer_rwnd);
        buf.put_u16(self.inbound_streams);
        buf.put_u16(self.outbound_streams);
        buf.put_u16(self.source_port);
        buf.put_u16(self.destination_port);
        buf.put_u32(self.local_tie_tag);
        buf.put_u32(self.peer_tie_tag);
        debug_assert_eq!(BODY_LENGTH, buf.len());
        buf
    }

    fn decode(mut body: &[u8]) -> Option<Self> {
        if body.len() != BODY_LENGTH || body.get_u8() != COOKIE_VERSION {
            return None;
        }
        let key_id = body.get_u8();
        let flags = body.get_u8();
        body.advance(1);
        Some(CookieFields {
            key_id,
            created_ms: body.get_u64(),
            my_tag: body.get_u32(),
            my_initial_tsn: body.get_u32(),
            peer_tag: body.get_u32(),
            peer_initial_tsn: body.get_u32(),
            peer_rwnd: body.get_u32(),
            inbound_streams: body.get_u16(),
            outbound_streams: body.get_u16(),
            use_forward_tsn: flags & 1 != 0,
            use_interleaving: flags & 2 != 0,
            reconfig: flags & 4 != 0,
            source_port: body.get_u16(),
            destination_port: body.get_u16(),
            local_tie_tag: body.get_u32(),
            peer_tie_tag: body.get_u32(),
        })
    }
}

/// Makes and checks State Cookies under one secret key.
pub(crate) struct CookieSigner {
    provider: Arc<dyn RTCCryptoProvider>,
    /// RFC 9260 5.1.3: "a secret key" that "SHOULD be random"; it is the provider's random
    /// bytes, and is zeroed when dropped.
    key: SecretVec,
    key_id: u8,
    /// The zero of the cookies' timestamps.
    epoch: Instant,
    /// When this key came into use.
    pub(crate) since: Instant,
}

impl std::fmt::Debug for CookieSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieSigner")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl CookieSigner {
    /// A signer with a new random key. `None` when the provider has no randomness or no
    /// HMAC-SHA-256 to give.
    pub(crate) fn new(
        provider: Arc<dyn RTCCryptoProvider>,
        key_id: u8,
        epoch: Instant,
        now: Instant,
    ) -> Option<Self> {
        let mut key = vec![0u8; KEY_LENGTH];
        provider.random().fill(&mut key).ok()?;
        let key = SecretVec::new(key);
        // Fail now, not at the first INIT, if the provider cannot do the MAC.
        provider
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, key.as_ref())
            .ok()?;
        Some(CookieSigner {
            provider,
            key,
            key_id,
            epoch,
            since: now,
        })
    }

    pub(crate) fn key_id(&self) -> u8 {
        self.key_id
    }

    /// `at` on the clock the cookies are stamped with.
    pub(crate) fn timestamp(&self, at: Instant) -> u64 {
        at.saturating_duration_since(self.epoch).as_millis() as u64
    }

    /// How long ago the cookie was made.
    pub(crate) fn age(&self, fields: &CookieFields, now: Instant) -> Duration {
        Duration::from_millis(self.timestamp(now).saturating_sub(fields.created_ms))
    }

    /// The cookie for `fields`: the fields and their MAC.
    pub(crate) fn seal(&self, fields: &CookieFields) -> Option<Bytes> {
        let mut cookie = CookieFields {
            key_id: self.key_id,
            ..fields.clone()
        }
        .encode();
        let mut mac = [0u8; MAC_LENGTH];
        self.provider
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, self.key.as_ref())
            .ok()?
            .sign(&[&cookie[..]], &mut mac)
            .ok()?;
        cookie.put_slice(&mac);
        Some(cookie.freeze())
    }

    /// What `cookie` says, if this signer made it: its MAC is verified, in constant time
    /// (RFC 9260 5.1.5 1, 2).
    pub(crate) fn open(&self, cookie: &[u8]) -> Option<CookieFields> {
        if cookie.len() != COOKIE_LENGTH {
            return None;
        }
        let (body, mac) = cookie.split_at(BODY_LENGTH);
        self.provider
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, self.key.as_ref())
            .ok()?
            .verify(&[body], mac)
            .ok()?;
        CookieFields::decode(body)
    }
}

/// The key id a cookie names, without checking anything else about it.
pub(crate) fn cookie_key_id(cookie: &[u8]) -> Option<u8> {
    (cookie.len() == COOKIE_LENGTH && cookie[0] == COOKIE_VERSION).then(|| cookie[1])
}
