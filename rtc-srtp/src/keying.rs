//! Master keys over a context's lifetime: the key derivation rate, the Master Key Identifier
//! (MKI), the number of packets a master key may protect, and the events that tell the
//! application to re-key ([RFC 3711] sections 3.2.1, 4.3.1, 8.1 and 9.2).
//!
//! [RFC 3711]: https://www.rfc-editor.org/rfc/rfc3711

use shared::error::{Error, Result};

/// The most SRTP packets one master key may protect (RFC 3711 section 9.2, RFC 7714
/// section 10): 2^48.
pub const MAX_SRTP_PACKETS_PER_KEY: u64 = 1 << 48;
/// The most SRTCP packets one master key may protect (RFC 3711 section 9.2, RFC 7714
/// section 10): 2^31.
pub const MAX_SRTCP_PACKETS_PER_KEY: u64 = 1 << 31;
/// The longest MKI a context accepts, in octets. RFC 3711 leaves the length to key management;
/// DTLS-SRTP (RFC 5764 section 4.1.3) and SDES (RFC 4568) carry at most 255 and 128.
pub const MAX_MKI_LEN: usize = 255;

/// The key derivation rate (RFC 3711 section 4.3.1): session keys are derived again each time
/// the packet index crosses a multiple of it. Zero, the default and what DTLS-SRTP fixes
/// (RFC 5764 section 4.1.2), derives them once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyDerivationRate(Option<u8>);

impl KeyDerivationRate {
    /// Session keys are derived once per master key.
    pub const ZERO: Self = Self(None);

    /// A rate of `rate` packets.
    ///
    /// # Errors
    ///
    /// RFC 3711 section 4.3.1 allows zero and the powers of two from 1 to 2^24; anything else
    /// is refused.
    pub fn new(rate: u64) -> Result<Self> {
        if rate == 0 {
            return Ok(Self::ZERO);
        }
        if !rate.is_power_of_two() || rate > (1 << 24) {
            return Err(Error::Other(format!(
                "SRTP key derivation rate {rate} is not zero or a power of two up to 2^24"
            )));
        }
        Ok(Self(Some(rate.trailing_zeros() as u8)))
    }

    /// The rate in packets; zero when session keys are derived once.
    pub fn get(self) -> u64 {
        self.0.map_or(0, |shift| 1 << shift)
    }

    /// Whether session keys are derived once per master key.
    pub fn is_zero(self) -> bool {
        self.0.is_none()
    }

    /// `index DIV key_derivation_rate`, zero for a zero rate.
    pub(crate) fn epoch(self, index: u64) -> u64 {
        self.0.map_or(0, |shift| index >> shift)
    }
}

/// How a context is keyed beyond its first master key and salt; see
/// [`Context::with_keying`](crate::context::Context::with_keying). Both are fixed for the
/// context's lifetime (RFC 3711 sections 3.2.1 and 4.3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keying {
    /// The key derivation rate, the same for every master key of the context.
    pub key_derivation_rate: KeyDerivationRate,
    /// The MKI of the first master key. `Some` puts an MKI of this length in every SRTP and
    /// SRTCP packet, and lets further master keys be added under MKIs of the same length;
    /// `None` uses no MKI field.
    pub mki: Option<Vec<u8>>,
}

/// How many packets one master key may protect before the context refuses to use it.
///
/// The default is the profile's
/// ([`ProtectionProfile::default_key_lifetime`](crate::protection_profile::ProtectionProfile::default_key_lifetime)).
/// Key management may agree on less (RFC 5764 section 4.1.2 gives every DTLS-SRTP profile a
/// maximum lifetime of 2^31 packets); it can never be more than
/// [`MAX_SRTP_PACKETS_PER_KEY`] and [`MAX_SRTCP_PACKETS_PER_KEY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLifetime {
    /// SRTP packets per master key.
    pub srtp_packets: u64,
    /// SRTCP packets per master key.
    pub srtcp_packets: u64,
}

/// Checks a key lifetime as [`Context::set_key_lifetime`](crate::context::Context::set_key_lifetime)
/// does: at least one packet, at most 2^48 SRTP and 2^31 SRTCP (RFC 3711 section 9.2).
///
/// # Errors
///
/// For a lifetime outside those bounds.
pub fn validate_key_lifetime(lifetime: KeyLifetime) -> shared::error::Result<()> {
    lifetime.validate()
}

impl KeyLifetime {
    /// The longest lifetime RFC 3711 allows: 2^48 SRTP and 2^31 SRTCP packets.
    pub const MAX: Self = Self {
        srtp_packets: MAX_SRTP_PACKETS_PER_KEY,
        srtcp_packets: MAX_SRTCP_PACKETS_PER_KEY,
    };

    pub(crate) fn validate(self) -> Result<()> {
        if self.srtp_packets == 0
            || self.srtcp_packets == 0
            || self.srtp_packets > MAX_SRTP_PACKETS_PER_KEY
            || self.srtcp_packets > MAX_SRTCP_PACKETS_PER_KEY
        {
            return Err(Error::Other(format!(
                "SRTP key lifetime {self:?} is outside 1..=2^48 SRTP and 1..=2^31 SRTCP packets"
            )));
        }
        Ok(())
    }

    pub(crate) fn limit(self, kind: PacketKind) -> u64 {
        match kind {
            PacketKind::Rtp => self.srtp_packets,
            PacketKind::Rtcp => self.srtcp_packets,
        }
    }
}

/// Which of a master key's two packet counts something is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketKind {
    /// SRTP packets.
    Rtp,
    /// SRTCP packets.
    Rtcp,
}

/// How much of a master key's lifetime is used; see
/// [`Context::key_usage`](crate::context::Context::key_usage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage {
    /// SRTP packets processed with the key (protected, or authenticated on reception).
    pub srtp_packets: u64,
    /// SRTCP packets processed with the key.
    pub srtcp_packets: u64,
    /// The lifetime the counts are held against.
    pub lifetime: KeyLifetime,
}

/// What a context reports to the application; read with
/// [`Context::poll_event`](crate::context::Context::poll_event).
///
/// Each event is raised once per master key and packet kind (the Cryptex one once per change
/// of the Cryptex settings), so a context never queues more than a few of them per key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextEvent {
    /// A master key has used fifteen sixteenths of its lifetime: key management should provide a
    /// new one now (RFC 3711 sections 3.3.1 and 9.2: re-keying is triggered before the limit).
    /// With DTLS-SRTP that is a new handshake; with an MKI, [`add_master_key`] and
    /// [`set_sending_mki`].
    ///
    /// [`add_master_key`]: crate::context::Context::add_master_key
    /// [`set_sending_mki`]: crate::context::Context::set_sending_mki
    KeyLifetimeExpiring {
        /// The key's MKI; empty when the context uses none.
        mki: Vec<u8>,
        /// Whether it is the SRTP or the SRTCP count that runs out.
        kind: PacketKind,
        /// How many more packets of that kind the key may protect.
        remaining: u64,
    },
    /// A master key reached its lifetime and a packet was refused with
    /// [`Error::ErrExceededMaxPackets`]. Nothing more is protected or accepted with that key:
    /// re-key, or end the session (RFC 3711 section 9.2).
    KeyExhausted {
        /// The key's MKI; empty when the context uses none.
        mki: Vec<u8>,
        /// Whether it is the SRTP or the SRTCP count that ran out.
        kind: PacketKind,
    },
    /// Cryptex is required and the peer sent an authentic packet whose CSRCs or header
    /// extensions were not protected with it (RFC 9335 section 5.2). The packet was discarded.
    CryptexRequiredViolation {
        /// The stream the packet belongs to.
        ssrc: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3711 section 4.3.1: the rate is zero or a power of two in 1..=2^24.
    #[test]
    fn key_derivation_rate_accepts_only_the_rates_the_rfc_allows() {
        assert_eq!(KeyDerivationRate::new(0).unwrap(), KeyDerivationRate::ZERO);
        assert!(KeyDerivationRate::ZERO.is_zero());
        for shift in 0..=24 {
            let rate = KeyDerivationRate::new(1 << shift).unwrap();
            assert_eq!(rate.get(), 1 << shift);
            assert_eq!(rate.epoch(5 << shift), 5);
            assert_eq!(rate.epoch((5 << shift) - 1), 4);
        }
        for bad in [3, 6, 1000, 1 << 25, u64::MAX] {
            assert!(KeyDerivationRate::new(bad).is_err(), "{bad}");
        }
        assert_eq!(KeyDerivationRate::ZERO.epoch(u64::MAX), 0);
    }

    /// RFC 3711 section 9.2: a lifetime never exceeds 2^48 SRTP or 2^31 SRTCP packets.
    #[test]
    fn key_lifetime_is_bounded_by_the_rfc_maximum() {
        KeyLifetime::MAX.validate().unwrap();
        for bad in [
            KeyLifetime {
                srtp_packets: MAX_SRTP_PACKETS_PER_KEY + 1,
                ..KeyLifetime::MAX
            },
            KeyLifetime {
                srtcp_packets: MAX_SRTCP_PACKETS_PER_KEY + 1,
                ..KeyLifetime::MAX
            },
            KeyLifetime {
                srtp_packets: 0,
                ..KeyLifetime::MAX
            },
            KeyLifetime {
                srtcp_packets: 0,
                ..KeyLifetime::MAX
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }
}
