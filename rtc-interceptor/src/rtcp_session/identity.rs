//! The identity an endpoint has in RTCP: its CNAME (RFC 7022) and the SSRC it reports from
//! when it sends no media (RFC 3550 8.1), and where the randomness for both comes from.

/// The source of the random numbers the RTCP session uses: the variation of the report
/// interval (RFC 3550 6.3.1), the dither of early feedback (RFC 4585 3.5.2), a reporting SSRC
/// (RFC 3550 8.1) and the CNAME (RFC 7022 section 5).
///
/// The default draws from the operating system's CSPRNG through `rand`. A test supplies its
/// own for a run that repeats exactly.
pub trait RtcpRandom: Send + Sync {
    /// 32 random bits.
    fn next_u32(&mut self) -> u32;

    /// A number uniformly distributed in [0, 1).
    fn unit(&mut self) -> f64 {
        f64::from(self.next_u32()) / 4_294_967_296.0
    }
}

/// [`RtcpRandom`] from the thread's cryptographically secure generator.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ThreadRandom;

impl RtcpRandom for ThreadRandom {
    fn next_u32(&mut self) -> u32 {
        rand::random::<u32>()
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A short-term persistent RTCP CNAME as RFC 7022 section 4.2 defines it: 96 random bits
/// (section 5 asks for at least that many, from a cryptographic generator), Base64 encoded
/// into 16 characters, with no "user@" part and nothing that identifies the host or the user.
pub(crate) fn generate_cname(random: &mut dyn RtcpRandom) -> String {
    let mut octets = [0u8; 12];
    for chunk in octets.chunks_mut(4) {
        chunk.copy_from_slice(&random.next_u32().to_be_bytes());
    }
    let mut cname = String::with_capacity(16);
    for triple in octets.chunks(3) {
        let bits = u32::from(triple[0]) << 16 | u32::from(triple[1]) << 8 | u32::from(triple[2]);
        for shift in [18, 12, 6, 0] {
            cname.push(char::from(BASE64[((bits >> shift) & 0x3F) as usize]));
        }
    }
    cname
}

/// A new RTCP CNAME for an endpoint, as RFC 7022 section 4.2 defines a short-term persistent
/// one: 96 bits from the operating system's CSPRNG, Base64 encoded (16 characters). RFC 8834
/// 4.9 asks for one per `RTCPeerConnection`, used by every SSRC it sends from.
pub fn generate_rtcp_cname() -> String {
    generate_cname(&mut ThreadRandom)
}

/// A new SSRC for this endpoint (RFC 3550 8.1): random, never zero, and not one `in_use`
/// reports as taken by a source already in the session.
pub(crate) fn choose_ssrc(random: &mut dyn RtcpRandom, in_use: impl Fn(u32) -> bool) -> u32 {
    loop {
        let candidate = random.next_u32();
        if candidate != 0 && !in_use(candidate) {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(u32);

    impl RtcpRandom for Counter {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_add(1);
            self.0
        }
    }

    /// RFC 7022 4.2: "at least the low 96 bits ... MUST be Base64 encoded" (16 characters).
    #[test]
    fn a_cname_is_96_random_bits_in_base64() {
        let cname = generate_cname(&mut ThreadRandom);
        assert_eq!(16, cname.len());
        assert!(
            cname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        );
        assert!(!cname.contains('@'));

        // RFC 4648 section 10: BASE64("foobar") = "Zm9vYmFy"; twelve octets of it twice over.
        struct Foobar(u32);
        impl RtcpRandom for Foobar {
            fn next_u32(&mut self) -> u32 {
                let words = [
                    u32::from_be_bytes(*b"foob"),
                    u32::from_be_bytes(*b"arfo"),
                    u32::from_be_bytes(*b"obar"),
                ];
                self.0 += 1;
                words[(self.0 as usize - 1) % 3]
            }
        }
        assert_eq!("Zm9vYmFyZm9vYmFy", generate_cname(&mut Foobar(0)));
    }

    /// RFC 7022 section 5: random, so two endpoints (and two sessions) do not share one.
    #[test]
    fn two_cnames_differ() {
        assert_ne!(
            generate_cname(&mut ThreadRandom),
            generate_cname(&mut ThreadRandom)
        );
    }

    /// RFC 3550 8.1: a candidate already in use is drawn again; zero is never chosen.
    #[test]
    fn a_chosen_ssrc_is_not_zero_and_not_in_use() {
        // The counter yields 1, 2, 3, ...: 1 and 2 are taken.
        assert_eq!(3, choose_ssrc(&mut Counter(0), |ssrc| ssrc < 3));
        // It yields 0 first here.
        assert_eq!(1, choose_ssrc(&mut Counter(u32::MAX), |_| false));
    }

    #[test]
    fn unit_is_in_the_half_open_interval() {
        struct Fixed(u32);
        impl RtcpRandom for Fixed {
            fn next_u32(&mut self) -> u32 {
                self.0
            }
        }
        assert_eq!(0.0, Fixed(0).unit());
        assert!(Fixed(u32::MAX).unit() < 1.0);
        assert_eq!(0.5, Fixed(1 << 31).unit());
    }
}
