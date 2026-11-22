//! DTLS 1.3 (RFC 9147, on the TLS 1.3 handshake of RFC 8446).
//!
//! An association starts in the DTLS 1.2 code, which the first flight shares: the
//! ClientHello and the HelloRetryRequest or ServerHello that answers it travel in the same
//! plaintext records as before. Once `supported_versions` has selected DTLS 1.3 the
//! association is run from here: its own record layer ([`record`]), key schedule
//! ([`key_schedule`]) and handshake.

pub(crate) mod codec;
pub(crate) mod conn;
#[cfg(any(fuzzing, test))]
pub(crate) mod fuzz_harness;
pub(crate) mod handshake;
pub(crate) mod hello;
pub(crate) mod key_schedule;
pub(crate) mod messages;
pub(crate) mod psk;
pub(crate) mod record;
pub(crate) mod suite;

#[cfg(test)]
mod connection_id_test;
#[cfg(test)]
mod early_data_test;
#[cfg(test)]
mod fuzz_corpus_test;
#[cfg(test)]
pub(crate) mod handshake_test;
#[cfg(test)]
mod hello_loss_test;
#[cfg(test)]
mod key_schedule_test;
#[cfg(test)]
mod openssl_kat_test;
#[cfg(test)]
mod openssl_recordings;
#[cfg(test)]
mod post_handshake_auth_test;
#[cfg(test)]
mod psk_test;
#[cfg(test)]
mod record_test;
#[cfg(test)]
mod reliability_test;

/// DTLS 1.3 on the wire, in `supported_versions` (RFC 9147 section 5.3).
pub(crate) const DTLS1_3_WIRE_VERSION: u16 = 0xfefc;
/// DTLS 1.2 on the wire.
pub(crate) const DTLS1_2_WIRE_VERSION: u16 = 0xfefd;
