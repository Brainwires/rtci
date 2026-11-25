#[cfg(feature = "crypto-aws-lc-rs")]
mod aws_lc_rs;
#[cfg(feature = "crypto-ring")]
mod ring;

#[cfg(feature = "crypto-aws-lc-rs")]
pub use aws_lc_rs::{AwsLcRsCrypto, AwsLcRsProvider, AwsLcRsRandom};
#[cfg(all(feature = "crypto-ring", feature = "test-support"))]
#[doc(hidden)]
pub use ring::ring_key_exchange_with_seed;
#[cfg(feature = "crypto-ring")]
pub use ring::{RingCrypto, RingProvider, RingRandom};
