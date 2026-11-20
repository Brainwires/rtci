//! `CipherAeadAesGcm::new` refuses what it cannot build instead of panicking.

use super::cipher_aead_aes_gcm::CipherAeadAesGcm;
use crate::protection_profile::ProtectionProfile;
use shared::error::Error;

#[test]
fn test_aead_cipher_refuses_a_non_gcm_profile() {
    let provider = crypto::default_provider().unwrap();
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let result = CipherAeadAesGcm::new(
        profile,
        &vec![0u8; profile.key_len()],
        &vec![0u8; profile.salt_len()],
        provider.crypto(),
    );
    assert!(matches!(result, Err(Error::ErrNoSuchSrtpProfile)));
}

#[test]
fn test_aead_cipher_refuses_a_wrong_salt_length() {
    let provider = crypto::default_provider().unwrap();
    let profile = ProtectionProfile::AeadAes128Gcm;
    let result = CipherAeadAesGcm::new(
        profile,
        &vec![0u8; profile.key_len()],
        &[0u8; 14],
        provider.crypto(),
    );
    assert!(matches!(result, Err(Error::SrtpSaltLength(12, 14))));
}
