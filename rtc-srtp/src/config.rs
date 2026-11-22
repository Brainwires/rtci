use crate::{option::*, protection_profile::*};
use shared::error::{Error, Result};

/// RFC 5764 exporter label used to derive SRTP master keys and salts from DTLS.
pub const LABEL_EXTRACTOR_DTLS_SRTP: &str = "EXTRACTOR-dtls_srtp";

/// SessionKeys bundles the keys required to setup an SRTP session
///
/// The keys and salts are zeroized when the value is dropped, and `Debug` prints their lengths
/// only (RFC 3711 section 3.2.1: master keys are kept secret; RFC 7714 section 13.1: keys and
/// salts are erased when no longer needed).
#[derive(Default, Clone)]
pub struct SessionKeys {
    /// The master key used to protect outbound packets.
    pub local_master_key: Vec<u8>,
    /// The master salt used to protect outbound packets.
    pub local_master_salt: Vec<u8>,
    /// The master key used to unprotect inbound packets.
    pub remote_master_key: Vec<u8>,
    /// The master salt used to unprotect inbound packets.
    pub remote_master_salt: Vec<u8>,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field(
                "local_master_key",
                &format_args!("[REDACTED; {}]", self.local_master_key.len()),
            )
            .field(
                "local_master_salt",
                &format_args!("[REDACTED; {}]", self.local_master_salt.len()),
            )
            .field(
                "remote_master_key",
                &format_args!("[REDACTED; {}]", self.remote_master_key.len()),
            )
            .field(
                "remote_master_salt",
                &format_args!("[REDACTED; {}]", self.remote_master_salt.len()),
            )
            .finish()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        for secret in [
            &mut self.local_master_key,
            &mut self.local_master_salt,
            &mut self.remote_master_key,
            &mut self.remote_master_salt,
        ] {
            // `SecretVec` zeroizes the allocation it is handed when it drops.
            drop(crypto::SecretVec::new(std::mem::take(secret)));
        }
    }
}

/// Config is used to configure a session.
/// The top-level integration exports keying material from DTLS and installs it here, or callers
/// can directly pass the keys themselves.
/// After a Config is passed to a session it must not be modified.
#[derive(Default)]
pub struct Config {
    /// The master keys and salts for both directions.
    pub keys: SessionKeys,
    /// The negotiated protection profile, which fixes the cipher and tag lengths.
    pub profile: ProtectionProfile,
    //LoggerFactory: logging.LoggerFactory
    /// List of local/remote context options.
    /// Replay protection is on by default, for every context: one created with `None` uses a
    /// window of [`DEFAULT_REPLAY_PROTECTION_WINDOW`] (64) packets. A context only checks for
    /// replays when it unprotects, so the local options matter only to a context used that way.
    pub local_rtp_options: Option<ContextOption>,
    /// Replay-protection options for the inbound RTP context. Enabled by default.
    pub remote_rtp_options: Option<ContextOption>,

    /// Replay-protection options for the outbound RTCP context.
    pub local_rtcp_options: Option<ContextOption>,
    /// Replay-protection options for the inbound RTCP context. Enabled by default.
    pub remote_rtcp_options: Option<ContextOption>,
}

impl Config {
    /// Returns the exact number of DTLS exporter bytes required by this profile.
    #[must_use]
    pub fn keying_material_len(&self) -> usize {
        let key_len = self.profile.key_len();
        let salt_len = self.profile.salt_len();
        (key_len * 2) + (salt_len * 2)
    }

    /// Splits DTLS-SRTP exporter output into local and remote master keys and salts according to
    /// RFC 5764.
    ///
    /// # Errors
    ///
    /// Returns an error unless `keying_material` has exactly [`Self::keying_material_len`] bytes.
    pub fn set_session_keys_from_keying_material(
        &mut self,
        keying_material: &[u8],
        is_client: bool,
    ) -> Result<()> {
        let expected = self.keying_material_len();
        if keying_material.len() != expected {
            return Err(Error::Other(format!(
                "invalid DTLS-SRTP keying material length: expected {expected}, got {}",
                keying_material.len()
            )));
        }

        let key_len = self.profile.key_len();
        let salt_len = self.profile.salt_len();

        let (client_write_key, rest) = keying_material.split_at(key_len);
        let (server_write_key, rest) = rest.split_at(key_len);
        let (client_write_salt, server_write_salt) = rest.split_at(salt_len);

        let (local_key, local_salt, remote_key, remote_salt) = if is_client {
            (
                client_write_key,
                client_write_salt,
                server_write_key,
                server_write_salt,
            )
        } else {
            (
                server_write_key,
                server_write_salt,
                client_write_key,
                client_write_salt,
            )
        };
        // Dropping the previous keys zeroizes them.
        self.keys = SessionKeys {
            local_master_key: local_key.to_vec(),
            local_master_salt: local_salt.to_vec(),
            remote_master_key: remote_key.to_vec(),
            remote_master_salt: remote_salt.to_vec(),
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material(len: usize) -> Vec<u8> {
        (0..len).map(|value| value as u8).collect()
    }

    #[test]
    fn rejects_keying_material_with_the_wrong_length() {
        let mut config = Config {
            profile: ProtectionProfile::Aes128CmHmacSha1_80,
            ..Default::default()
        };
        let expected = config.keying_material_len();

        for actual in [expected - 1, expected + 1] {
            let error = config
                .set_session_keys_from_keying_material(&material(actual), true)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("expected {expected}, got {actual}"))
            );
        }
    }

    /// RFC 3711 section 3.2.1, RFC 7714 section 13.1: key bytes never reach a log through
    /// `Debug`.
    #[test]
    fn session_keys_debug_output_holds_no_key_bytes() {
        let mut config = Config {
            profile: ProtectionProfile::Aes128CmHmacSha1_80,
            ..Default::default()
        };
        let bytes: Vec<u8> = (0..config.keying_material_len())
            .map(|value| 0xA0 + value as u8)
            .collect();
        config
            .set_session_keys_from_keying_material(&bytes, true)
            .unwrap();
        assert_eq!(
            format!("{:?}", config.keys),
            "SessionKeys { local_master_key: [REDACTED; 16], local_master_salt: [REDACTED; 14], \
             remote_master_key: [REDACTED; 16], remote_master_salt: [REDACTED; 14] }"
        );
    }

    #[test]
    fn assigns_client_and_server_material_by_role() -> Result<()> {
        let mut client = Config {
            profile: ProtectionProfile::Aes128CmHmacSha1_80,
            ..Default::default()
        };
        let bytes = material(client.keying_material_len());
        client.set_session_keys_from_keying_material(&bytes, true)?;

        let mut server = Config {
            profile: client.profile,
            ..Default::default()
        };
        server.set_session_keys_from_keying_material(&bytes, false)?;

        assert_eq!(client.keys.local_master_key, server.keys.remote_master_key);
        assert_eq!(
            client.keys.local_master_salt,
            server.keys.remote_master_salt
        );
        assert_eq!(client.keys.remote_master_key, server.keys.local_master_key);
        assert_eq!(
            client.keys.remote_master_salt,
            server.keys.local_master_salt
        );
        Ok(())
    }
}
