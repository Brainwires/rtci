//! W3C webrtc-encoded-transform section 3, the SFrame transforms: `RTCRtpSFrameEncryptor` and
//! `RTCRtpSFrameDecryptor` (and, being the same objects without an owner, `SFrameEncryptorStream`
//! and `SFrameDecryptorStream`), over [`rtc::sframe`](crate::sframe).
//!
//! The engine has no encoder or decoder, so the frames are the application's: a sender's
//! application runs [`RTCRtpSFrameEncryptor::transform`] on each encoded frame and sends the
//! result with the SFrame payload format (`rtc::rtp::codec::sframe::SFramePayloader`), a
//! receiver's application reassembles (`SFrameReassembler`) and runs
//! [`RTCRtpSFrameDecryptor::transform`]. Setting such a transform on a sender or a receiver is
//! [`RTCRtpTransceiver::set_transform_use_sframe`](crate::rtp_transceiver::RTCRtpTransceiver::set_transform_use_sframe)
//! `(true)`: `[[useSFrame]]` (the constructors' "Set this.\[\[useSFrame\]\] to true").

use crate::sframe::{CipherSuite, ErrorKind, SFrameContext};
use shared::error::{Error, Result};

/// `SFrameType`: how a sender's SFrame ciphertext is carried (draft-ietf-avtcore-rtp-sframe:
/// one SFrame per media frame, or one per RTP packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RTCSFrameType {
    /// "per-frame", the default.
    #[default]
    PerFrame,
    /// "per-packet".
    PerPacket,
}

/// `SFrameTransformErrorEventType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RTCSFrameTransformErrorType {
    /// "authentication": the authentication tag did not validate.
    Authentication,
    /// "keyID": no decryption key for the frame's key id.
    KeyId,
    /// "syntax": the data does not follow the SFrame format.
    Syntax,
}

/// `SFrameTransformErrorEvent`: why a frame could not be decrypted, with the key id when the
/// header named one. The frame is the one the application passed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RTCSFrameTransformError {
    /// `errorType`.
    pub error_type: RTCSFrameTransformErrorType,
    /// `keyID`.
    pub key_id: Option<u64>,
}

fn sframe_error(error: crate::sframe::Error) -> Error {
    Error::Other(format!("sframe: {error}"))
}

/// `RTCRtpSFrameEncryptor` (and `SFrameEncryptorStream`): SFrame-encrypts the frames of a
/// sender with the cipher suite of its options and the key `setEncryptionKey` set.
pub struct RTCRtpSFrameEncryptor {
    context: SFrameContext,
    sframe_type: RTCSFrameType,
    key_id: Option<u64>,
}

impl RTCRtpSFrameEncryptor {
    /// `new RTCRtpSFrameEncryptor(options)`: the SFrame initialization algorithm with
    /// `cipherSuite` and `type`.
    ///
    /// # Errors
    ///
    /// When the default crypto provider is missing or cannot do `cipher_suite`.
    pub fn new(cipher_suite: CipherSuite, sframe_type: RTCSFrameType) -> Result<Self> {
        Ok(Self {
            context: SFrameContext::with_default_provider(cipher_suite).map_err(sframe_error)?,
            sframe_type,
            key_id: None,
        })
    }

    /// `[[cipherSuite]]`.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.context.cipher_suite()
    }

    /// The `type` of the options: per-frame or per-packet sending.
    pub fn sframe_type(&self) -> RTCSFrameType {
        self.sframe_type
    }

    /// `setEncryptionKey(key, keyId)`: frames are encrypted with `key` under `key_id` from now
    /// on (RFC 9605 section 4.4: the base key, from which the SFrame key and salt derive).
    ///
    /// # Errors
    ///
    /// An empty key, or a key id that was used for sending before (a new key needs a new
    /// id: reusing one would repeat nonces, RFC 9605 section 9.1).
    pub fn set_encryption_key(&mut self, key: &[u8], key_id: u64) -> Result<()> {
        self.context
            .add_send_key(key_id, key)
            .map_err(sframe_error)?;
        if let Some(previous) = self.key_id.replace(key_id)
            && previous != key_id
        {
            self.context.remove_key(previous);
        }
        Ok(())
    }

    /// The SFrame transform algorithm for the "encrypt" role: `frame` (an encoded frame's
    /// data, or the payload of one packet for per-packet sending) as an SFrame ciphertext.
    ///
    /// # Errors
    ///
    /// `InvalidStateError` before `setEncryptionKey`; a key whose counter is exhausted.
    pub fn transform(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let key_id = self.key_id.ok_or(Error::InvalidStateError)?;
        self.context
            .encrypt(key_id, b"", frame)
            .map_err(sframe_error)
    }
}

/// `RTCRtpSFrameDecryptor` (and `SFrameDecryptorStream`): decrypts a receiver's SFrame
/// ciphertexts with the keys `addDecryptionKey` added.
pub struct RTCRtpSFrameDecryptor {
    context: SFrameContext,
}

impl RTCRtpSFrameDecryptor {
    /// `new RTCRtpSFrameDecryptor(options)`.
    ///
    /// # Errors
    ///
    /// When the default crypto provider is missing or cannot do `cipher_suite`.
    pub fn new(cipher_suite: CipherSuite) -> Result<Self> {
        Ok(Self {
            context: SFrameContext::with_default_provider(cipher_suite).map_err(sframe_error)?,
        })
    }

    /// `[[cipherSuite]]`.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.context.cipher_suite()
    }

    /// `addDecryptionKey(key, keyId)`.
    ///
    /// # Errors
    ///
    /// An empty key, or a key id already used for sending in this context.
    pub fn add_decryption_key(&mut self, key: &[u8], key_id: u64) -> Result<()> {
        self.context.add_recv_key(key_id, key).map_err(sframe_error)
    }

    /// `removeDecryptionKey(keyId)`: frames under `key_id` no longer decrypt. Whether there
    /// was such a key.
    pub fn remove_decryption_key(&mut self, key_id: u64) -> bool {
        self.context.remove_key(key_id)
    }

    /// The SFrame transform algorithm for the "decrypt" role: the plaintext of `frame`, or
    /// the `error` event the spec fires for it (`authentication`, `keyID` or `syntax`). A frame
    /// that fails otherwise (a replayed counter) is dropped with no event: `None` in both.
    pub fn transform(
        &mut self,
        frame: &[u8],
    ) -> std::result::Result<Vec<u8>, Option<RTCSFrameTransformError>> {
        self.context.decrypt(b"", frame).map_err(|error| {
            error.kind().map(|kind| RTCSFrameTransformError {
                error_type: match kind {
                    ErrorKind::Authentication => RTCSFrameTransformErrorType::Authentication,
                    ErrorKind::KeyId => RTCSFrameTransformErrorType::KeyId,
                    ErrorKind::Syntax => RTCSFrameTransformErrorType::Syntax,
                },
                key_id: error.key_id(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// webrtc-encoded-transform 3: an encryptor and a decryptor of one cipher suite round-trip
    /// a frame under the key id the encryptor was given; the decryptor reports `keyID` for an
    /// unknown key (with the id), `authentication` for a tampered frame and `syntax` for data
    /// that is not SFrame; a removed key no longer decrypts; no key, no encryption.
    #[test]
    fn sframe_transforms_encrypt_decrypt_and_report_the_three_errors() -> Result<()> {
        let suite = CipherSuite::Aes128GcmSha256_128;
        let mut encryptor = RTCRtpSFrameEncryptor::new(suite, RTCSFrameType::default())?;
        assert_eq!(encryptor.sframe_type(), RTCSFrameType::PerFrame);
        assert!(matches!(
            encryptor.transform(b"frame"),
            Err(Error::InvalidStateError)
        ));
        encryptor.set_encryption_key(&[7u8; 16], 3)?;
        let ciphertext = encryptor.transform(b"an encoded frame")?;
        assert_ne!(ciphertext, b"an encoded frame".to_vec());

        let mut decryptor = RTCRtpSFrameDecryptor::new(suite)?;
        assert_eq!(
            decryptor.transform(&ciphertext),
            Err(Some(RTCSFrameTransformError {
                error_type: RTCSFrameTransformErrorType::KeyId,
                key_id: Some(3),
            }))
        );
        decryptor.add_decryption_key(&[7u8; 16], 3)?;
        assert_eq!(
            decryptor.transform(&ciphertext),
            Ok(b"an encoded frame".to_vec())
        );

        let mut tampered = encryptor.transform(b"another frame")?;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            decryptor
                .transform(&tampered)
                .map_err(|e| e.map(|e| e.error_type)),
            Err(Some(RTCSFrameTransformErrorType::Authentication))
        );
        assert_eq!(
            decryptor
                .transform(&[])
                .map_err(|e| e.map(|e| e.error_type)),
            Err(Some(RTCSFrameTransformErrorType::Syntax))
        );

        assert!(decryptor.remove_decryption_key(3));
        let next = encryptor.transform(b"a third frame")?;
        assert_eq!(
            decryptor
                .transform(&next)
                .map_err(|e| e.map(|e| e.error_type)),
            Err(Some(RTCSFrameTransformErrorType::KeyId))
        );

        // A new key under a new id: frames go under it.
        encryptor.set_encryption_key(&[9u8; 16], 4)?;
        decryptor.add_decryption_key(&[9u8; 16], 4)?;
        let rekeyed = encryptor.transform(b"after the new key")?;
        assert_eq!(
            decryptor.transform(&rekeyed),
            Ok(b"after the new key".to_vec())
        );
        Ok(())
    }
}
