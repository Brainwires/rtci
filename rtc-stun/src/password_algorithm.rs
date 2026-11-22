//! `PASSWORD-ALGORITHM` and `PASSWORD-ALGORITHMS` (RFC 8489 sections 14.11 and 14.12): the
//! algorithm that turns a long-term password into the HMAC key, and the list a server offers.

use crate::attributes::*;
use crate::message::*;
use shared::error::*;

use std::fmt;

/// MD5, the key of RFC 5389 (RFC 8489 section 18.5.1.1): for legacy systems only.
pub const PASSWORD_ALGORITHM_MD5: u16 = 0x0001;
/// SHA-256 (RFC 8489 section 18.5.1.2).
pub const PASSWORD_ALGORITHM_SHA256: u16 = 0x0002;

/// One entry of the STUN Password Algorithms registry with its parameters: the value of
/// `PASSWORD-ALGORITHM`, and an element of `PASSWORD-ALGORITHMS`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordAlgorithm {
    /// The algorithm number ([`PASSWORD_ALGORITHM_MD5`], [`PASSWORD_ALGORITHM_SHA256`]).
    pub algorithm: u16,
    /// The algorithm's parameters; empty for MD5 and SHA-256.
    pub parameters: Vec<u8>,
}

impl PasswordAlgorithm {
    /// An algorithm without parameters.
    #[must_use]
    pub const fn new(algorithm: u16) -> Self {
        Self {
            algorithm,
            parameters: Vec::new(),
        }
    }

    /// Appends the algorithm number, the parameters' length and the parameters, zero-padded to
    /// a 32-bit boundary.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let length =
            u16::try_from(self.parameters.len()).map_err(|_| Error::ErrAttributeSizeOverflow)?;
        out.extend_from_slice(&self.algorithm.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.parameters);
        out.resize(
            out.len() + nearest_padded_value_length(self.parameters.len()) - self.parameters.len(),
            0,
        );
        Ok(())
    }

    /// Reads one algorithm from the front of `v`; returns it and the bytes it took, padding
    /// included. The padding's content is ignored, and the last algorithm of a value may come
    /// without it.
    fn decode(v: &[u8]) -> Result<(Self, usize)> {
        if v.len() < 4 {
            return Err(Error::ErrUnexpectedEof);
        }
        let algorithm = u16::from_be_bytes([v[0], v[1]]);
        let length = usize::from(u16::from_be_bytes([v[2], v[3]]));
        let parameters = v.get(4..4 + length).ok_or(Error::ErrUnexpectedEof)?;
        let taken = (4 + nearest_padded_value_length(length)).min(v.len());
        Ok((
            Self {
                algorithm,
                parameters: parameters.to_vec(),
            },
            taken,
        ))
    }
}

impl fmt::Display for PasswordAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.algorithm {
            PASSWORD_ALGORITHM_MD5 => write!(f, "MD5"),
            PASSWORD_ALGORITHM_SHA256 => write!(f, "SHA-256"),
            other => write!(f, "{other:#06x}"),
        }
    }
}

impl Setter for PasswordAlgorithm {
    /// Adds PASSWORD-ALGORITHM to `m`.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        let mut value = Vec::with_capacity(4 + self.parameters.len());
        self.encode(&mut value)?;
        m.add(ATTR_PASSWORD_ALGORITHM, &value);
        Ok(())
    }
}

impl Getter for PasswordAlgorithm {
    /// Reads PASSWORD-ALGORITHM from `m`.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_PASSWORD_ALGORITHM)?;
        let (algorithm, taken) = Self::decode(&v)?;
        if taken != v.len() {
            return Err(Error::ErrAttributeSizeInvalid);
        }
        *self = algorithm;
        Ok(())
    }
}

/// The `PASSWORD-ALGORITHMS` attribute: the algorithms a server can derive the long-term key
/// with, in its order of preference.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordAlgorithms(pub Vec<PasswordAlgorithm>);

impl PasswordAlgorithms {
    /// The first algorithm of the list whose number is in `supported` (RFC 8489 section
    /// 9.2.5: "the first algorithm supported on the list"), with the parameters the server
    /// gave it.
    #[must_use]
    pub fn first_supported(&self, supported: &[u16]) -> Option<&PasswordAlgorithm> {
        self.0.iter().find(|a| supported.contains(&a.algorithm))
    }
}

impl Setter for PasswordAlgorithms {
    /// Adds PASSWORD-ALGORITHMS to `m`.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        let mut value = Vec::with_capacity(4 * self.0.len());
        for algorithm in &self.0 {
            algorithm.encode(&mut value)?;
        }
        m.add(ATTR_PASSWORD_ALGORITHMS, &value);
        Ok(())
    }
}

impl Getter for PasswordAlgorithms {
    /// Reads PASSWORD-ALGORITHMS from `m`.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_PASSWORD_ALGORITHMS)?;
        let mut algorithms = vec![];
        let mut rest = &v[..];
        while !rest.is_empty() {
            let (algorithm, taken) = PasswordAlgorithm::decode(rest)?;
            algorithms.push(algorithm);
            rest = &rest[taken..];
        }
        self.0 = algorithms;
        Ok(())
    }
}

#[cfg(test)]
mod password_algorithm_test {
    use super::*;

    fn message_with(t: AttrType, value: &[u8]) -> Message {
        let mut m = Message::new();
        m.write_header();
        m.add(t, value);
        m
    }

    /// RFC 8489 section 14.12, Figure 9: algorithm number, parameters length, parameters
    /// padded with zeros to a 32-bit boundary.
    #[test]
    fn test_password_algorithm_is_number_length_and_padded_parameters() -> Result<()> {
        let mut m = Message::new();
        m.write_header();
        PasswordAlgorithm::new(PASSWORD_ALGORITHM_SHA256).add_to(&mut m)?;
        assert_eq!(m.get(ATTR_PASSWORD_ALGORITHM)?, [0x00, 0x02, 0x00, 0x00]);

        let with_parameters = PasswordAlgorithm {
            algorithm: 0x8001,
            parameters: vec![1, 2, 3, 4, 5],
        };
        let mut m = Message::new();
        m.write_header();
        with_parameters.add_to(&mut m)?;
        assert_eq!(
            m.get(ATTR_PASSWORD_ALGORITHM)?,
            [0x80, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5, 0, 0, 0]
        );
        let mut got = PasswordAlgorithm::default();
        got.get_from(&m)?;
        assert_eq!(got, with_parameters);
        Ok(())
    }

    /// RFC 8489 section 14.12: the padding bits are ignored by the receiver.
    #[test]
    fn test_password_algorithm_padding_is_ignored_on_receipt() -> Result<()> {
        let m = message_with(
            ATTR_PASSWORD_ALGORITHM,
            &[0x80, 0x01, 0x00, 0x01, 9, 0xff, 0xff, 0xff],
        );
        let mut got = PasswordAlgorithm::default();
        got.get_from(&m)?;
        assert_eq!(got.algorithm, 0x8001);
        assert_eq!(got.parameters, [9]);
        Ok(())
    }

    /// RFC 8489 section 14.11, Figure 8: the list is the algorithms one after another, each
    /// padded.
    #[test]
    fn test_password_algorithms_is_a_list_in_the_servers_order() -> Result<()> {
        let list = PasswordAlgorithms(vec![
            PasswordAlgorithm {
                algorithm: 0x8001,
                parameters: vec![7, 7],
            },
            PasswordAlgorithm::new(PASSWORD_ALGORITHM_SHA256),
            PasswordAlgorithm::new(PASSWORD_ALGORITHM_MD5),
        ]);
        let mut m = Message::new();
        m.write_header();
        list.add_to(&mut m)?;
        assert_eq!(
            m.get(ATTR_PASSWORD_ALGORITHMS)?,
            [
                0x80, 0x01, 0x00, 0x02, 7, 7, 0, 0, // an algorithm with two parameter bytes
                0x00, 0x02, 0x00, 0x00, // SHA-256
                0x00, 0x01, 0x00, 0x00, // MD5
            ]
        );
        let mut got = PasswordAlgorithms::default();
        got.get_from(&m)?;
        assert_eq!(got, list);
        assert_eq!(
            got.first_supported(&[PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256]),
            Some(&PasswordAlgorithm::new(PASSWORD_ALGORITHM_SHA256)),
            "the first supported one in the server's order, not the client's"
        );
        assert_eq!(got.first_supported(&[0x7777]), None);
        Ok(())
    }

    /// A parameters length that runs past the value is not an algorithm.
    #[test]
    fn test_password_algorithm_with_truncated_parameters_is_refused() {
        for value in [&[0x00, 0x02][..], &[0x00, 0x02, 0x00, 0x08, 1, 2, 3, 4][..]] {
            let m = message_with(ATTR_PASSWORD_ALGORITHM, value);
            assert!(PasswordAlgorithm::default().get_from(&m).is_err());
            let m = message_with(ATTR_PASSWORD_ALGORITHMS, value);
            assert!(PasswordAlgorithms::default().get_from(&m).is_err());
        }
    }
}
