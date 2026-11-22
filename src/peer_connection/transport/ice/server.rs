use serde::{Deserialize, Serialize};

use shared::error::{Error, Result};

/// ICEServer describes a single STUN and TURN server that can be used by
/// the ICEAgent to establish a connection with a peer.
///
/// ## Specifications
///
/// * [W3C]
///
/// [W3C]: https://www.w3.org/TR/webrtc/#dom-rtciceserver
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Hash)]
#[serde(default)]
pub struct RTCIceServer {
    /// The URLs representing the STUN or TURN servers.
    pub urls: Vec<String>,
    /// The username to use when authenticating with a TURN server.
    pub username: String,
    /// The credential (password or token) to use when authenticating with a TURN server.
    pub credential: String,
}

impl RTCIceServer {
    pub(crate) fn parse_url(&self, url_str: &str) -> Result<ice::url::Url> {
        ice::url::Url::parse_url(url_str)
    }

    /// W3C "set a configuration", for one server: `urls` is not empty, and each url passes
    /// "validate an ICE server URL" (webrtc-pc section 4.4.1.5).
    ///
    /// # Errors
    ///
    /// The W3C `SyntaxError` cases: no url ([`Error::ErrNoIceServerUrls`]), a scheme other than
    /// `stun`, `stuns`, `turn` and `turns` ([`Error::ErrSchemeType`]), no opaque path, or one
    /// with `/` or `@`, or a fragment ([`Error::ErrInvalidUrl`]), a query on a STUN url
    /// ([`Error::ErrStunQuery`]) or one other than `transport=udp` / `transport=tcp` on a TURN
    /// url ([`Error::ErrInvalidQuery`]), and a host and port that do not parse. The
    /// `InvalidAccessError` cases: a TURN url without a username or credential
    /// ([`Error::ErrNoTurnCredentials`]), or with a username of 509 bytes or more (RFC 8489
    /// section 14.3) or a credential that is not an RFC 8265 OpaqueString
    /// ([`Error::InvalidAccessError`]).
    pub(crate) fn validate(&self) -> Result<()> {
        if self.urls.is_empty() {
            return Err(Error::ErrNoIceServerUrls);
        }
        for url in &self.urls {
            self.validate_url(url)?;
        }
        self.urls()?;
        Ok(())
    }

    /// The textual checks of W3C "validate an ICE server URL" that the URL parser of the ICE
    /// agent does not make.
    fn validate_url(&self, url: &str) -> Result<()> {
        let Some((scheme, opaque_path)) = url.split_once(':') else {
            return Err(Error::ErrSchemeType);
        };
        let scheme = scheme.to_ascii_lowercase();
        let turn = match scheme.as_str() {
            "stun" | "stuns" => false,
            "turn" | "turns" => true,
            _ => return Err(Error::ErrSchemeType),
        };
        // An opaque path: not empty, not starting with `/` (that is a hierarchical URL), and
        // with neither `/` nor `@` in it; and no fragment.
        let (path, query) = match opaque_path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (opaque_path, None),
        };
        if path.is_empty() || path.contains(['/', '@']) || url.contains('#') {
            return Err(Error::ErrInvalidUrl);
        }
        match query {
            Some(_) if !turn => return Err(Error::ErrStunQuery),
            Some(query) if query != "transport=udp" && query != "transport=tcp" => {
                return Err(Error::ErrInvalidQuery);
            }
            _ => {}
        }
        if turn {
            if self.username.is_empty() || self.credential.is_empty() {
                return Err(Error::ErrNoTurnCredentials);
            }
            // RFC 8489 section 14.3: "fewer than 509 bytes". RFC 8265 section 4.1: an
            // OpaqueString has at least one character and no control character.
            if self.username.len() >= 509 || self.credential.chars().any(char::is_control) {
                return Err(Error::InvalidAccessError);
            }
        }
        Ok(())
    }

    /// Parses and returns the parsed ICE URLs, validating TURN credentials if necessary.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any entry in `urls` is not a well-formed STUN/TURN URL
    /// - A `turn:` or `turns:` URL is present but `username` or `credential` is empty
    ///   (`ErrNoTurnCredentials`)
    pub fn urls(&self) -> Result<Vec<ice::url::Url>> {
        let mut urls = vec![];

        for url_str in &self.urls {
            let mut url = self.parse_url(url_str)?;
            if url.scheme == ice::url::SchemeType::Turn || url.scheme == ice::url::SchemeType::Turns
            {
                // https://www.w3.org/TR/webrtc/#set-the-configuration (step #11.3.2)
                if self.username.is_empty() || self.credential.is_empty() {
                    return Err(Error::ErrNoTurnCredentials);
                }

                url.username.clone_from(&self.username);
                url.password.clone_from(&self.credential);
            }

            urls.push(url);
        }

        Ok(urls)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ice_server_validate_success() {
        let tests = vec![
            (
                RTCIceServer {
                    urls: vec!["turn:192.158.29.39?transport=udp".to_owned()],
                    username: "unittest".to_owned(),
                    credential: "placeholder".to_owned(),
                },
                true,
            ),
            (
                RTCIceServer {
                    urls: vec!["turn:[2001:db8:1234:5678::1]?transport=udp".to_owned()],
                    username: "unittest".to_owned(),
                    credential: "placeholder".to_owned(),
                },
                true,
            ),
            /*TODO:(ICEServer{
                URLs:     []string{"turn:192.158.29.39?transport=udp"},
                Username: "unittest".to_owned(),
                Credential: OAuthCredential{
                    MACKey:      "WmtzanB3ZW9peFhtdm42NzUzNG0=",
                    AccessToken: "AAwg3kPHWPfvk9bDFL936wYvkoctMADzQ5VhNDgeMR3+ZlZ35byg972fW8QjpEl7bx91YLBPFsIhsxloWcXPhA==",
                },
                CredentialType: ICECredentialTypeOauth,
            }, true),*/
        ];

        for (ice_server, expected_validate) in tests {
            let result = ice_server.urls();
            assert_eq!(result.is_ok(), expected_validate);
        }
    }

    #[test]
    fn test_ice_server_validate_failure() {
        let tests = vec![
            (
                RTCIceServer {
                    urls: vec!["turn:192.158.29.39?transport=udp".to_owned()],
                    ..Default::default()
                },
                Error::ErrNoTurnCredentials,
            ),
            (
                RTCIceServer {
                    urls: vec!["turn:192.158.29.39?transport=udp".to_owned()],
                    username: "unittest".to_owned(),
                    credential: String::new(),
                },
                Error::ErrNoTurnCredentials,
            ),
            (
                RTCIceServer {
                    urls: vec!["turn:192.158.29.39?transport=udp".to_owned()],
                    username: "unittest".to_owned(),
                    credential: String::new(),
                },
                Error::ErrNoTurnCredentials,
            ),
            (
                RTCIceServer {
                    urls: vec!["turn:192.158.29.39?transport=udp".to_owned()],
                    username: "unittest".to_owned(),
                    credential: String::new(),
                },
                Error::ErrNoTurnCredentials,
            ),
        ];

        for (ice_server, expected_err) in tests {
            if let Err(err) = ice_server.urls() {
                assert_eq!(err, expected_err, "{ice_server:?} with err {err:?}");
            } else {
                panic!("expected error, but got ok");
            }
        }
    }

    #[test]
    fn test_ice_server_validate_failure_err_stun_query() {
        let tests = vec![(
            RTCIceServer {
                urls: vec!["stun:google.de?transport=udp".to_owned()],
                username: "unittest".to_owned(),
                credential: String::new(),
            },
            Error::ErrStunQuery,
        )];

        for (ice_server, expected_err) in tests {
            if let Err(err) = ice_server.urls() {
                assert_eq!(err, expected_err, "{ice_server:?} with err {err:?}");
            } else {
                panic!("expected error, but got ok");
            }
        }
    }
}
