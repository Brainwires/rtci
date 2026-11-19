//! Transport statistics.
//!
//! This module contains the [`RTCTransportStats`] type which provides
//! information about the underlying transport (ICE, DTLS, SRTP).

use super::RTCStats;
use crate::peer_connection::transport::{
    RTCDtlsRole, RTCDtlsTransportState, RTCIceRole, RTCIceTransportState,
};
use serde::{Deserialize, Serialize};

/// Statistics for the transport layer.
///
/// This struct corresponds to the `RTCTransportStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about the underlying
/// transport, including ICE connectivity, DTLS security, and packet counters.
///
/// # Specification
///
/// See [RTCTransportStats](https://www.w3.org/TR/webrtc-stats/#transportstats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCTransportStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// Total number of packets sent over this transport.
    pub packets_sent: u64,

    /// Total number of packets received over this transport.
    pub packets_received: u64,

    /// Total number of bytes sent over this transport.
    ///
    /// This includes all protocol overhead (STUN, DTLS, SRTP headers).
    pub bytes_sent: u64,

    /// Total number of bytes received over this transport.
    ///
    /// This includes all protocol overhead (STUN, DTLS, SRTP headers).
    pub bytes_received: u64,

    /// The ICE role of this peer.
    ///
    /// Either "controlling" or "controlled".
    pub ice_role: RTCIceRole,

    /// The local ICE username fragment.
    ///
    /// Used to identify this peer in ICE connectivity checks.
    pub ice_local_username_fragment: String,

    /// The current state of the ICE transport.
    pub ice_state: RTCIceTransportState,

    /// The current state of the DTLS transport.
    pub dtls_state: RTCDtlsTransportState,

    /// The DTLS role of this peer.
    ///
    /// "client" or "server", and "unknown" before it is decided (W3C `RTCDtlsRole`).
    #[serde(with = "w3c_dtls_role")]
    pub dtls_role: RTCDtlsRole,

    /// The negotiated TLS version.
    ///
    /// The uppercase hex of the ServerHello version bytes, "FEFD" for DTLS 1.2.
    pub tls_version: String,

    /// The negotiated DTLS cipher suite.
    ///
    /// For example: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".
    pub dtls_cipher: String,

    /// The negotiated SRTP cipher suite.
    ///
    /// For example: "AES_CM_128_HMAC_SHA1_80".
    pub srtp_cipher: String,

    /// The ID of the selected ICE candidate pair.
    ///
    /// References an [`RTCIceCandidatePairStats`](super::ice_candidate_pair::RTCIceCandidatePairStats) object.
    pub selected_candidate_pair_id: String,

    /// Number of times the selected candidate pair has changed.
    pub selected_candidate_pair_changes: u32,

    /// The ID of the local certificate stats.
    ///
    /// References an [`RTCCertificateStats`](super::certificate::RTCCertificateStats) object.
    pub local_certificate_id: String,

    /// The ID of the remote certificate stats.
    ///
    /// References an [`RTCCertificateStats`](super::certificate::RTCCertificateStats) object.
    pub remote_certificate_id: String,

    /// Number of RTCP congestion control feedback messages sent.
    pub ccfb_messages_sent: u32,

    /// Number of RTCP congestion control feedback messages received.
    pub ccfb_messages_received: u32,
}

/// The W3C `RTCDtlsRole` enum of `RTCTransportStats.dtlsRole`: "client", "server", or
/// "unknown" for a role that isn't decided yet (this crate's `Unspecified` and `Auto`).
mod w3c_dtls_role {
    use super::RTCDtlsRole;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(role: &RTCDtlsRole, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match role {
            RTCDtlsRole::Client => "client",
            RTCDtlsRole::Server => "server",
            _ => "unknown",
        })
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<RTCDtlsRole, D::Error> {
        Ok(match String::deserialize(d)?.as_str() {
            "client" => RTCDtlsRole::Client,
            "server" => RTCDtlsRole::Server,
            _ => RTCDtlsRole::Unspecified,
        })
    }
}

#[cfg(test)]
mod w3c_dtls_role_tests {
    use super::*;

    #[test]
    fn dtls_role_is_unknown_until_decided() {
        let value = |role| w3c_dtls_role::serialize(&role, serde_json::value::Serializer).unwrap();
        assert_eq!(value(RTCDtlsRole::Unspecified), "unknown");
        assert_eq!(value(RTCDtlsRole::Auto), "unknown");
        assert_eq!(value(RTCDtlsRole::Client), "client");
        assert_eq!(value(RTCDtlsRole::Server), "server");
    }
}
