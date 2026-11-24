//! A DTLS handshake against a certificate that does not match the signalled fingerprint ends
//! the connection as `failed`, over real sockets in the test environment
//! (`scripts/test-env/run.sh`); ignored elsewhere.
//!
//! RFC 5763 5 / RFC 8122 5: an endpoint that receives a certificate whose fingerprint does not
//! match the one in the remote description must not complete the association. W3C webrtc 5.5.1:
//! the RTCDtlsTransport then goes to "failed", and the connection state with it (4.3.3). A
//! handshake error that is only logged leaves the connection "connecting" for good.

mod common;
mod testenv;

use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use std::time::{Duration, Instant};
use testenv::{Env, EnvPeer, Gather, negotiate_with, pump, with_wrong_fingerprint};

const FAIL_WITHIN: Duration = Duration::from_secs(30);

fn channel_opened(p: &EnvPeer) -> bool {
    p.events.iter().any(|e| {
        matches!(
            e,
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_))
        )
    })
}

/// `tamper_offer`: b receives a's offer with a wrong fingerprint (b, the answerer, is the one
/// that checks a's certificate against it); otherwise a receives the wrong fingerprint in b's
/// answer.
fn wrong_fingerprint_fails(tamper_offer: bool) {
    common::install_crypto_provider();
    let env = Env::get();
    let new_pc = || {
        RTCPeerConnectionBuilder::new()
            .build(Instant::now())
            .unwrap()
    };
    let mut a = EnvPeer::new("a", "open-a", Gather::HOST, &env, new_pc()).expect("peer a");
    let mut b = EnvPeer::new("b", "open-b", Gather::HOST, &env, new_pc()).expect("peer b");
    a.pc.create_data_channel("fingerprint", None).unwrap();
    let keep = |sdp: &str| sdp.to_owned();
    if tamper_offer {
        negotiate_with(&mut a, &mut b, with_wrong_fingerprint, keep).unwrap();
    } else {
        negotiate_with(&mut a, &mut b, keep, with_wrong_fingerprint).unwrap();
    }
    let ever_connected = |p: &EnvPeer| {
        p.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    rtci::peer_connection::state::RTCPeerConnectionState::Connected
                )
            )
        })
    };
    let failed = pump(&mut [&mut a, &mut b], FAIL_WITHIN, |p| {
        let checker = if tamper_offer { &*p[1] } else { &*p[0] };
        checker.failed()
    })
    .unwrap();
    let (checker, other) = if tamper_offer { (&b, &a) } else { (&a, &b) };
    eprintln!(
        "wrong fingerprint in the {}: checker {} state {:?}, other {} state {:?}",
        if tamper_offer { "offer" } else { "answer" },
        checker.name,
        checker.connection_state(),
        other.name,
        other.connection_state()
    );
    assert!(
        !ever_connected(checker),
        "{} connected to a peer whose certificate does not match the fingerprint",
        checker.name
    );
    assert!(
        !channel_opened(&a) && !channel_opened(&b),
        "a data channel opened over a DTLS association with the wrong certificate"
    );
    assert!(
        failed,
        "{} never reached \"failed\" within {FAIL_WITHIN:?} (state {:?})",
        checker.name,
        checker.connection_state()
    );
}

#[test]
#[ignore = "needs the real-network test environment: scripts/test-env/run.sh"]
fn wrong_fingerprint_in_the_answer_fails_the_offerer() {
    wrong_fingerprint_fails(false);
}

#[test]
#[ignore = "needs the real-network test environment: scripts/test-env/run.sh"]
fn wrong_fingerprint_in_the_offer_fails_the_answerer() {
    wrong_fingerprint_fails(true);
}
