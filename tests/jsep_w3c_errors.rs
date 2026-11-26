//! W3C webrtc-pc section 4.4.1.5 ("set the session description"): which error a JavaScript
//! API over this engine raises when a description is refused. One that does not parse (RFC
//! 9429 sections 5.8.1 and 5.8.2) is an `RTCError` (`OperationError`) with `errorDetail`
//! `"sdp-syntax-error"`; one that fails the semantic checks of RFC 9429 section 5.8.3 is an
//! `InvalidAccessError`; one the signaling state does not take is an `InvalidStateError`.
//! `Error::dom_exception_name` and `Error::rtc_error_detail` give those names.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::peer_connection::sdp::RTCSessionDescription;

fn video(mid: &str, transport: &str) -> String {
    format!(
        "m=video 9 UDP/TLS/RTP/SAVPF 96\n{transport}a=mid:{mid}\na=recvonly\na=rtpmap:96 VP8/90000\n"
    )
}

/// RFC 9429 section 5.8.3 refusals: each is an `InvalidAccessError`.
#[test]
fn a_description_that_fails_the_semantic_checks_is_an_invalid_access_error() -> TestResult {
    let without_ufrag = TRANSPORT.replace("a=ice-ufrag:4ZcD\n", "");
    let without_fingerprint = TRANSPORT
        .lines()
        .filter(|l| !l.starts_with("a=fingerprint:"))
        .map(|l| format!("{l}\n"))
        .collect::<String>();
    let without_mux = TRANSPORT.replace("a=rtcp-mux\n", "");
    for (what, sdp) in [
        ("no a=ice-ufrag", video("0", &without_ufrag)),
        ("no a=fingerprint", video("0", &without_fingerprint)),
        (
            "no a=rtcp-mux under the require policy",
            video("0", &without_mux),
        ),
    ] {
        let mut offerer = default_peer()?;
        offerer.add_transceiver_from_kind(
            rtci::rtp_transceiver::rtp_sender::RtpCodecKind::Video,
            None,
        )?;
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(Instant::now(), offer)?;
        let answer = RTCSessionDescription::answer(crlf(&format!(
            "{SESSION}{}",
            sdp.replace("a=recvonly", "a=sendrecv")
        )))?;
        let refused = offerer
            .set_remote_description(Instant::now(), answer)
            .expect_err(what);
        assert_eq!(
            refused.dom_exception_name(),
            Some("InvalidAccessError"),
            "{what}: {refused}"
        );
        assert_eq!(refused.rtc_error_detail(), None, "{what}");
    }
    Ok(())
}

/// A description that does not parse is an `RTCError` with `errorDetail` `sdp-syntax-error`.
#[test]
fn a_description_that_does_not_parse_is_an_sdp_syntax_error() -> TestResult {
    let refused = RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}m=video nine UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\n"
    )))
    .expect_err("a port that is not a number");
    assert_eq!(
        refused.dom_exception_name(),
        Some("OperationError"),
        "{refused}"
    );
    assert_eq!(refused.rtc_error_detail(), Some("sdp-syntax-error"));
    Ok(())
}

/// An answer in the `stable` state is an `InvalidStateError`.
#[test]
fn an_answer_without_an_offer_is_an_invalid_state_error() -> TestResult {
    let mut pc = default_peer()?;
    // A well-formed answer (`a=setup:active`): only the state is wrong.
    let transport = TRANSPORT.replace("a=setup:actpass", "a=setup:active");
    let answer =
        RTCSessionDescription::answer(crlf(&format!("{SESSION}{}", video("0", &transport))))?;
    let refused = pc
        .set_remote_description(Instant::now(), answer)
        .expect_err("no offer");
    assert_eq!(
        refused.dom_exception_name(),
        Some("InvalidStateError"),
        "{refused}"
    );
    Ok(())
}

/// W3C webrtc-pc 4.5.1 ("the specified error name"), for the operations other than setting a
/// description: what each refusal of the constructor, `setConfiguration` ("set the
/// configuration", "validate an ICE server URL"), `createAnswer` and `addIceCandidate` is
/// named, by the step that raises it.
#[test]
fn every_refusal_of_the_configuration_and_the_candidates_has_its_w3c_name() -> TestResult {
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::certificate::RTCCertificate;
    use rtci::peer_connection::configuration::{
        RTCBundlePolicy, RTCConfiguration, RTCConfigurationBuilder, RTCIceServer, RTCRtcpMuxPolicy,
    };
    use rtci::peer_connection::transport::RTCIceCandidateInit;
    use std::time::{Duration, SystemTime};

    let now = Instant::now();
    let provider = rtci::crypto::default_provider()?;
    let certificate = |issued: SystemTime, lifetime: Option<Duration>| {
        RTCCertificate::generate_certificate(
            provider.crypto(),
            rtci::crypto::SignatureScheme::EcdsaP256Sha256,
            lifetime,
            issued,
        )
    };
    let mut named: Vec<(String, Option<&'static str>, &'static str)> = vec![];
    let mut expect = |what: &str, refused: rtci::shared::error::Error, name: &'static str| {
        named.push((
            format!("{what}: {refused:?}"),
            refused.dom_exception_name(),
            name,
        ));
    };

    // Constructor step 3: "If the value of certificate.expires is less than the current
    // time, throw an InvalidAccessError."
    let expired = certificate(
        SystemTime::now() - Duration::from_secs(60 * 24 * 3600),
        Some(Duration::from_secs(24 * 3600)),
    )?;
    let built = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_certificates(vec![expired])
                .build(),
        )
        .build(now);
    expect(
        "an expired certificate",
        built.err().expect("refused"),
        "InvalidAccessError",
    );

    // "Set the configuration": "If oldConfig is not null, run the following steps, and if
    // any of them fail, throw an InvalidModificationError".
    let original = certificate(SystemTime::now(), None)?;
    let base = || {
        RTCConfigurationBuilder::new()
            .with_certificates(vec![original.clone()])
            .with_bundle_policy(RTCBundlePolicy::Balanced)
            .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
            .with_ice_candidate_pool_size(0)
    };
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(base().build())
        .build(now)?;
    pc.create_data_channel("errors", None)?;
    let offer = pc.create_offer(None)?;
    // setLocalDescription: an offer that is not [[LastCreatedOffer]] is an
    // InvalidModificationError (an answer that is not [[LastCreatedAnswer]] alike:
    // jsep_description_state.rs).
    expect(
        "an offer that is not the last created",
        pc.set_local_description(
            now,
            RTCSessionDescription::offer(offer.sdp.replace("s=-", "s=edited"))?,
        )
        .expect_err("edited"),
        "InvalidModificationError",
    );
    pc.set_local_description(now, offer.clone())?;
    let changes: Vec<(&str, RTCConfiguration)> = vec![
        (
            "other certificates",
            base()
                .with_certificates(vec![certificate(SystemTime::now(), None)?])
                .build(),
        ),
        (
            "another bundlePolicy",
            base()
                .with_bundle_policy(RTCBundlePolicy::MaxBundle)
                .build(),
        ),
        (
            "another rtcpMuxPolicy",
            base()
                .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Negotiate)
                .build(),
        ),
        (
            "another iceCandidatePoolSize after setLocalDescription",
            base().with_ice_candidate_pool_size(2).build(),
        ),
    ];
    for (what, changed) in changes {
        let refused = pc.set_configuration(changed).expect_err(what);
        expect(what, refused, "InvalidModificationError");
    }

    // "Validate an ICE server URL" and "set the configuration" step 11: SyntaxError, and
    // InvalidAccessError for the TURN credentials.
    let server = |url: &str| RTCIceServer {
        urls: vec![url.to_owned()],
        username: "user".to_owned(),
        credential: "secret".to_owned(),
    };
    for (what, server, name) in [
        (
            "no url",
            RTCIceServer {
                urls: vec![],
                ..server("stun:x")
            },
            "SyntaxError",
        ),
        ("another scheme", server("http:example.org"), "SyntaxError"),
        ("a fragment", server("stun:example.org#frag"), "SyntaxError"),
        (
            "an @ in the path",
            server("turn:user@example.org"),
            "SyntaxError",
        ),
        (
            "a / in the path",
            server("turn:example.org/path"),
            "SyntaxError",
        ),
        (
            "a query on a stun url",
            server("stun:example.org?transport=udp"),
            "SyntaxError",
        ),
        (
            "a query other than the transport",
            server("turn:example.org?transport=sctp"),
            "SyntaxError",
        ),
        (
            "a host that does not parse",
            server("turn:exa mple.org"),
            "SyntaxError",
        ),
        (
            "a port that does not parse",
            server("stun:example.org:99999"),
            "SyntaxError",
        ),
        (
            "a turn url without a credential",
            RTCIceServer {
                credential: String::new(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a turn url without a username",
            RTCIceServer {
                username: String::new(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a username of 509 bytes",
            RTCIceServer {
                username: "u".repeat(509),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a credential with a control character",
            RTCIceServer {
                credential: "sec\u{7}ret".to_owned(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a credential with a default-ignorable code point (not an OpaqueString)",
            RTCIceServer {
                credential: "The\u{ad}Matrix".to_owned(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
        (
            "a username that is not an OpaqueString (RFC 8489 section 14.3)",
            RTCIceServer {
                username: "us\u{0}er".to_owned(),
                ..server("turn:example.org")
            },
            "InvalidAccessError",
        ),
    ] {
        let refused = pc
            .set_configuration(base().with_ice_servers(vec![server]).build())
            .expect_err(what);
        expect(what, refused, name);
    }

    // createAnswer: "If connection.[[RemoteDescription]] is null ... InvalidStateError".
    let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
    expect(
        "createAnswer without a remote description",
        answerer
            .create_answer(None)
            .expect_err("no remote description"),
        "InvalidStateError",
    );

    // addIceCandidate (4.4.2).
    let host = |init: RTCIceCandidateInit| RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.0.2.1 5000 typ host".to_owned(),
        ..init
    };
    let mid = Some("0".to_owned());
    expect(
        "addIceCandidate without a remote description",
        answerer
            .add_remote_candidate(host(RTCIceCandidateInit {
                sdp_mid: mid.clone(),
                ..Default::default()
            }))
            .expect_err("no remote description"),
        "InvalidStateError",
    );
    answerer.set_remote_description(now, offer)?;
    for (what, init, name) in [
        (
            "neither sdpMid nor sdpMLineIndex",
            RTCIceCandidateInit::default(),
            "TypeError",
        ),
        (
            "an sdpMid of no media description",
            RTCIceCandidateInit {
                sdp_mid: Some("nope".to_owned()),
                ..Default::default()
            },
            "OperationError",
        ),
        (
            "an sdpMLineIndex past the media descriptions",
            RTCIceCandidateInit {
                sdp_mline_index: Some(5),
                ..Default::default()
            },
            "OperationError",
        ),
        (
            "a usernameFragment that is not the section's",
            RTCIceCandidateInit {
                sdp_mid: mid.clone(),
                username_fragment: Some("someoneelse".to_owned()),
                ..Default::default()
            },
            "OperationError",
        ),
    ] {
        let refused = answerer.add_remote_candidate(host(init)).expect_err(what);
        expect(what, refused, name);
    }

    let wrong: Vec<_> = named
        .iter()
        .filter(|(_, got, want)| *got != Some(*want))
        .collect();
    assert!(wrong.is_empty(), "named otherwise: {wrong:#?}");
    Ok(())
}
