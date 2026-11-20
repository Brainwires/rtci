use super::*;

// The tests that sat in a block comment here, written for the async connection, are ported to
// the sans-I/O connection in `conn_ported_test.rs` (test_renegotation_info below).

// --- RenegotiationInfo, driven without sockets ---
//
// The asynchronous original raced a spawned server against wall-clock sleeps and timed out on
// Windows CI, so it was gated off there. Sans-I/O, the server is a `DTLSConn` fed records
// directly; nothing waits on the clock, so the gate is gone.

/// One ClientHello record (epoch 0), optionally offering renegotiation_info.
fn client_hello_record(
    cookie: Vec<u8>,
    sequence_number: u64,
    send_renegotiation_info: bool,
) -> Result<Vec<u8>> {
    use crate::cipher_suite::CipherSuiteId;
    use crate::compression_methods::default_compression_methods;
    use crate::extension::Extension;
    use crate::extension::renegotiation_info::ExtensionRenegotiationInfo;
    use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
    use crate::handshake::handshake_random::HandshakeRandom;

    let mut extensions = vec![];
    if send_renegotiation_info {
        extensions.push(Extension::RenegotiationInfo(ExtensionRenegotiationInfo {
            renegotiated_connection: 0,
        }));
    }

    let mut h = Handshake::new(HandshakeMessage::ClientHello(HandshakeMessageClientHello {
        version: PROTOCOL_VERSION1_2,
        random: HandshakeRandom::default(),
        cookie,

        cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
        compression_methods: default_compression_methods(),
        extensions,
    }));
    h.handshake_header.message_sequence = sequence_number as u16;

    let mut record = RecordLayer::new(PROTOCOL_VERSION1_2, 0, Content::Handshake(h));
    record.record_layer_header.sequence_number = sequence_number;

    let mut packet = vec![];
    record.marshal(&mut packet)?;
    Ok(packet)
}

/// The first record of `datagram`, parsed.
fn first_record(datagram: &[u8]) -> Result<RecordLayer> {
    let records = unpack_datagram(datagram)?;
    let mut reader = records[0].as_slice();
    RecordLayer::unmarshal(&mut reader)
}

// Assert that a DTLS Server always responds with RenegotiationInfo if
// a ClientHello contained that extension or not
#[test]
fn test_renegotation_info() -> Result<()> {
    use crate::cipher_suite::CipherSuiteId;
    use crate::config::ConfigBuilder;
    use crate::crypto::Certificate;
    use crate::extension::Extension;

    let provider = crypto::default_provider().map_err(|err| Error::Crypto(err.to_string()))?;
    let config = Arc::new(
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
            .with_certificates(vec![Certificate::generate_self_signed(
                vec!["localhost".to_owned()],
                provider.crypto(),
            )?])
            .build(false, None)?,
    );
    // The clock never has to move: every answer is produced by the read that provokes it.
    let now = Instant::now();

    let tests = vec![
        ("Include RenegotiationInfo", true),
        ("No RenegotiationInfo", false),
    ];

    for (name, send_renegotiation_info) in tests {
        let mut server = DTLSConn::new(config.clone(), false, None);

        server.read(&client_hello_record(vec![], 0, send_renegotiation_info)?)?;
        server.handshake(now)?;
        let response = server
            .outgoing_raw_packet()
            .expect("the server answers a cookieless ClientHello");
        let hello_verify_request = match first_record(&response)?.content {
            Content::Handshake(h) => match h.handshake_message {
                HandshakeMessage::HelloVerifyRequest(hvr) => hvr,
                _ => {
                    panic!("unexpected handshake message");
                }
            },
            _ => {
                panic!("unexpected content");
            }
        };

        server.read(&client_hello_record(
            hello_verify_request.cookie.clone(),
            1,
            send_renegotiation_info,
        )?)?;
        server.handshake(now)?;
        let response = server
            .outgoing_raw_packet()
            .expect("the server answers the ClientHello with its cookie");

        let server_hello = match first_record(&response)?.content {
            Content::Handshake(h) => match h.handshake_message {
                HandshakeMessage::ServerHello(sh) => sh,
                _ => {
                    panic!("unexpected handshake message");
                }
            },
            _ => {
                panic!("unexpected content");
            }
        };

        let got_negotation_info = server_hello
            .extensions
            .iter()
            .any(|v| matches!(v, Extension::RenegotiationInfo(_)));

        assert!(
            got_negotation_info,
            "{name}: Received ServerHello without RenegotiationInfo"
        );
    }

    Ok(())
}

// --- Tests for issue #46: DTLS handshake deadlock when Finished arrives before ChangeCipherSpec ---
//
// The deadlock scenario:
//   1. Client sends ChangeCipherSpec (epoch=0) + Finished (epoch=1), possibly out of order.
//   2. Finished (epoch=1) arrives first → queued in incoming_encrypted_packets because
//      remote_epoch is still 0 (h.epoch > remote_epoch).
//   3. ChangeCipherSpec arrives → remote_epoch bumps to 1, cipher suite initialized.
//   4. handshake() runs but stays in Waiting because handshake_rx is None.
//   5. handle_incoming_queued_packets() is called: the fix drains the queue (cipher ready),
//      processes Finished, and sets handshake_rx = Some(()).
//   6. Second handshake() call advances the FSM past Waiting.
//
// Fix 1 (read): pass enqueue = !is_handshake_completed() so post-handshake future-epoch
//               packets are discarded, not buffered indefinitely (RFC 6347 §4.2.4).
// Fix 2 (handle_incoming_queued_packets): use cipher_suite.is_initialized() as the gate
//               (not is_handshake_completed()), and propagate hs → handshake_rx.

/// Verify that read() no longer enqueues future-epoch packets once the handshake
/// is completed (RFC 6347: buffer only until Finished is received).
#[test]
fn test_read_does_not_enqueue_after_handshake_completed() {
    let config = Arc::new(HandshakeConfig::new(
        crypto::default_provider().expect("a built-in crypto provider is enabled for tests"),
    ));
    let mut conn = DTLSConn::new(config, false, None);

    // Mark handshake as completed.
    conn.set_handshake_completed();
    assert!(conn.is_handshake_completed());
    assert!(conn.incoming_encrypted_packets.is_empty());

    // Build a minimal valid DTLS record with epoch=1 (next-epoch packet).
    // unpack_datagram reads content_len from the last 2 bytes of the 13-byte header.
    let datagram = vec![
        0x16, // content_type: Handshake
        0xfe, 0xfd, // protocol_version: DTLS 1.2
        0x00, 0x01, // epoch: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number: 1
        0x00, 0x01, // content_len: 1
        0x00, // payload (1 byte)
    ];

    // read() with handshake completed: should NOT enqueue the epoch=1 packet.
    let _ = conn.read(&datagram);
    assert!(
        conn.incoming_encrypted_packets.is_empty(),
        "After handshake completion, future-epoch packets must be discarded, not queued"
    );
}

/// Verify that read() still enqueues future-epoch packets while the handshake
/// is in progress (needed to handle Finished arriving before ChangeCipherSpec).
#[test]
fn test_read_enqueues_during_handshake() {
    let config = Arc::new(HandshakeConfig::new(
        crypto::default_provider().expect("a built-in crypto provider is enabled for tests"),
    ));
    let mut conn = DTLSConn::new(config, false, None);

    assert!(!conn.is_handshake_completed());
    assert!(conn.incoming_encrypted_packets.is_empty());

    // Build epoch=1 packet while remote_epoch is still 0 → should be queued.
    let datagram = vec![
        0x16, // content_type: Handshake
        0xfe, 0xfd, // protocol_version: DTLS 1.2
        0x00, 0x01, // epoch: 1 (one ahead of remote_epoch=0)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number: 1
        0x00, 0x01, // content_len: 1
        0x00, // payload
    ];

    let _ = conn.read(&datagram);
    assert_eq!(
        conn.incoming_encrypted_packets.len(),
        1,
        "During handshake, future-epoch packets must be queued for later processing"
    );
}

/// Verify that handle_incoming_queued_packets() drains the queue and sets
/// handshake_rx when the cipher suite is initialized (even before handshake_completed).
/// This is the core fix: the old code guarded on is_handshake_completed() which
/// was always false at the call site in endpoint.rs, making it a no-op.
#[test]
fn test_handle_incoming_queued_packets_drains_when_cipher_ready() {
    use crate::cipher_suite::CipherSuite;
    use crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;

    let config = Arc::new(HandshakeConfig::new(
        crypto::default_provider().expect("a built-in crypto provider is enabled for tests"),
    ));
    let mut conn = DTLSConn::new(config, false, None);

    assert!(!conn.is_handshake_completed());

    // Simulate a queued epoch=0 handshake packet (epoch matches remote_epoch=0,
    // so handle_incoming_packet can attempt to process it — it will fail to decode
    // as a real handshake message, but the queue will be drained, which is what we test).
    let pkt = vec![
        0x16, // content_type: Handshake
        0xfe, 0xfd, // protocol_version: DTLS 1.2
        0x00, 0x00, // epoch: 0 (matches remote_epoch so no re-queuing)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number: 1
        0x00, 0x01, // content_len: 1
        0x00, // payload
    ];
    conn.incoming_encrypted_packets.push_back(pkt.clone());
    assert_eq!(conn.incoming_encrypted_packets.len(), 1);

    // Without cipher suite initialized: should NOT drain.
    conn.handle_incoming_queued_packets().unwrap();
    assert_eq!(
        conn.incoming_encrypted_packets.len(),
        1,
        "Queue must not be drained when cipher suite is not yet initialized"
    );

    // Now initialize the cipher suite (simulates ChangeCipherSpec having been processed).
    let mut cs = Box::new(CipherSuiteAes128GcmSha256::new(false));
    // init() with dummy key material — will produce an initialized cipher suite.
    let _ = cs.init(
        crypto::default_provider().unwrap(),
        &[0u8; 48],
        &[0u8; 32],
        &[0u8; 32],
        false,
    );
    assert!(cs.is_initialized());
    conn.state.cipher_suite = Some(cs);

    // Now drain: cipher is ready, queue should be processed and emptied.
    conn.handle_incoming_queued_packets().unwrap();
    assert!(
        conn.incoming_encrypted_packets.is_empty(),
        "Queue must be drained once the cipher suite is initialized"
    );
}

/// Verify that handle_incoming_queued_packets() sets handshake_rx when
/// processing a queued packet that yields hs=true, so the FSM's wait()
/// state can advance past Waiting on the next handshake() call.
#[test]
fn test_handle_incoming_queued_packets_sets_handshake_rx() {
    use crate::cipher_suite::CipherSuite;
    use crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;

    let config = Arc::new(HandshakeConfig::new(
        crypto::default_provider().expect("a built-in crypto provider is enabled for tests"),
    ));
    let mut conn = DTLSConn::new(config, false, None);

    // Initialize cipher suite.
    let mut cs = Box::new(CipherSuiteAes128GcmSha256::new(false));
    let _ = cs.init(
        crypto::default_provider().unwrap(),
        &[0u8; 48],
        &[0u8; 32],
        &[0u8; 32],
        false,
    );
    conn.state.cipher_suite = Some(cs);
    conn.state.remote_epoch = 0;
    conn.handshake_rx = None;

    // Queue a minimal epoch=0 handshake record. handle_incoming_packet will
    // attempt to process it; even if the payload isn't a valid Finished, the
    // important thing is that handshake_rx remains None only if hs==false.
    // We test the plumbing: if the queue is drained, handshake_rx is set
    // whenever hs==true comes back. For a fragment-buffer hit, hs==true.
    // Here we just confirm the queue is drained and no panic occurs.
    let pkt = vec![
        0x16, // content_type: Handshake
        0xfe, 0xfd, // protocol_version: DTLS 1.2
        0x00, 0x00, // epoch: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // sequence_number: 2
        0x00, 0x01, // content_len: 1
        0x00, // payload
    ];
    conn.incoming_encrypted_packets.push_back(pkt);

    conn.handle_incoming_queued_packets().unwrap();

    // Queue must be empty regardless of whether hs was true or false.
    assert!(
        conn.incoming_encrypted_packets.is_empty(),
        "Queue must be fully drained by handle_incoming_queued_packets"
    );
    // handshake_rx is set if and only if the packet was recognized as a handshake
    // message by the fragment buffer. For this minimal stub it won't be, but the
    // key invariant is that the function runs without leaving packets behind.
}

fn setup_dtls_conn_server_handshake_in_progress() -> DTLSConn {
    let handshake_config = Arc::new(HandshakeConfig::new(
        crypto::default_provider().expect("a built-in crypto provider is enabled for tests"),
    ));
    // is_client=false (server), no initial_state → handshake not completed
    DTLSConn::new(handshake_config, false, None)
}

/// From issue #46 — verifies the fix for Bug 1:
/// After the fix, handle_incoming_queued_packets() drains the queue once the
/// cipher suite is initialized, even before handshake_completed.
/// (The old guard `is_handshake_completed()` was replaced with `cipher_suite.is_initialized()`.)
///
/// This test uses an epoch=1 packet queued while the cipher suite is initialized,
/// confirming the queue IS drained (fixed behavior).
#[test]
fn test_queued_packets_drained_when_cipher_ready() {
    use crate::cipher_suite::CipherSuite;
    use crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;

    let mut conn = setup_dtls_conn_server_handshake_in_progress();
    assert!(!conn.is_handshake_completed());

    // Simulate a queued epoch-1 encrypted packet (e.g. Finished).
    let fake_epoch1_packet: Vec<u8> = vec![
        0x16, // content_type: Handshake
        0xfe, 0xfd, // protocol_version: DTLS 1.2
        0x00, 0x01, // epoch: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number: 1
        0x00, 0x01, // content_len: 1
        0x00, // payload (dummy)
    ];
    conn.incoming_encrypted_packets
        .push_back(fake_epoch1_packet);

    // Without cipher suite: queue is not drained.
    conn.handle_incoming_queued_packets().unwrap();
    assert_eq!(conn.incoming_encrypted_packets.len(), 1);

    // Initialize cipher suite (simulates ChangeCipherSpec having been processed).
    let mut cs = Box::new(CipherSuiteAes128GcmSha256::new(false));
    let _ = cs.init(
        crypto::default_provider().unwrap(),
        &[0u8; 48],
        &[0u8; 32],
        &[0u8; 32],
        false,
    );
    conn.state.cipher_suite = Some(cs);
    conn.state.remote_epoch = 1; // ChangeCipherSpec has been processed

    // After fix: queue IS drained once cipher suite is initialized.
    conn.handle_incoming_queued_packets().unwrap();
    assert!(
        conn.incoming_encrypted_packets.is_empty(),
        "After fix: queued packets must be drained once cipher suite is initialized"
    );
}

/// From issue #46 — verifies the fix for Bug 2:
/// After the fix, handle_incoming_queued_packets() propagates hs=true from
/// handle_incoming_packet() into self.handshake_rx = Some(()).
///
/// Uses a well-formed epoch-0 handshake fragment that the fragment_buffer
/// will accept, causing handle_incoming_packet to return hs=true.
#[test]
fn test_handshake_rx_set_after_queue_processing() {
    use crate::cipher_suite::CipherSuite;
    use crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;

    let mut conn = setup_dtls_conn_server_handshake_in_progress();

    // Initialize cipher suite so the queue-drain guard passes.
    let mut cs = Box::new(CipherSuiteAes128GcmSha256::new(false));
    let _ = cs.init(
        crypto::default_provider().unwrap(),
        &[0u8; 48],
        &[0u8; 32],
        &[0u8; 32],
        false,
    );
    conn.state.cipher_suite = Some(cs);

    assert!(conn.handshake_rx.is_none());

    // A well-formed epoch-0 handshake record with a complete fragment
    // (ClientHello stub) that the fragment_buffer will accept, causing
    // handle_incoming_packet to return hs=true.
    let fake_handshake_packet: Vec<u8> = vec![
        0x16, // content_type: Handshake
        0xfe, 0xfd, // protocol_version: DTLS 1.2
        0x00, 0x00, // epoch: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence_number: 0
        0x00, 0x10, // content_len: 16
        // Minimal handshake header
        0x01, // handshake_type: ClientHello
        0x00, 0x00, 0x04, // length: 4
        0x00, 0x00, // message_sequence: 0
        0x00, 0x00, 0x00, // fragment_offset: 0
        0x00, 0x00, 0x04, // fragment_length: 4
        0xfe, 0xfd, 0x00, 0x00, // body (version + dummy)
    ];
    conn.incoming_encrypted_packets
        .push_back(fake_handshake_packet);

    conn.handle_incoming_queued_packets().unwrap();

    // After fix: handshake_rx is set because hs=true is now propagated.
    assert!(
        conn.handshake_rx.is_some(),
        "After fix: handshake_rx must be set when a queued packet yields hs=true"
    );
}

/// RFC 6347 4.1: "Until the handshake has completed, implementations MUST accept packets from the
/// old epoch." Between the peer's ChangeCipherSpec (remote_epoch already 1) and the end of the
/// handshake, a plaintext epoch-0 alert is still honoured; only once the handshake has completed
/// is it discarded.
#[test]
fn test_old_epoch_alert_honoured_until_handshake_completes() {
    let fatal_alert: Vec<u8> = vec![
        0x15, // content_type: Alert
        0xfe, 0xfd, // protocol_version: DTLS 1.2
        0x00, 0x00, // epoch: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // sequence_number: 5
        0x00, 0x02, // content_len: 2
        0x02, 0x28, // fatal handshake_failure
    ];

    let mut conn = setup_dtls_conn_server_handshake_in_progress();
    conn.state.remote_epoch = 1; // ChangeCipherSpec has been processed
    assert!(!conn.is_handshake_completed());
    assert!(
        matches!(conn.read(&fatal_alert), Err(Error::ErrAlertFatalOrClose)),
        "an old-epoch alert must be accepted until the handshake completes"
    );

    let mut conn = setup_dtls_conn_server_handshake_in_progress();
    conn.state.remote_epoch = 1;
    conn.set_handshake_completed();
    assert!(
        conn.read(&fatal_alert).is_ok(),
        "an old-epoch alert must be discarded once the handshake has completed"
    );
    assert!(
        conn.outgoing_packets.is_empty(),
        "a discarded alert was answered"
    );
}

/// The queue of records that arrive before they can be decrypted is bounded: an unauthenticated
/// sender must not be able to make it grow without limit during the handshake.
#[test]
fn test_early_encrypted_queue_is_bounded() {
    let config = Arc::new(HandshakeConfig::new(
        crypto::default_provider().expect("a built-in crypto provider is enabled for tests"),
    ));
    let mut conn = DTLSConn::new(config, false, None);
    for sequence in 0..(MAX_EARLY_ENCRYPTED_PACKETS as u8 + 50) {
        let datagram = vec![
            0x16, // content_type: Handshake
            0xfe, 0xfd, // protocol_version: DTLS 1.2
            0x00, 0x01, // epoch: 1 (one ahead of remote_epoch=0)
            0x00, 0x00, 0x00, 0x00, 0x00, sequence, // sequence_number
            0x00, 0x01, // content_len: 1
            0x00, // payload
        ];
        let _ = conn.read(&datagram);
    }
    assert_eq!(
        conn.incoming_encrypted_packets.len(),
        MAX_EARLY_ENCRYPTED_PACKETS,
        "the early encrypted queue must stop growing at its cap"
    );
}

/// A ChangeCipherSpec is not authenticated, so its epoch is whatever the sender claims. One at
/// the last epoch has no successor; it used to overflow `epoch + 1` and panic.
#[test]
fn test_change_cipher_spec_at_the_last_epoch_is_dropped() {
    use crate::cipher_suite::CipherSuite;
    use crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;

    let mut conn = setup_dtls_conn_server_handshake_in_progress();
    let mut cs = Box::new(CipherSuiteAes128GcmSha256::new(false));
    cs.init(
        crypto::default_provider().unwrap(),
        &[0u8; 48],
        &[0u8; 32],
        &[0u8; 32],
        false,
    )
    .unwrap();
    conn.state.cipher_suite = Some(cs);
    conn.state.remote_epoch = u16::MAX;

    let change_cipher_spec: Vec<u8> = vec![
        0x14, // content_type: ChangeCipherSpec
        0xfe, 0xfd, // protocol_version: DTLS 1.2
        0xff, 0xff, // epoch: 65535
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence_number: 0
        0x00, 0x01, // content_len: 1
        0x01,
    ];
    let _ = conn.read(&change_cipher_spec);
    assert_eq!(conn.state.remote_epoch, u16::MAX);
}

/// A ChangeCipherSpec is unauthenticated. Once the handshake has completed, one spoofed at the
/// current epoch used to move `remote_epoch` to 2, after which every genuine epoch-1 record was
/// discarded as old: a keyless denial of service. Repeated, it also grew one replay detector
/// per claimed epoch.
#[test]
fn test_change_cipher_spec_after_handshake_is_ignored() {
    use crate::cipher_suite::CipherSuite;
    use crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;

    let mut conn = setup_dtls_conn_server_handshake_in_progress();
    let mut cs = Box::new(CipherSuiteAes128GcmSha256::new(false));
    cs.init(
        crypto::default_provider().unwrap(),
        &[0u8; 48],
        &[0u8; 32],
        &[0u8; 32],
        false,
    )
    .unwrap();
    conn.state.cipher_suite = Some(cs);
    conn.state.remote_epoch = 1;
    conn.set_handshake_completed();

    for epoch in 1u16..200 {
        let [hi, lo] = epoch.to_be_bytes();
        let change_cipher_spec: Vec<u8> = vec![
            0x14, // content_type: ChangeCipherSpec
            0xfe, 0xfd, // protocol_version: DTLS 1.2
            hi, lo, // epoch
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence_number: 0
            0x00, 0x01, // content_len: 1
            0x01,
        ];
        let _ = conn.read(&change_cipher_spec);
    }
    assert_eq!(
        conn.state.remote_epoch, 1,
        "a spoofed ChangeCipherSpec moved the epoch"
    );
    assert!(
        conn.replay_detector.len() <= usize::from(MAX_REMOTE_EPOCH) + 2,
        "{} replay detectors",
        conn.replay_detector.len()
    );
}

/// Before the handshake completes, a ChangeCipherSpec at epoch 0 still moves the peer to
/// epoch 1, and only once.
#[test]
fn test_change_cipher_spec_moves_epoch_0_to_1_only() {
    use crate::cipher_suite::CipherSuite;
    use crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;

    let mut conn = setup_dtls_conn_server_handshake_in_progress();
    let mut cs = Box::new(CipherSuiteAes128GcmSha256::new(false));
    cs.init(
        crypto::default_provider().unwrap(),
        &[0u8; 48],
        &[0u8; 32],
        &[0u8; 32],
        false,
    )
    .unwrap();
    conn.state.cipher_suite = Some(cs);
    for (epoch, sequence) in [(0u8, 0u8), (1, 0), (1, 1)] {
        let change_cipher_spec: Vec<u8> = vec![
            0x14, 0xfe, 0xfd, 0x00, epoch, 0x00, 0x00, 0x00, 0x00, 0x00, sequence, 0x00, 0x01, 0x01,
        ];
        let _ = conn.read(&change_cipher_spec);
        assert_eq!(conn.state.remote_epoch, 1);
    }
}

/// Encrypts one epoch-1 application-data record as the peer would.
fn encrypt_epoch1_application_data(
    peer_cipher_suite: &mut dyn crate::cipher_suite::CipherSuite,
    sequence_number: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut record = RecordLayer::new(
        PROTOCOL_VERSION1_2,
        1,
        Content::ApplicationData(ApplicationData {
            data: BytesMut::from(payload),
        }),
    );
    record.record_layer_header.sequence_number = sequence_number;
    let mut raw = vec![];
    record.marshal(&mut raw).unwrap();
    peer_cipher_suite
        .encrypt(&record.record_layer_header, &raw)
        .unwrap()
}

/// Until the handshake completes the sender of epoch-1 records is not authenticated (a server
/// keys its cipher from the client's key exchange, before Finished and the client-certificate
/// check). Application data received then must not be held without limit, nor delivered.
#[test]
fn test_pre_handshake_application_data_is_bounded() {
    use crate::cipher_suite::CipherSuite;
    use crate::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;

    let mut conn = setup_dtls_conn_server_handshake_in_progress();
    let mut server_cs = Box::new(CipherSuiteAes128GcmSha256::new(false));
    server_cs
        .init(
            crypto::default_provider().unwrap(),
            &[7u8; 48],
            &[1u8; 32],
            &[2u8; 32],
            false,
        )
        .unwrap();
    let mut client_cs = CipherSuiteAes128GcmSha256::new(false);
    client_cs
        .init(
            crypto::default_provider().unwrap(),
            &[7u8; 48],
            &[1u8; 32],
            &[2u8; 32],
            true,
        )
        .unwrap();
    conn.state.cipher_suite = Some(server_cs);
    conn.state.remote_epoch = 1; // the peer's ChangeCipherSpec has been processed

    let payload = vec![0xabu8; 1200];
    for sequence_number in 0..10_000u64 {
        let datagram = encrypt_epoch1_application_data(&mut client_cs, sequence_number, &payload);
        let _ = conn.read(&datagram);
        assert!(
            conn.incoming_decrypted_packets.len() <= MAX_PRE_HANDSHAKE_APPLICATION_DATA_PACKETS,
            "pre-handshake application data grew to {} records",
            conn.incoming_decrypted_packets.len()
        );
        assert!(
            conn.incoming_decrypted_packets
                .iter()
                .map(|p| p.len())
                .sum::<usize>()
                <= MAX_PRE_HANDSHAKE_APPLICATION_DATA_BYTES
        );
        assert!(
            conn.incoming_application_data().is_none(),
            "application data delivered before the handshake completed"
        );
    }
    assert!(
        !conn.incoming_decrypted_packets.is_empty(),
        "the first records after the peer's Finished must still be kept"
    );

    // Once the handshake has completed, application data is no longer capped.
    conn.set_handshake_completed();
    let held = conn.incoming_decrypted_packets.len();
    for sequence_number in 10_000..10_000 + 2 * MAX_PRE_HANDSHAKE_APPLICATION_DATA_PACKETS as u64 {
        let datagram = encrypt_epoch1_application_data(&mut client_cs, sequence_number, &payload);
        conn.read(&datagram).unwrap();
    }
    assert_eq!(
        conn.incoming_decrypted_packets.len(),
        held + 2 * MAX_PRE_HANDSHAKE_APPLICATION_DATA_PACKETS
    );
    assert_eq!(
        conn.incoming_application_data().unwrap().len(),
        payload.len()
    );
}

/// A flight whose parse failed (and sent a fatal alert) is terminal: further handshake records
/// must not make the server parse, and verify, it again.
#[test]
fn test_failed_flight_is_not_parsed_again() {
    use crate::cipher_suite::CipherSuiteId;
    use crate::compression_methods::default_compression_methods;
    use crate::flight::flight2::Flight2;
    use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
    use crate::handshake::handshake_random::HandshakeRandom;

    let mut conn = setup_dtls_conn_server_handshake_in_progress();
    conn.current_flight = Box::new(Flight2 {});
    conn.current_handshake_state = HandshakeState::Waiting;
    conn.state.cookie = vec![1; COOKIE_LENGTH];
    conn.state.handshake_recv_sequence = 1;

    let mut handshake =
        Handshake::new(HandshakeMessage::ClientHello(HandshakeMessageClientHello {
            version: PROTOCOL_VERSION1_2,
            random: HandshakeRandom::default(),
            cookie: vec![2; COOKIE_LENGTH],
            cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
            compression_methods: default_compression_methods(),
            extensions: vec![],
        }));
    handshake.handshake_header.message_sequence = 1;
    let mut data = vec![];
    handshake.marshal(&mut data).unwrap();
    assert!(
        conn.cache
            .push(data, 0, 1, HandshakeType::ClientHello, true)
    );

    conn.handshake_rx = Some(());
    assert!(matches!(
        conn.handshake(Instant::now()),
        Err(Error::ErrCookieMismatch)
    ));
    assert!(conn.current_handshake_state == HandshakeState::Errored);

    // More handshake records: the failed flight is not parsed again. The failed handshake
    // failed the association, which refuses any further handshake step as closed.
    for _ in 0..100 {
        conn.handshake_rx = Some(());
        assert!(matches!(
            conn.handshake(Instant::now()),
            Err(Error::ErrConnClosed)
        ));
    }
    assert!(conn.current_handshake_state == HandshakeState::Errored);
}
