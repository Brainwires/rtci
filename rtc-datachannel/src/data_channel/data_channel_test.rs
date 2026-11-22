use super::*;
use crate::message::message_type::MessageType;
use sansio::Protocol;
use shared::error::Result;

fn create_new_association_pair() -> Result<(usize, usize)> {
    Ok((0, 0))
}

fn close_association_pair(_client: usize, _server: usize) {}

//use std::io::Write;

// pr_ordered_unordered_test is in sctp_link_test.rs.

#[test]
fn test_data_channel_channel_type_reliable_ordered() -> Result<()> {
    let mut sbuf = vec![0u8; 1000];

    let (a0, a1) = create_new_association_pair()?;

    let cfg = DataChannelConfig {
        channel_type: ChannelType::Reliable,
        reliability_parameter: 123,
        label: "data".to_string(),
        ..Default::default()
    };

    let mut dc0 = DataChannel::dial(cfg.clone(), a0, 100)?;

    let msg = dc0.poll_write().ok_or(Error::ErrAssociationNotExisted)?;
    let mut dc1 = DataChannel::accept(
        DataChannelConfig::default(),
        a1,
        msg.stream_id,
        PayloadProtocolIdentifier::Dcep,
        &msg.payload,
    )?;

    assert_eq!(dc0.config, cfg, "local config should match");
    assert_eq!(dc1.config, cfg, "remote config should match");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let data_channel_message =
        DataChannel::get_data_channel_message(true, BytesMut::from(&sbuf[0..4]));
    dc0.handle_write(data_channel_message)?;
    assert_eq!(dc0.bytes_sent(), 4, "data length should match");

    sbuf[0..4].copy_from_slice(&2u32.to_be_bytes());
    let data_channel_message =
        DataChannel::get_data_channel_message(false, BytesMut::from(&sbuf[0..4]));
    dc0.handle_write(data_channel_message)?;
    assert_eq!(dc0.bytes_sent(), 8, "data length should match");

    let msg = dc0.poll_write().ok_or(Error::ErrAssociationNotExisted)?;
    dc1.handle_read(msg)?;
    assert_eq!(dc1.bytes_received(), 4, "data length should match");
    let data_channel_message = dc1.poll_read().ok_or(Error::ErrAssociationNotExisted)?;
    assert!(
        data_channel_message.ppi == PayloadProtocolIdentifier::String
            || data_channel_message.ppi == PayloadProtocolIdentifier::StringEmpty
    );
    assert_eq!(
        4,
        data_channel_message.payload.len(),
        "data length should match"
    );
    assert_eq!(
        1,
        u32::from_be_bytes([
            data_channel_message.payload[0],
            data_channel_message.payload[1],
            data_channel_message.payload[2],
            data_channel_message.payload[3]
        ]),
        "data should match"
    );

    let msg = dc0.poll_write().ok_or(Error::ErrAssociationNotExisted)?;
    dc1.handle_read(msg)?;
    assert_eq!(dc1.bytes_received(), 8, "data length should match");
    let data_channel_message = dc1.poll_read().ok_or(Error::ErrAssociationNotExisted)?;
    assert!(
        !(data_channel_message.ppi == PayloadProtocolIdentifier::String
            || data_channel_message.ppi == PayloadProtocolIdentifier::StringEmpty)
    );
    assert_eq!(
        4,
        data_channel_message.payload.len(),
        "data length should match"
    );
    assert_eq!(
        2,
        u32::from_be_bytes([
            data_channel_message.payload[0],
            data_channel_message.payload[1],
            data_channel_message.payload[2],
            data_channel_message.payload[3]
        ]),
        "data should match"
    );

    dc0.close()?;
    dc1.close()?;

    close_association_pair(a0, a1);

    Ok(())
}

/// Pre-negotiated (out-of-band) channels rely on the `SctpHandler` to suppress
/// the DCEP DataChannelOpen payload on the wire.  This test verifies the
/// `dial()` side of that contract: the outbound `DataChannelMessage` must carry
/// `negotiated = true` so the SCTP handler knows to open the stream without
/// sending the DCEP payload to the remote peer.
///
/// Note: the handler-side suppression is exercised by integration tests in the
/// `rtc` crate; this unit test only covers the flagging produced by `dial()`.
///
/// Regression test for <https://github.com/webrtc-rs/rtc/issues/61>.
#[test]
fn test_data_channel_negotiated_dial_flags_message() -> Result<()> {
    let (a0, a1) = create_new_association_pair()?;
    let stream_id = 42;

    let cfg = DataChannelConfig {
        channel_type: ChannelType::Reliable,
        negotiated: true,
        label: "negotiated-ch".to_string(),
        protocol: "test-proto".to_string(),
        ..Default::default()
    };

    let mut dc = DataChannel::dial(cfg.clone(), a0, stream_id)?;

    // dial() must still produce exactly one outbound DCEP message so the SCTP
    // handler can register the stream.
    let msg = dc.poll_write().ok_or(Error::ErrAssociationNotExisted)?;
    assert_eq!(msg.ppi, PayloadProtocolIdentifier::Dcep);
    assert_eq!(msg.stream_id, stream_id);

    // The message must be flagged as negotiated so the SCTP handler opens the
    // stream but does NOT send the DCEP payload to the peer.
    assert!(
        msg.negotiated,
        "negotiated DataChannelOpen must be marked as internal-only"
    );

    // No further outbound messages should be queued.
    assert!(
        dc.poll_write().is_none(),
        "negotiated dial should produce exactly one outbound message"
    );

    // Verify the config round-trips correctly.
    assert_eq!(dc.config(), &cfg);

    dc.close()?;
    close_association_pair(a0, a1);

    Ok(())
}

/// Regression test for <https://github.com/webrtc-rs/rtc/issues/61>.
///
/// An out-of-band *negotiated* channel used to emit no message from `dial`, so
/// the underlying SCTP stream was never opened and any later write failed with
/// "Stream not existed". `dial` must now emit a `DATA_CHANNEL_OPEN` (to open and
/// configure the local stream) that is flagged so the transport keeps it local
/// and does not perform the DCEP handshake with the peer.
#[test]
fn test_data_channel_negotiated_opens_stream_without_dcep_handshake() -> Result<()> {
    let (a0, _a1) = create_new_association_pair()?;

    let cfg = DataChannelConfig {
        channel_type: ChannelType::Reliable,
        label: "negotiated".to_string(),
        negotiated: true,
        ..Default::default()
    };

    let mut dc = DataChannel::dial(cfg, a0, 100)?;

    // A single DATA_CHANNEL_OPEN must be queued so the stream gets opened.
    let msg = dc.poll_write().ok_or(Error::ErrStreamNotExisted)?;
    assert_eq!(
        msg.ppi,
        PayloadProtocolIdentifier::Dcep,
        "negotiated dial should emit a DATA_CHANNEL_OPEN to open the stream"
    );
    assert!(
        msg.negotiated,
        "a negotiated channel's DATA_CHANNEL_OPEN must be flagged internal-only"
    );
    assert_eq!(
        Message::unmarshal(&mut &msg.payload[..])?.message_type(),
        MessageType::DataChannelOpen,
        "the queued message should be a DATA_CHANNEL_OPEN"
    );
    assert!(
        dc.poll_write().is_none(),
        "no further DCEP messages expected for a negotiated channel"
    );
    assert!(
        dc.is_handshake_complete(),
        "an out-of-band negotiated channel is open immediately (no DCEP handshake)"
    );

    Ok(())
}

/// Non-negotiated (in-band) channels must send a regular DCEP DataChannelOpen
/// that can be accepted by the peer.
#[test]
fn test_data_channel_non_negotiated_sends_dcep() -> Result<()> {
    let (a0, a1) = create_new_association_pair()?;

    let cfg = DataChannelConfig {
        channel_type: ChannelType::Reliable,
        negotiated: false,
        label: "in-band".to_string(),
        ..Default::default()
    };

    let mut dc0 = DataChannel::dial(cfg.clone(), a0, 100)?;

    let msg = dc0.poll_write().ok_or(Error::ErrAssociationNotExisted)?;
    assert_eq!(msg.ppi, PayloadProtocolIdentifier::Dcep);
    // In-band channel: negotiated flag must be false so the SCTP handler sends
    // the DCEP payload over the wire.
    assert!(
        !msg.negotiated,
        "in-band DataChannelOpen must NOT be marked as internal-only"
    );

    // The peer should be able to accept this DCEP message.
    let mut dc1 = DataChannel::accept(
        DataChannelConfig::default(),
        a1,
        msg.stream_id,
        PayloadProtocolIdentifier::Dcep,
        &msg.payload,
    )?;
    assert_eq!(dc1.config(), &cfg, "remote config should match");

    dc0.close()?;
    dc1.close()?;
    close_association_pair(a0, a1);

    Ok(())
}

/// A non-negotiated (in-band) channel emits a `DATA_CHANNEL_OPEN` that IS sent
/// over the wire, so it must not be flagged as negotiated.
#[test]
fn test_data_channel_in_band_open_is_transmitted() -> Result<()> {
    let (a0, _a1) = create_new_association_pair()?;

    let cfg = DataChannelConfig {
        channel_type: ChannelType::Reliable,
        label: "in-band".to_string(),
        negotiated: false,
        ..Default::default()
    };

    let mut dc = DataChannel::dial(cfg, a0, 100)?;
    let msg = dc.poll_write().ok_or(Error::ErrStreamNotExisted)?;
    assert_eq!(msg.ppi, PayloadProtocolIdentifier::Dcep);
    assert!(
        !msg.negotiated,
        "an in-band DATA_CHANNEL_OPEN must be transmitted to the peer"
    );
    assert!(
        !dc.is_handshake_complete(),
        "an in-band channel is not open until the peer's DATA_CHANNEL_ACK arrives"
    );

    Ok(())
}

/// An in-band channel becomes open the moment its `DATA_CHANNEL_ACK` is processed.
#[test]
fn test_data_channel_in_band_open_on_data_channel_ack() -> Result<()> {
    let (a0, _a1) = create_new_association_pair()?;

    let cfg = DataChannelConfig {
        channel_type: ChannelType::Reliable,
        label: "in-band".to_string(),
        negotiated: false,
        ..Default::default()
    };

    let mut dc = DataChannel::dial(cfg, a0, 100)?;
    assert!(!dc.is_handshake_complete());

    // The dialed channel is a Protocol<DataChannelMessage, ...>; feed it the peer's ACK.
    let ack_bytes = Message::DataChannelAck(DataChannelAck {}).marshal()?;
    dc.handle_read(DataChannelMessage {
        association_handle: a0,
        stream_id: 100,
        ppi: PayloadProtocolIdentifier::Dcep,
        payload: BytesMut::from(&ack_bytes[..]),
        negotiated: false,
    })?;

    assert!(
        dc.is_handshake_complete(),
        "receiving DATA_CHANNEL_ACK must mark the local channel as open"
    );

    Ok(())
}

/// A remote channel is open from `accept()`: the peer's `DATA_CHANNEL_OPEN` has
/// been processed and the ACK is written out, completing the handshake.
#[test]
fn test_data_channel_accept_marks_remote_channel_open() -> Result<()> {
    let (a0, _a1) = create_new_association_pair()?;

    let open_bytes = Message::DataChannelOpen(DataChannelOpen {
        channel_type: ChannelType::Reliable,
        priority: CHANNEL_PRIORITY_NORMAL,
        reliability_parameter: 0,
        label: b"remote".to_vec(),
        protocol: Vec::new(),
    })
    .marshal()?;

    let dc = DataChannel::accept(
        DataChannelConfig::default(),
        a0,
        100,
        PayloadProtocolIdentifier::Dcep,
        &open_bytes[..],
    )?;

    assert!(
        dc.is_handshake_complete(),
        "accept() processing the peer's DATA_CHANNEL_OPEN must mark the remote channel as open"
    );

    Ok(())
}

/// Closing an open channel clears the handshake-complete flag.
#[test]
fn test_data_channel_close_resets_handshake_complete_flag() -> Result<()> {
    let (a0, _a1) = create_new_association_pair()?;

    let cfg = DataChannelConfig {
        channel_type: ChannelType::Reliable,
        label: "negotiated".to_string(),
        negotiated: true,
        ..Default::default()
    };

    let mut dc = DataChannel::dial(cfg, a0, 100)?;
    assert!(
        dc.is_handshake_complete(),
        "an out-of-band negotiated channel is open immediately (no DCEP handshake)"
    );

    dc.close()?;
    assert!(
        !dc.is_handshake_complete(),
        "closing an open channel must clear the handshake-complete flag"
    );

    Ok(())
}

// test_data_channel_channel_type_reliable_unordered, the four partial-reliability tests,
// test_data_channel_buffered_amount, test_stats and test_poll_data_channel ran over a tokio
// bridge upstream; they are in sctp_link_test.rs, over two real SCTP associations.

/// DCEP types 0x00 (threshold) and 0x01 (close) are internal to this stack and never sent on
/// the wire. From the peer they are refused, whether they would open a channel or arrive on
/// one, and they cause no write.
#[test]
fn test_internal_dcep_types_from_the_peer_are_refused() -> Result<()> {
    let (a0, _a1) = create_new_association_pair()?;
    let internal: [&[u8]; 3] = [&[0x00, 0x00, 0x00, 0x00, 0x10, 0x00], &[0x00], &[0x01]];
    for payload in internal {
        assert!(
            DataChannel::accept(
                DataChannelConfig::default(),
                a0,
                100,
                PayloadProtocolIdentifier::Dcep,
                payload,
            )
            .is_err(),
            "accept() took {payload:?}"
        );

        let mut dc = DataChannel::dial(
            DataChannelConfig {
                label: "in-band".to_string(),
                ..Default::default()
            },
            a0,
            100,
        )?;
        while dc.poll_write().is_some() {}
        assert!(
            dc.handle_read(DataChannelMessage {
                association_handle: a0,
                stream_id: 100,
                ppi: PayloadProtocolIdentifier::Dcep,
                payload: BytesMut::from(payload),
                negotiated: false,
            })
            .is_err(),
            "an open channel took {payload:?}"
        );
        assert!(dc.poll_write().is_none());
        assert!(dc.poll_read().is_none());
        assert!(!dc.is_handshake_complete());
    }
    Ok(())
}

/// Fuzz regression (`data_channel_handle_dcep`, minimised input `2f00f9ff79005b00`): a one-byte
/// DCEP payload `0x00` on a new stream, or on an open channel, panicked the receiver.
#[test]
fn test_one_byte_dcep_payload_is_an_error() {
    assert!(
        DataChannel::accept(
            DataChannelConfig::default(),
            0,
            1,
            PayloadProtocolIdentifier::Dcep,
            &[0x00]
        )
        .is_err()
    );

    let mut dc = DataChannel::accept(
        DataChannelConfig::default(),
        0,
        1,
        PayloadProtocolIdentifier::Dcep,
        &Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: 0,
            reliability_parameter: 0,
            label: b"chat".to_vec(),
            protocol: vec![],
        })
        .marshal()
        .unwrap(),
    )
    .unwrap();
    let msg = DataChannelMessage {
        stream_id: 1,
        ppi: PayloadProtocolIdentifier::Dcep,
        payload: BytesMut::from(&[0x00][..]),
        ..Default::default()
    };
    assert!(dc.handle_read(msg).is_err());
}

/// RFC 8832 section 6: a DATA_CHANNEL_OPEN "received on an already used stream" is not
/// acknowledged. The channel reports it as an error, on which its owner closes the channel;
/// it used to answer with a second DATA_CHANNEL_ACK and carry on.
#[test]
fn test_open_on_a_channel_in_use_is_refused_without_an_ack() -> Result<()> {
    let open = Message::DataChannelOpen(DataChannelOpen {
        channel_type: ChannelType::Reliable,
        priority: CHANNEL_PRIORITY_NORMAL,
        reliability_parameter: 0,
        label: b"again".to_vec(),
        protocol: Vec::new(),
    })
    .marshal()?;
    let open_on = |stream_id| DataChannelMessage {
        stream_id,
        ppi: PayloadProtocolIdentifier::Dcep,
        payload: BytesMut::from(&open[..]),
        ..Default::default()
    };

    // A channel the peer opened, one this side opened, and one negotiated out of band.
    let accepted = DataChannel::accept(
        DataChannelConfig::default(),
        0,
        1,
        PayloadProtocolIdentifier::Dcep,
        &open,
    )?;
    let dialed = DataChannel::dial(DataChannelConfig::default(), 0, 1)?;
    let negotiated = DataChannel::dial(
        DataChannelConfig {
            negotiated: true,
            ..Default::default()
        },
        0,
        1,
    )?;
    for mut dc in [accepted, dialed, negotiated] {
        while dc.poll_write().is_some() {}
        assert!(dc.handle_read(open_on(1)).is_err());
        assert!(dc.poll_write().is_none(), "no DATA_CHANNEL_ACK");
        assert_eq!(
            dc.messages_received(),
            0,
            "a refused message is not counted"
        );
    }
    Ok(())
}

/// RFC 8831 section 6.6: the PPID says how a message is to be read. One under a PPID that is
/// not a data channel's (52 and 54, the deprecated partial ones, included: all decode to
/// `Unknown`) is refused, where it used to be queued for the application as binary data.
#[test]
fn test_a_message_with_an_unsupported_ppid_is_refused() -> Result<()> {
    let mut dc = DataChannel::dial(
        DataChannelConfig {
            negotiated: true,
            ..Default::default()
        },
        0,
        1,
    )?;
    for wire_ppid in [0u32, 52, 54, 55, 58] {
        let ppi = PayloadProtocolIdentifier::from(wire_ppid);
        assert!(
            dc.handle_read(DataChannelMessage {
                stream_id: 1,
                ppi,
                payload: BytesMut::from(&b"fragment"[..]),
                ..Default::default()
            })
            .is_err(),
            "PPID {wire_ppid}"
        );
    }
    assert!(dc.poll_read().is_none());
    assert_eq!(dc.messages_received(), 0);
    assert_eq!(dc.bytes_received(), 0);

    // The four user PPIDs of RFC 8831 section 8 are delivered.
    for wire_ppid in [51u32, 53, 56, 57] {
        dc.handle_read(DataChannelMessage {
            stream_id: 1,
            ppi: PayloadProtocolIdentifier::from(wire_ppid),
            payload: BytesMut::from(&[0u8][..]),
            ..Default::default()
        })?;
        assert!(dc.poll_read().is_some(), "PPID {wire_ppid}");
    }
    Ok(())
}

/// RFC 8832 section 5.1: for reliable data channels the Reliability Parameter "MUST be set to
/// 0 on the sending side", and the OPEN this side sends carries the priority, label and
/// protocol the channel was created with.
#[test]
fn test_a_dialed_open_carries_the_channels_parameters() -> Result<()> {
    let (channel_type, reliability_parameter) =
        DataChannel::get_channel_type_and_reliability_parameter(false, None, None);
    assert_eq!(
        (channel_type, reliability_parameter),
        (ChannelType::ReliableUnordered, 0)
    );
    let mut dc = DataChannel::dial(
        DataChannelConfig {
            channel_type,
            reliability_parameter,
            priority: 1024,
            label: "label".to_owned(),
            protocol: "proto".to_owned(),
            negotiated: false,
        },
        0,
        2,
    )?;
    let open = dc.poll_write().expect("the OPEN");
    assert_eq!(open.ppi, PayloadProtocolIdentifier::Dcep);
    assert_eq!(open.stream_id, 2);
    assert_eq!(
        Message::unmarshal(&mut &open.payload[..])?,
        Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::ReliableUnordered,
            priority: 1024,
            reliability_parameter: 0,
            label: b"label".to_vec(),
            protocol: b"proto".to_vec(),
        })
    );
    Ok(())
}
