//! What `create_data_channel` refuses, by RFC 8832 section 5.1 and RFC 8831 section 6.5.
//!
//! A DATA_CHANNEL_OPEN carries the label and the protocol behind 16-bit lengths, so neither
//! can be longer than 65535 bytes: a longer label used to be accepted and sent as a corrupt
//! OPEN. And a data channel is one pair of SCTP streams with the same identifier, so a second
//! channel negotiated onto a stream in use has to fail: it used to take the stream over.

use anyhow::Result;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::shared::error::Error;
use std::time::Instant;

#[test]
fn a_label_over_65535_bytes_is_refused() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    let longest = "l".repeat(65535);
    assert_eq!(pc.create_data_channel(&longest, None)?.label().len(), 65535);
    let too_long = "l".repeat(65536);
    assert_eq!(
        pc.create_data_channel(&too_long, None).err(),
        Some(Error::ErrLabelTooLarge)
    );
    // Bytes, not characters: 32768 two-byte characters are 65536 bytes.
    let too_long = "\u{e9}".repeat(32768);
    assert_eq!(
        pc.create_data_channel(&too_long, None).err(),
        Some(Error::ErrLabelTooLarge)
    );
    Ok(())
}

#[test]
fn a_protocol_over_65535_bytes_is_refused() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    let with_protocol = |protocol: String| {
        Some(RTCDataChannelInit {
            protocol,
            ..Default::default()
        })
    };
    assert!(
        pc.create_data_channel("a", with_protocol("p".repeat(65535)))
            .is_ok()
    );
    assert_eq!(
        pc.create_data_channel("b", with_protocol("p".repeat(65536)))
            .err(),
        Some(Error::ErrProtocolTooLarge)
    );
    Ok(())
}

/// RFC 8831 section 6.5: "If it attempts to reuse a stream that is part of an existing data
/// channel, the addition MUST fail." The first channel keeps the stream.
#[test]
fn a_second_negotiated_channel_on_a_stream_in_use_is_refused() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    let negotiated = |id| {
        Some(RTCDataChannelInit {
            negotiated: Some(id),
            ..Default::default()
        })
    };
    let first = pc.create_data_channel("first", negotiated(4))?.id();
    assert_eq!(
        pc.create_data_channel("second", negotiated(4)).err(),
        Some(Error::ErrDataChannelIdInUse)
    );
    let first = pc.data_channel(first).expect("the first channel");
    assert_eq!(first.label(), "first");
    assert_eq!(first.stream_id(), Some(4));

    // Another id is fine, and so is an in-band channel, whose id comes later.
    pc.create_data_channel("third", negotiated(5))?;
    pc.create_data_channel("in-band", None)?;
    Ok(())
}

/// An association has at most 65535 streams, numbered from 0: there is no stream 65535.
#[test]
fn negotiated_id_65535_is_refused() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    let negotiated = |id| {
        Some(RTCDataChannelInit {
            negotiated: Some(id),
            ..Default::default()
        })
    };
    assert_eq!(
        pc.create_data_channel("out of range", negotiated(65535))
            .err(),
        Some(Error::ErrMaxDataChannelID)
    );
    pc.create_data_channel("highest", negotiated(65534))?;
    Ok(())
}
