//! Upstream webrtc-rs/webrtc v0.17.1 `sctp/src/stream/stream_test.rs`, ported to the
//! sans-I/O stream: a `Stream` is a handle on its association, so each test drives an
//! established association instead of a stream with its own task and channels.

use super::*;
use crate::association::timer::Timer;
use crate::config::TransportConfig;
use shared::TransportProtocol;
use std::net::SocketAddr;
use std::sync::Arc;

fn established() -> Association {
    let mut a = Association::new(
        None,
        Arc::new(TransportConfig::default()),
        1200,
        0,
        SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::from(([0, 0, 0, 0], 0)),
        TransportProtocol::UDP,
        Instant::now(),
        crate::util::RandomSource::default(),
    );
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a
}

fn unordered_chunk(tsn: u32, data: &'static [u8]) -> ChunkPayloadData {
    ChunkPayloadData {
        tsn,
        unordered: true,
        beginning_fragment: true,
        ending_fragment: true,
        user_data: Bytes::from_static(data),
        payload_type: PayloadProtocolIdentifier::Binary,
        ..Default::default()
    }
}

/// Reads one message into a 5-byte buffer, as upstream's `read(&mut [0; 5])`.
fn read5(stream: &mut Stream<'_>) -> Result<[u8; 5]> {
    let chunks = stream.read_sctp()?.expect("a message is readable");
    let mut buf = [0u8; 5];
    let n = chunks.read(&mut buf)?;
    assert_eq!(5, n);
    Ok(buf)
}

#[test]
fn test_stream_buffered_amount() -> Result<()> {
    let mut a = established();
    let mut s = a.open_stream(0, PayloadProtocolIdentifier::Binary)?;
    assert_eq!(0, s.buffered_amount()?);
    assert_eq!(0, s.buffered_amount_low_threshold()?);

    s.association.streams.get_mut(&0).unwrap().buffered_amount = 8192;
    s.set_buffered_amount_low_threshold(2048)?;
    assert_eq!(8192, s.buffered_amount()?, "unexpected bufferedAmount");
    assert_eq!(
        2048,
        s.buffered_amount_low_threshold()?,
        "unexpected threshold"
    );
    Ok(())
}

/// `on_buffer_released` reports a crossing to or below the threshold, once per crossing, the
/// way upstream's callback fires.
#[test]
fn test_stream_amount_on_buffered_amount_low() {
    let mut s = StreamState::new(Side::Client, 0, 1200, PayloadProtocolIdentifier::Binary);
    s.buffered_amount = 4096;
    s.buffered_amount_low = 2048;
    let mut n_cbs = 0;

    // Negative value should be ignored (by design)
    n_cbs += usize::from(s.on_buffer_released(-32));
    assert_eq!(4096, s.buffered_amount);
    assert_eq!(0, n_cbs);

    // Above to above, no callback
    n_cbs += usize::from(s.on_buffer_released(1024));
    assert_eq!(3072, s.buffered_amount);
    assert_eq!(0, n_cbs);

    // Above to equal, callback should be made
    n_cbs += usize::from(s.on_buffer_released(1024));
    assert_eq!(2048, s.buffered_amount);
    assert_eq!(1, n_cbs);

    // Equal to below, no callback
    n_cbs += usize::from(s.on_buffer_released(1024));
    assert_eq!(1024, s.buffered_amount);
    assert_eq!(1, n_cbs);

    // Below to below, no callback
    n_cbs += usize::from(s.on_buffer_released(1024));
    assert_eq!(0, s.buffered_amount);
    assert_eq!(1, n_cbs);

    // Capped at 0, no callback
    n_cbs += usize::from(s.on_buffer_released(1024));
    assert_eq!(0, s.buffered_amount);
    assert_eq!(1, n_cbs);
}

#[test]
fn test_stream() -> Result<()> {
    let now = Instant::now();
    let mut a = established();
    let mut s = a.open_stream(0, PayloadProtocolIdentifier::Binary)?;

    // getters
    assert_eq!(0, s.stream_identifier());
    assert_eq!(0, s.buffered_amount()?);
    assert_eq!(0, s.buffered_amount_low_threshold()?);
    assert_eq!(
        0,
        s.association.streams[&0].get_num_bytes_in_reassembly_queue()
    );

    // setters
    s.set_default_payload_type(PayloadProtocolIdentifier::Binary)?;
    s.set_reliability_params(true, ReliabilityType::Reliable, 0)?;

    // write
    assert_eq!(6, s.write(now, b"Hello ")?);
    assert_eq!(6, s.buffered_amount()?);
    assert_eq!(
        5,
        s.write_sctp(
            now,
            &Bytes::from_static(b"world"),
            PayloadProtocolIdentifier::Binary
        )?
    );
    assert_eq!(11, s.buffered_amount()?);

    // read: pretend that we've received a chunk, then read it
    s.association
        .streams
        .get_mut(&0)
        .unwrap()
        .handle_data(&unordered_chunk(1, &[0, 1, 2, 3, 4]));
    assert_eq!([0, 1, 2, 3, 4], read5(&mut s)?);

    // shutdown write: writes fail, reads keep working
    s.finish()?;
    assert!(s.write(now, b"error").is_err());
    s.association
        .streams
        .get_mut(&0)
        .unwrap()
        .handle_data(&unordered_chunk(2, &[5, 6, 7, 8, 9]));
    assert_eq!([5, 6, 7, 8, 9], read5(&mut s)?);

    // shutdown read: upstream's EOF is the closed-stream error here
    s.stop(now)?;
    assert!(matches!(s.read_sctp(), Err(Error::ErrStreamClosed)));
    Ok(())
}

/// Upstream's `PollStream` is the async adapter; here the same calls are the stream's own
/// `write` (default payload type) and `read`, and a second handle on the same stream.
#[test]
fn test_poll_stream() -> Result<()> {
    let now = Instant::now();
    let mut a = established();
    let mut s = a.open_stream(0, PayloadProtocolIdentifier::Binary)?;

    // getters
    assert_eq!(0, s.stream_identifier());
    assert_eq!(0, s.buffered_amount()?);
    assert_eq!(0, s.buffered_amount_low_threshold()?);

    // write
    assert_eq!(3, s.write(now, &[1, 2, 3])?);
    assert_eq!(3, s.buffered_amount()?);

    // read
    s.association
        .streams
        .get_mut(&0)
        .unwrap()
        .handle_data(&unordered_chunk(1, &[0, 1, 2, 3, 4]));
    let chunks = s.read()?.expect("readable");
    let mut buf = [0u8; 5];
    chunks.read(&mut buf)?;
    assert_eq!([0, 1, 2, 3, 4], buf);

    // shutdown write: writes fail, reads keep working
    s.finish()?;
    assert!(s.write(now, &[1, 2, 3]).is_err());
    s.association
        .streams
        .get_mut(&0)
        .unwrap()
        .handle_data(&unordered_chunk(2, &[5, 6, 7, 8, 9]));
    assert_eq!([5, 6, 7, 8, 9], read5(&mut s)?);

    // misc.: another handle names the same stream
    let id = s.stream_identifier();
    assert_eq!(id, a.stream(0)?.stream_identifier());
    Ok(())
}
