//! What a sender who can spoof the peer's address can do to reassembly with unauthenticated
//! epoch-0 records: none of it may keep the genuine messages from being reassembled.

use super::*;

/// One epoch-0 handshake record holding one fragment.
fn fragment_record(
    record_sequence: u8,
    handshake_type: u8,
    length: u32,
    message_sequence: u16,
    fragment_offset: u32,
    fragment: &[u8],
) -> Vec<u8> {
    let mut body = vec![handshake_type];
    body.extend_from_slice(&length.to_be_bytes()[1..]);
    body.extend_from_slice(&message_sequence.to_be_bytes());
    body.extend_from_slice(&fragment_offset.to_be_bytes()[1..]);
    body.extend_from_slice(&(fragment.len() as u32).to_be_bytes()[1..]);
    body.extend_from_slice(fragment);
    let mut record = vec![
        0x16,
        0xfe,
        0xfd,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        record_sequence,
    ];
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

/// A complete three-byte ServerHelloDone-shaped message (type 14) under `message_sequence`.
fn genuine_record(record_sequence: u8, message_sequence: u16) -> Vec<u8> {
    fragment_record(
        record_sequence,
        14,
        3,
        message_sequence,
        0,
        &[0x01, 0x02, 0x03],
    )
}

/// A forged first fragment that disagrees with the genuine message's length used to win offset 0
/// for good, so the genuine message never reassembled.
#[test]
fn a_conflicting_forged_fragment_does_not_block_the_genuine_message() -> Result<()> {
    let mut f = FragmentBuffer::new();
    f.push(&fragment_record(0, 14, 1000, 0, 0, &[0xee; 10]))?;
    assert!(f.pop().is_err(), "the forged fragment alone is incomplete");

    f.push(&genuine_record(1, 0))?;
    let (message, epoch) = f.pop()?;
    assert_eq!(epoch, 0);
    assert_eq!(
        &message[HANDSHAKE_HEADER_LENGTH..],
        &[0x01, 0x02, 0x03],
        "the genuine message is reassembled"
    );
    Ok(())
}

/// A later genuine fragment replaces a forged one at the same offset with the same reading.
#[test]
fn a_later_fragment_replaces_a_conflicting_one_at_the_same_offset() -> Result<()> {
    let mut f = FragmentBuffer::new();
    // Forged: the right type and length, but its first fragment ends where nothing follows.
    f.push(&fragment_record(0, 14, 6, 0, 0, &[0xee; 2]))?;
    // Genuine: three bytes at offset 0, then three at offset 3.
    f.push(&fragment_record(1, 14, 6, 0, 0, &[0x01, 0x02, 0x03]))?;
    f.push(&fragment_record(2, 14, 6, 0, 3, &[0x04, 0x05, 0x06]))?;
    let (message, _) = f.pop()?;
    assert_eq!(
        &message[HANDSHAKE_HEADER_LENGTH..],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    );
    Ok(())
}

/// Fragments far ahead of the next expected message are evicted, so they cannot take every
/// buffer slot and lock the genuine messages out.
#[test]
fn fragments_far_ahead_are_evicted() -> Result<()> {
    let mut f = FragmentBuffer::new();
    for (index, message_sequence) in (1000u16..1000 + MAX_BUFFERED_MESSAGES as u16 + 8).enumerate()
    {
        // Incomplete: two bytes claimed, one sent.
        f.push(&fragment_record(
            index as u8,
            14,
            2,
            message_sequence,
            0,
            &[0xee],
        ))?;
        // As the connection does after every handshake record.
        assert!(f.pop().is_err());
    }
    assert!(
        f.cache.keys().all(|seq| *seq < MESSAGE_SEQUENCE_WINDOW),
        "nothing beyond the window is kept"
    );

    f.push(&genuine_record(200, 0))?;
    assert!(f.pop().is_ok(), "the genuine message still gets a slot");
    Ok(())
}

/// A message that turned out not to parse hands its sequence number out again, so the genuine
/// message under it is still taken.
#[test]
fn unpop_hands_the_sequence_number_out_again() -> Result<()> {
    let mut f = FragmentBuffer::new();
    f.push(&fragment_record(0, 0xff, 3, 0, 0, &[0xee; 3]))?;
    assert!(f.pop().is_ok());
    f.unpop();

    f.push(&genuine_record(1, 0))?;
    let (message, _) = f.pop()?;
    assert_eq!(&message[HANDSHAKE_HEADER_LENGTH..], &[0x01, 0x02, 0x03]);
    Ok(())
}

/// A message sent again after it was popped is handed out by `pop_stale`, once, and no longer
/// sits in the buffer.
#[test]
fn a_repeated_message_is_taken_by_pop_stale() -> Result<()> {
    let mut f = FragmentBuffer::new();
    f.push(&genuine_record(0, 0))?;
    let (first, _) = f.pop()?;

    f.push(&genuine_record(1, 0))?;
    assert!(f.pop().is_err(), "a repeat is not handed out by pop");
    let (repeat, epoch, message_sequence) = f.pop_stale().expect("the repeat is complete");
    assert_eq!((repeat, epoch, message_sequence), (first, 0, 0));
    assert!(f.pop_stale().is_none());
    assert!(f.cache.is_empty());
    Ok(())
}
