#![no_main]
//! Stateful target: one data channel, opened by a fuzzed `DATA_CHANNEL_OPEN` (`accept`) or by us
//! (`dial`), then fed fuzzed messages as the SCTP layer would hand them over: DCEP on the DCEP
//! PPI (ACKs, repeated OPENs, the crate's internal types a peer must not send), user data on the
//! others, interleaved with local writes and close. No clock, no randomness.

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rtci_datachannel::data_channel::{DataChannel, DataChannelConfig, DataChannelMessage};
use rtci_sctp::PayloadProtocolIdentifier;
use sansio::Protocol;

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

/// Splits the next op argument off `data`: a two-byte length, then that many bytes.
fn take_arg<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    if data.len() < 2 {
        *data = &[];
        return &[];
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]])).min(data.len() - 2);
    let (arg, rest) = data[2..].split_at(len);
    *data = rest;
    arg
}

fn ppi(selector: u8) -> PayloadProtocolIdentifier {
    match selector % 7 {
        0 => PayloadProtocolIdentifier::Dcep,
        1 => PayloadProtocolIdentifier::String,
        2 => PayloadProtocolIdentifier::Binary,
        3 => PayloadProtocolIdentifier::StringEmpty,
        4 => PayloadProtocolIdentifier::BinaryEmpty,
        _ => PayloadProtocolIdentifier::from(u32::from(selector)),
    }
}

fn drain(channel: &mut DataChannel) {
    while channel.poll_read().is_some() {}
    while channel.poll_write().is_some() {}
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;
    let stream_id = u16::from(config);
    let open = take_arg(&mut data);

    let channel = if config & 0x01 == 0 {
        DataChannel::accept(
            DataChannelConfig::default(),
            1,
            stream_id,
            ppi(config >> 1),
            open,
        )
    } else {
        DataChannel::dial(
            DataChannelConfig {
                negotiated: config & 0x02 != 0,
                label: String::from_utf8_lossy(open).into_owned(),
                ..Default::default()
            },
            1,
            stream_id,
        )
    };
    let Ok(mut channel) = channel else {
        return;
    };
    drain(&mut channel);

    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 512 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 4 {
            0 | 1 => {
                let _ = channel.handle_read(DataChannelMessage::new(
                    1,
                    stream_id,
                    ppi(byte(arg, 0)),
                    BytesMut::from(arg.get(1..).unwrap_or(&[])),
                    false,
                ));
            }
            2 => {
                let message =
                    DataChannel::get_data_channel_message(op & 0x80 != 0, BytesMut::from(arg));
                let _ = channel.handle_write(message);
            }
            _ => {
                let _ = channel.close();
            }
        }
        let _ = channel.is_handshake_complete();
        drain(&mut channel);
    }
});
