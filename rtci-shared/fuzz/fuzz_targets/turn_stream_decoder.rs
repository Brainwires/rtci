#![no_main]
//! Stateful target: the decoder that splits a TURN-over-TCP / TLS stream (RFC 8656 section 12.5)
//! into STUN and ChannelData messages, fed the server's bytes in fuzzed chunk sizes.

use libfuzzer_sys::fuzz_target;
use rtci_shared::turn_framing::TurnStreamDecoder;

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let mut decoder = TurnStreamDecoder::new();
    let mut steps = 0;
    while let Some((&len, rest)) = data.split_first() {
        steps += 1;
        if steps > 4096 {
            break;
        }
        let len = usize::from(len).min(rest.len());
        let (chunk, rest) = rest.split_at(len);
        data = rest;
        decoder.extend_from_slice(chunk);
        loop {
            match decoder.next_message() {
                Ok(Some(message)) => {
                    // A message is at least its 4-byte length prefix plus what that says.
                    assert!(message.len() >= 4);
                }
                Ok(None) => break,
                // The stream is not TURN: a client drops the connection here.
                Err(_) => return,
            }
        }
        let _ = decoder.buffered_len();
    }
});
