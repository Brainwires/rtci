#![no_main]
//! The RFC 8627 FEC header parser (`flexfec`), fed what a peer puts in a repair packet: a CSRC
//! list and a payload. Whatever parses must be consistent with itself: one block per CSRC, the
//! repair payload inside the packet, the protected offsets ascending and within what L, D or a
//! 110-bit mask can express.

use libfuzzer_sys::fuzz_target;
use rtc::interceptor::{FLEXFEC_MAX_MASK_BITS, FlexFecHeader, FlexFecProtected};

fuzz_target!(|data: &[u8]| {
    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let count = usize::from(count & 0x0F);
    if rest.len() < count * 4 {
        return;
    }
    let (csrc_bytes, payload) = rest.split_at(count * 4);
    let csrc: Vec<u32> = csrc_bytes
        .chunks_exact(4)
        .map(|word| u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
        .collect();

    let Ok(header) = FlexFecHeader::parse(&csrc, payload) else {
        return;
    };
    let FlexFecHeader::Repair {
        recovery,
        blocks,
        payload_offset,
    } = header
    else {
        assert_eq!(0x80, payload[0] & 0xC0, "a retransmission is R=1 F=0");
        assert!(payload.len() >= 12);
        return;
    };

    assert_eq!(0, payload[0] & 0x80, "a parity packet is R=0");
    assert_eq!(payload[..8], recovery);
    assert_eq!(csrc.len(), blocks.len());
    assert!(payload_offset <= payload.len());
    assert!(payload_offset >= 8 + 4 * blocks.len());
    assert!(payload_offset <= 8 + 16 * blocks.len());

    let mut protected = 0;
    for (block, ssrc) in blocks.iter().zip(&csrc) {
        assert_eq!(*ssrc, block.ssrc);
        let offsets = block.offsets();
        assert!(offsets.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            block.span(),
            offsets.last().map_or(0, |&last| u32::from(last) + 1)
        );
        assert_eq!(offsets.len(), block.sequence_numbers().len());
        match block.protected {
            FlexFecProtected::Mask(_) => assert!(block.span() <= FLEXFEC_MAX_MASK_BITS),
            FlexFecProtected::Fixed { l, d } => {
                assert_ne!(0, l, "L=0 is never accepted");
                assert_eq!(
                    offsets.len(),
                    if d <= 1 {
                        usize::from(l)
                    } else {
                        usize::from(d)
                    }
                );
            }
        }
        protected += offsets.len();
    }
    assert!(protected > 0, "a parsed repair header protects something");
});
