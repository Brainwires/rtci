#![no_main]
//! Differential target: the replay windows DTLS (RFC 6347 section 4.1.2.6) and SRTP / SRTCP
//! (RFC 3711 section 3.3.2) use, against a reference model.
//!
//! The first bytes pick the detector, its window size and its sequence space. Each op checks a
//! sequence number (a fuzzed one, or a small step from the newest) and, if the op says so,
//! accepts it, as a receiver does once the packet authenticates. The non-wrapping detector is
//! compared with a model that remembers every accepted number: it must accept exactly what the
//! model accepts. For both detectors a number just accepted must be refused when it is checked
//! again: a replay inside the window is a finding.

use libfuzzer_sys::fuzz_target;
use rtci_shared::replay_detector::{
    ReplayDetector, SlidingWindowDetector, WrappedSlidingWindowDetector,
};
use std::collections::BTreeSet;

/// DTLS's sequence space: a 48-bit record sequence number.
const DTLS_MAX_SEQ: u64 = (1 << 48) - 1;

/// The non-wrapping window, written the obvious way.
struct Model {
    window: u64,
    max: u64,
    latest: u64,
    accepted: BTreeSet<u64>,
    pending: Option<u64>,
}

impl Model {
    fn check(&mut self, seq: u64) -> bool {
        self.pending = None;
        if seq > self.max {
            return false;
        }
        if seq <= self.latest && (self.latest - seq >= self.window || self.accepted.contains(&seq))
        {
            return false;
        }
        self.pending = Some(seq);
        true
    }

    fn accept(&mut self) {
        let Some(seq) = self.pending.take() else {
            return;
        };
        self.accepted.insert(seq);
        self.latest = self.latest.max(seq);
        // Anything this far behind is refused by the window check; forget it.
        let floor = self.latest.saturating_sub(self.window);
        self.accepted = self.accepted.split_off(&floor);
    }
}

fn byte(data: &[u8], i: usize) -> u8 {
    data.get(i).copied().unwrap_or(0)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let config = data[0];
    let window = 1 + (usize::from(u16::from_be_bytes([data[1], data[2]])) % 1024);
    let mut data = &data[3..];

    let wrapped = config & 0x01 != 0;
    let max = if wrapped {
        if config & 0x02 == 0 {
            u64::from(u16::MAX)
        } else {
            (1 << 31) - 1
        }
    } else {
        DTLS_MAX_SEQ
    };
    let mut detector: Box<dyn ReplayDetector> = if wrapped {
        Box::new(WrappedSlidingWindowDetector::new(window, max))
    } else {
        Box::new(SlidingWindowDetector::new(window, max))
    };
    let mut model = Model {
        window: window as u64,
        max,
        latest: 0,
        accepted: BTreeSet::new(),
        pending: None,
    };

    let mut newest = 0u64;
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 4096 {
            break;
        }
        let seq = if op & 0x80 != 0 {
            // A fuzzed number, eight bytes, inside or just past the sequence space.
            let mut raw = [0u8; 8];
            for (i, b) in raw.iter_mut().enumerate() {
                *b = byte(data, i);
            }
            data = data.get(8..).unwrap_or(&[]);
            u64::from_be_bytes(raw) % (max + 2)
        } else {
            // A step around the newest accepted number, the shape real traffic has.
            let step = u64::from(op & 0x1f);
            if op & 0x20 == 0 {
                newest.saturating_add(step)
            } else {
                newest.saturating_sub(step)
            }
        };

        let ok = detector.check(seq);
        if !wrapped {
            assert_eq!(
                ok,
                model.check(seq),
                "window decision differs from the model for {seq}"
            );
        }
        if ok && op & 0x40 == 0 {
            detector.accept();
            if !wrapped {
                model.accept();
            }
            newest = seq;
            assert!(!detector.check(seq), "sequence number {seq} accepted twice");
            if !wrapped {
                model.check(seq);
            }
        }
    }
});
