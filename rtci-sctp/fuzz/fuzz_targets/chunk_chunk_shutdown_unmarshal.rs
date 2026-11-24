#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_sctp::fuzzing::chunk_chunk_shutdown_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = chunk_chunk_shutdown_unmarshal(data);
});
