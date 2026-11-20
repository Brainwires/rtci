//! SCTP recovery-flush scaling benchmark: the time to retransmit one chunk at a time out of an
//! in-flight window of 128, 1024 and 4096 messages, by T3-rtx and by fast retransmit.
//!
//! Formerly the ignored `benchmark_recovery_flushes` test. Run in release mode:
//! `cargo run --release -p rtc-sctp --example sctp_recovery_bench --features bench`

#[cfg(feature = "bench")]
fn main() {
    for count in [128, 1024, 4096] {
        for fast in [false, true] {
            let elapsed =
                rtc_sctp::fuzzing::bench_recovery_flushes(count, fast).expect("recovery window");
            println!("recovery-bench fast={fast} window={count} elapsed_ns={elapsed}");
        }
    }
}

#[cfg(not(feature = "bench"))]
fn main() {
    eprintln!("build with --features bench");
}
