//! A decoder in a child process (`codec::isolated`): a frame that aborts rav1d 1.1.0 costs that
//! frame, not the process.
//!
//! The child is this test binary itself, started with `RTC_VIDEO_TEST_CHILD` set: the test
//! `child_process_entry` then serves (or decodes in process) instead of testing.
//!
//! Test data (`tests/data`): `clean-stream.ivf`, 12 temporal units of 96x64 AV1 from rav1e 0.8.1
//! (speed 10, low latency, 150 kbit/s); `rav1d-abort.ivf`, its key frame with bit 6 of byte 4
//! flipped, which aborts rav1d 1.1.0 with one frame context (memorysafety/rav1d issue 1497;
//! 711 of the 19,352 single-bit flips of that key frame do, docs/video-pipeline.md 4.6).

use std::process::Command;

use rtci_video::codec::av1::Av1Decoder;
use rtci_video::codec::isolated::{IsolatedDecoder, serve};
use rtci_video::decoder::{DecodeError, VideoDecoder};
use rtci_video::frame::Codec;

const CHILD: &str = "RTC_VIDEO_TEST_CHILD";

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn ivf_units(d: &[u8]) -> Vec<Vec<u8>> {
    let mut at = u16::from_le_bytes([d[6], d[7]]) as usize;
    let mut out = Vec::new();
    while at + 12 <= d.len() {
        let n = u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]) as usize;
        at += 12;
        out.push(d[at..at + n].to_vec());
        at += n;
    }
    out
}

/// The child's side. Not a test of its own: it returns at once unless started as a child.
#[test]
fn child_process_entry() {
    match std::env::var(CHILD).as_deref() {
        Ok("serve-av1") => {
            let mut d = Av1Decoder::new().expect("decoder");
            let r = serve(
                &mut d,
                Codec::Av1,
                std::io::stdin().lock(),
                std::io::stdout().lock(),
                std::time::Instant::now(),
            );
            std::process::exit(i32::from(r.is_err()));
        }
        Ok("in-process") => {
            // The reproducer decoded in this process, as an application without isolation would.
            let mut d = Av1Decoder::new().expect("decoder");
            for unit in ivf_units(&data("rav1d-abort.ivf")) {
                let _ = d.decode_bytes(&unit, true);
            }
            std::process::exit(0);
        }
        _ => {}
    }
}

/// This test binary, running only the test `entry`, in `role`.
fn child_running(entry: &str, role: &str) -> Command {
    let mut c = Command::new(std::env::current_exe().expect("test binary"));
    c.args([entry, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, role);
    c
}

fn child(role: &str) -> Command {
    child_running("child_process_entry", role)
}

/// Without isolation the reproducer ends the process: what the isolated decoder must survive.
#[test]
fn the_reproducer_aborts_rav1d_in_process() {
    let status = child("in-process")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run");
    println!("MEASURE isolation: in-process decode of the reproducer: {status}");
    assert!(!status.success(), "rav1d 1.1.0 no longer aborts: {status}");
}

/// Through the child the stream decodes to exactly the pictures of an in-process decoder.
#[test]
fn an_isolated_decoder_gives_the_pictures_of_the_decoder_in_process() {
    let units = ivf_units(&data("clean-stream.ivf"));
    assert_eq!(units.len(), 12);
    let mut local = Av1Decoder::new().expect("decoder");
    let mut isolated = IsolatedDecoder::new(child("serve-av1"), "rav1d (isolated)");
    for (i, unit) in units.iter().enumerate() {
        let a = local.decode_bytes(unit, i == 0).expect("local decode");
        let b = isolated
            .decode_bytes(unit, i == 0)
            .expect("isolated decode");
        assert_eq!(a, b, "unit {i}");
        assert!(a.is_some(), "unit {i}: a picture per temporal unit");
        let (pa, pb) = (
            local.picture().expect("local"),
            isolated.picture().expect("isolated"),
        );
        assert_eq!((pa.width, pa.height), (96, 64));
        assert!(pa.rows().eq(pb.rows()), "unit {i}: same pixels");
    }
    assert_eq!(isolated.restarts(), 0);
    assert_eq!(isolated.implementation_name(), "rav1d (isolated)");
}

/// The reproducer kills the child, the call returns an error, and the next key frame decodes in
/// a new child to the same picture as before.
#[test]
fn a_frame_that_aborts_rav1d_costs_only_the_decoder_process() {
    let units = ivf_units(&data("clean-stream.ivf"));
    let hostile = ivf_units(&data("rav1d-abort.ivf")).remove(0);
    let mut d = IsolatedDecoder::new(child("serve-av1"), "rav1d (isolated)");

    d.decode_bytes(&units[0], true)
        .expect("key frame")
        .expect("picture");
    let before: Vec<u8> = d
        .picture()
        .expect("picture")
        .rows()
        .flatten()
        .copied()
        .collect();
    d.decode_bytes(&units[1], false).expect("delta frame");

    let r = d.decode_bytes(&hostile, true);
    println!("MEASURE isolation: hostile frame through the isolated decoder: {r:?}");
    assert!(
        matches!(&r, Err(DecodeError::Corrupt(m)) if m.starts_with("decoder process ended")),
        "{r:?}"
    );
    assert_eq!(d.restarts(), 1);
    assert!(d.picture().is_none());

    // A new child: a delta frame first needs a key frame, then the key frame decodes as before.
    assert_eq!(
        d.decode_bytes(&units[2], false),
        Err(DecodeError::NeedKeyFrame)
    );
    d.decode_bytes(&units[0], true)
        .expect("key frame")
        .expect("picture");
    let after: Vec<u8> = d
        .picture()
        .expect("picture")
        .rows()
        .flatten()
        .copied()
        .collect();
    assert_eq!(before, after);
    assert_eq!(d.restarts(), 1);
}

/// A child that never answers is killed after the timeout, and replaced.
#[test]
fn a_hung_decoder_process_is_killed_after_the_timeout() {
    // A child that never writes the protocol header.
    let mut d = IsolatedDecoder::new(child_running("hang_role", "hang"), "hang");
    d.set_timeout(std::time::Duration::from_millis(500));
    let start = std::time::Instant::now();
    let r = d.decode_bytes(&[0x12, 0x00], true);
    let took = start.elapsed();
    println!("MEASURE isolation: hung child: {r:?} after {took:?}");
    assert!(
        matches!(&r, Err(DecodeError::Corrupt(m)) if m.starts_with("decoder process timed out")),
        "{r:?}"
    );
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
    assert_eq!(d.restarts(), 1);
}

/// The child of the hung-decoder test: sleeps without writing anything. Not a test of its own.
#[test]
fn hang_role() {
    if std::env::var(CHILD).as_deref() == Ok("hang") {
        std::thread::sleep(std::time::Duration::from_secs(30));
        std::process::exit(0);
    }
}
