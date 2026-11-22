//! The identification-tags of a remote description (RFC 5888 section 4, RFC 9429 section
//! 5.8.2): a mid is a token and names one media section. A description that breaks either is
//! refused before anything is applied.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::shared::error::Error;

fn offer(first: &str, second: &str) -> String {
    crlf(&format!(
        "{SESSION}a=group:BUNDLE {first}
m=audio 9 UDP/TLS/RTP/SAVPF 111
{TRANSPORT}a=mid:{first}
a=sendrecv
a=rtpmap:111 opus/48000/2
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:{second}
a=sendrecv
a=rtpmap:96 VP8/90000
"
    ))
}

#[test]
fn a_remote_description_that_repeats_a_mid_is_refused() -> TestResult {
    let mut pc = default_peer()?;
    let refused = pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer("0", "0"))?,
    );
    assert!(
        matches!(&refused, Err(Error::SdpInvalidValue(why)) if why.contains("a=mid:0")),
        "{refused:?}"
    );
    assert!(pc.remote_description().is_none());
    assert_eq!(pc.get_transceivers().count(), 0);

    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer("0", "1"))?,
    )?;
    assert_eq!(pc.get_transceivers().count(), 2);
    Ok(())
}

#[test]
fn a_mid_that_is_not_a_token_is_refused() -> TestResult {
    for mid in ["a b", "a\"b", "a,b", "caf\u{e9}"] {
        let mut pc = default_peer()?;
        let refused = pc.set_remote_description(
            Instant::now(),
            RTCSessionDescription::offer(offer("0", mid))?,
        );
        assert!(
            matches!(refused, Err(Error::SdpInvalidValue(_))),
            "mid {mid:?}: {refused:?}"
        );
        assert!(pc.remote_description().is_none());
    }
    // Every token character is fine.
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(offer("0", "v!#$%&'*+-.^_`{|}~1"))?,
    )?;
    Ok(())
}
