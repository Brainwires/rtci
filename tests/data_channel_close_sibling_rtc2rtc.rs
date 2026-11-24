//! A channel closed on one side while the peer still sends on it, beside a healthy channel of
//! the same association (webrtc-rs/rtc#340).
//!
//! The receiver reads every stream that became readable in one pass over a datagram and keeps
//! the messages of that pass in one list. A message that reached the closed channel's stream
//! (its reset not complete yet) used to make the read of that stream fail, and the error ended
//! the pass and dropped the list: the messages already read from the other streams were lost,
//! after SCTP had acknowledged them, so a reliable, ordered channel silently lost messages.
//! It needs a message of the healthy channel and one of the closed channel in one datagram,
//! the healthy one first, which bundling produces when the two are sent alternately.

mod dc_common;

use anyhow::{Result, ensure};
use bytes::BytesMut;
use dc_common::Pair;
use rtci::data_channel::RTCDataChannelId;
use rtci::peer_connection::transport::RTCDtlsRole;
use std::time::Duration;

/// Messages sent on the healthy channel (as many again on the closed one).
const COUNT: u32 = 300;

/// Opens `label` from the offerer and returns its handle there and the answerer's handle.
fn open(p: &mut Pair, label: &str) -> Result<(RTCDataChannelId, RTCDataChannelId)> {
    let offerer = p.offerer.pc.create_data_channel(label, None)?.id();
    let before = p.answerer.opened().len();
    ensure!(
        p.run_until(
            |p| p.offerer.opened().contains(&offerer) && p.answerer.opened().len() > before
        )?,
        "{label} never opened"
    );
    let answerer = *p.answerer.opened().last().expect("opened");
    Ok((offerer, answerer))
}

/// The answerer closes channel M; the offerer, before it has heard of that, sends numbered
/// messages on channel L and something on M, alternately. Every message of L arrives, in
/// order; those of M may be dropped.
#[test]
fn a_channel_closed_by_the_receiver_takes_no_message_of_another_channel_with_it() -> Result<()> {
    for round in 0..4 {
        let (mut p, _control) = Pair::connected(RTCDtlsRole::Client, "control")?;
        let (l_offerer, l_answerer) = open(&mut p, "l")?;
        let (m_offerer, m_answerer) = open(&mut p, "m")?;

        p.answerer
            .pc
            .data_channel(m_answerer)
            .expect("m on the answerer")
            .close()?;
        let now = p.now;
        for i in 0..COUNT {
            let mut l = p.offerer.pc.data_channel(l_offerer).expect("l");
            l.send(now, BytesMut::from(&i.to_be_bytes()[..]))?;
            if let Some(mut m) = p.offerer.pc.data_channel(m_offerer) {
                // The channel may be closing by now: what it refuses is of no interest.
                let _ = m.send(now, BytesMut::from(&b"m"[..]));
            }
            // Some rounds move the clock between sends, so the datagrams cut the alternating
            // messages at different places.
            if round % 2 == 1 && i % 7 == 0 {
                p.run_for(Duration::from_millis(1))?;
            }
        }

        let received = |p: &Pair| -> Vec<u32> {
            p.answerer
                .received
                .iter()
                .filter(|(id, _, _)| *id == l_answerer)
                .map(|(_, _, data)| u32::from_be_bytes(data[..4].try_into().expect("4 bytes")))
                .collect()
        };
        p.run_until(|p| received(p).len() >= COUNT as usize && p.answerer.closed(m_answerer))?;
        let got = received(&p);
        assert_eq!(
            got,
            (0..COUNT).collect::<Vec<_>>(),
            "round {round}: channel l lost or reordered messages ({} of {COUNT} arrived)",
            got.len()
        );
        assert!(
            p.answerer.closed(m_answerer),
            "round {round}: the close of m completes"
        );
        assert!(
            !p.answerer.closed(l_answerer) && !p.offerer.closed(l_offerer),
            "round {round}: l stays open"
        );
    }
    Ok(())
}
