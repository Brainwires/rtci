//! The descriptions webrtc-rs 0.17 writes, offers and answers with every media kind and a data
//! channel, gathered candidates included, are accepted by this engine's remote-description
//! checks with its default settings (RFC 9429 section 5.8: every line parsed by its grammar;
//! RFC 5763 section 5: an answer's `a=setup`; RFC 8859: IDENTICAL-PER-PT attributes in a
//! BUNDLE group).
//!
//! With `RTC_SDP_FIXTURE_DIR` set, each description is also written there, as
//! `webrtc-rs-0.17--<scenario>--<n>-<type>.sdp`: the source of `tests/fixtures/browser-sdp/`'s
//! webrtc-rs files, which `src/peer_connection/sdp/browser_sdp_test.rs` checks without a
//! network.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::time::timeout;

use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine as WebrtcMediaEngine;
use webrtc::interceptor::registry::Registry as WebrtcRegistry;
use webrtc::peer_connection::RTCPeerConnection as WebrtcPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription as WebrtcDescription;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;

mod common;

async fn webrtc_peer() -> Result<Arc<WebrtcPeerConnection>> {
    let mut media_engine = WebrtcMediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(WebrtcRegistry::new(), &mut media_engine)?;
    let api = APIBuilder::new()
        .with_setting_engine(common::webrtc_setting_engine())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();
    Ok(Arc::new(
        api.new_peer_connection(WebrtcConfiguration::default())
            .await?,
    ))
}

fn track(
    mime: &str,
    clock_rate: u32,
    channels: u16,
    id: &str,
) -> Arc<dyn TrackLocal + Send + Sync> {
    Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: mime.to_owned(),
            clock_rate,
            channels,
            ..Default::default()
        },
        id.to_owned(),
        "webrtc-stream".to_owned(),
    ))
}

/// A webrtc peer with an audio and a video track and a data channel.
async fn webrtc_peer_with_media() -> Result<Arc<WebrtcPeerConnection>> {
    let pc = webrtc_peer().await?;
    pc.add_track(track("audio/opus", 48000, 2, "audio")).await?;
    pc.add_track(track("video/VP8", 90000, 0, "video")).await?;
    pc.create_data_channel("data", None).await?;
    Ok(pc)
}

/// The local description of `pc` once its candidates are gathered.
async fn gathered(pc: &WebrtcPeerConnection) -> Result<String> {
    let mut done = pc.gathering_complete_promise().await;
    let _ = timeout(Duration::from_secs(5), done.recv()).await;
    Ok(pc
        .local_description()
        .await
        .ok_or_else(|| anyhow::anyhow!("no local description"))?
        .sdp)
}

fn record(scenario: &str, n: usize, kind: &str, sdp: &str) {
    println!("==== webrtc-rs 0.17, {scenario}, {kind} ====\n{sdp}");
    if let Ok(dir) = std::env::var("RTC_SDP_FIXTURE_DIR") {
        let _ = std::fs::create_dir_all(&dir);
        let path = format!("{dir}/webrtc-rs-0.17--{scenario}--{n}-{kind}.sdp");
        std::fs::write(&path, sdp).expect("the fixture is written");
    }
}

fn rtc_peer() -> Result<rtci::peer_connection::RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

#[tokio::test]
async fn webrtc_0_17_offers_pass_the_remote_description_checks() -> Result<()> {
    common::install_crypto_provider();
    for (scenario, with_media) in [("audio-video-data", true), ("data-only", false)] {
        let pc = if with_media {
            webrtc_peer_with_media().await?
        } else {
            let pc = webrtc_peer().await?;
            pc.create_data_channel("data", None).await?;
            pc
        };
        // A transceiver that only receives, beside the sending ones.
        if with_media {
            pc.add_transceiver_from_kind(RTPCodecType::Video, None)
                .await?;
        }
        // What a trickling application sends (`create_offer`'s text: a feedback without
        // parameters ends with a space) and the description once gathered (re-written with
        // its candidates, without those spaces).
        let offer = pc.create_offer(None).await?;
        pc.set_local_description(offer.clone()).await?;
        let gathered = gathered(&pc).await?;
        for (n, sdp) in [(1, offer.sdp), (2, gathered)] {
            record(scenario, n, "offer", &sdp);
            let mut answerer = rtc_peer()?;
            answerer
                .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp)?)
                .map_err(|e| {
                    anyhow::anyhow!("{scenario} {n}: the webrtc-rs 0.17 offer is refused: {e}")
                })?;
        }
        pc.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn webrtc_0_17_answers_pass_the_remote_description_checks() -> Result<()> {
    common::install_crypto_provider();
    let mut offerer = rtc_peer()?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    offerer.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    offerer.create_data_channel("data", None)?;
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer.clone())?;

    let pc = webrtc_peer_with_media().await?;
    pc.set_remote_description(WebrtcDescription::offer(offer.sdp.clone())?)
        .await?;
    let answer = pc.create_answer(None).await?;
    pc.set_local_description(answer.clone()).await?;
    let gathered = gathered(&pc).await?;
    record("answer-to-rtc-audio-video-data", 1, "answer", &answer.sdp);
    record("answer-to-rtc-audio-video-data", 2, "answer", &gathered);

    // The answer as `create_answer` wrote it is applied (the gathered one is checked by the
    // fixture test, `browser_sdp_test.rs`, which needs no offer of its own).
    offerer
        .set_remote_description(Instant::now(), RTCSessionDescription::answer(answer.sdp)?)
        .map_err(|e| anyhow::anyhow!("the webrtc-rs 0.17 answer is refused: {e}"))?;
    pc.close().await?;
    Ok(())
}
