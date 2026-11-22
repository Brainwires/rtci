//! `alwaysNegotiateDataChannels` (webrtc-extensions): an offer carries the data channel
//! `m=application` section whether or not a data channel exists, ahead of the media sections
//! the offer adds.

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::sdp::{get_application_media, get_mid_value};

impl RTCPeerConnection {
    /// Sets `alwaysNegotiateDataChannels` (webrtc-extensions). When on, an initial offer puts
    /// the `m=application` section first, and a subsequent offer that has none yet puts it
    /// after the sections already negotiated and before the new ones, with or without a data
    /// channel. Off (the default) offers it, last, only once a data channel exists.
    ///
    /// The W3C member is `RTCConfiguration`'s (`with_always_negotiate_data_channels`), which
    /// cannot change after construction (webrtc-extensions 13.2); this engine setting may
    /// until a description has been set, and is then refused (`InvalidModificationError`).
    pub fn set_always_negotiate_data_channels(
        &mut self,
        always: bool,
    ) -> shared::error::Result<()> {
        if always != self.always_negotiate_data_channels && self.a_description_was_set() {
            return Err(shared::error::Error::InvalidModificationError);
        }
        self.always_negotiate_data_channels = always;
        self.configuration.always_negotiate_data_channels = always;
        Ok(())
    }

    /// Whether `alwaysNegotiateDataChannels` is on.
    pub fn always_negotiate_data_channels(&self) -> bool {
        self.always_negotiate_data_channels
    }

    /// The mid of an `m=application` section an offer adds ahead of others: the one the
    /// pending local offer gave it, or one above every numeric mid in use (the transceivers
    /// have theirs by now, and `greater_mid` covers the remote description's).
    pub(crate) fn added_data_section_mid(&self) -> String {
        if let Some(mid) = self
            .pending_local_description
            .as_ref()
            .and_then(|d| d.parsed.as_ref())
            .and_then(get_application_media)
            .and_then(get_mid_value)
        {
            return mid.clone();
        }
        let mut greatest = self.greater_mid;
        for transceiver in &self.rtp_transceivers {
            if let Some(mid) = transceiver.mid()
                && let Ok(n) = mid.parse::<isize>()
                && n > greatest
            {
                greatest = n;
            }
        }
        greatest.saturating_add(1).to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use crate::peer_connection::configuration::media_engine::MediaEngine;
    use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
    use std::time::Instant;

    fn sections(sdp: &str) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = vec![];
        for line in sdp.lines() {
            if let Some(m) = line.strip_prefix("m=") {
                let kind = m.split(' ').next().unwrap_or_default().to_owned();
                out.push((kind, String::new()));
            } else if let Some(mid) = line.strip_prefix("a=mid:")
                && let Some(last) = out.last_mut()
            {
                last.1 = mid.to_owned();
            }
        }
        out
    }

    #[test]
    fn the_data_section_is_offered_first_without_a_channel() {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .expect("register default codecs");
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(Instant::now())
            .expect("build peer connection");
        pc.set_always_negotiate_data_channels(true).unwrap();

        let offer = pc.create_offer(None).expect("offer");
        let kinds: Vec<String> = sections(&offer.sdp).into_iter().map(|s| s.0).collect();
        assert_eq!(kinds, vec!["application".to_owned()]);

        pc.add_transceiver_from_kind(
            RtpCodecKind::Audio,
            Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
        )
        .expect("audio transceiver");
        let offer = pc.create_offer(None).expect("offer");
        let found = sections(&offer.sdp);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, "application");
        assert_eq!(found[1].0, "audio");
        assert_ne!(
            found[0].1, found[1].1,
            "the data section has a mid of its own"
        );
    }
}
