use super::*;

fn all() -> Vec<HeaderExtension> {
    vec![
        HeaderExtension::AbsSendTime(Default::default()),
        HeaderExtension::AudioLevel(Default::default()),
        HeaderExtension::PlayoutDelay(Default::default()),
        HeaderExtension::TransportCc(Default::default()),
        HeaderExtension::VideoOrientation(Default::default()),
        HeaderExtension::AbsCaptureTime(Default::default()),
        HeaderExtension::CsrcAudioLevel(Default::default()),
        HeaderExtension::Mid(sdes_extension::Mid::new("0").unwrap()),
        HeaderExtension::RtpStreamId(sdes_extension::RtpStreamId::new("h").unwrap()),
        HeaderExtension::RepairedRtpStreamId(
            sdes_extension::RepairedRtpStreamId::new("h").unwrap(),
        ),
        HeaderExtension::TransmissionOffset(Default::default()),
    ]
}

#[test]
fn every_extension_has_its_own_uri_and_is_the_same_as_itself_only() {
    let extensions = all();
    for (i, a) in extensions.iter().enumerate() {
        for (j, b) in extensions.iter().enumerate() {
            assert_eq!(i == j, a.is_same(b), "{a:?} and {b:?}");
            assert_eq!(i == j, a.uri() == b.uri());
        }
    }
}

#[test]
fn two_playout_delays_are_the_same_extension() {
    // `is_same` had no arm for it and said no.
    let a = HeaderExtension::PlayoutDelay(Default::default());
    let b = HeaderExtension::PlayoutDelay(playout_delay_extension::PlayoutDelayExtension {
        min_delay: 1,
        max_delay: 2,
    });
    assert!(a.is_same(&b));
}

#[test]
fn an_extension_marshals_as_its_value_does() {
    for extension in all() {
        let raw = extension.marshal().unwrap();
        assert_eq!(extension.marshal_size(), raw.len(), "{extension:?}");
    }
}
