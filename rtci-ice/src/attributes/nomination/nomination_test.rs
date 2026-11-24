use super::*;
use crate::attributes::use_candidate::UseCandidateAttr;
use shared::error::Result;
use stun::integrity::MessageIntegrity;
use stun::message::BINDING_REQUEST;
use stun::textattrs::TextAttribute;

fn decoded(m: &Message) -> Result<Message> {
    let mut out = Message::new();
    out.write(&m.raw)?;
    Ok(out)
}

#[test]
fn test_nomination_attr_round_trip() -> Result<()> {
    let mut m = Message::new();
    m.build(&[Box::new(BINDING_REQUEST), Box::new(NominationAttr(7))])?;
    let m1 = decoded(&m)?;
    let mut got = NominationAttr::default();
    got.get_from(&m1)?;
    assert_eq!(got, NominationAttr(7));
    Ok(())
}

#[test]
fn test_nomination_attr_wrong_size_is_an_error() -> Result<()> {
    let mut m = Message::new();
    m.build(&[Box::new(BINDING_REQUEST)])?;
    m.add(ATTR_NOMINATION, &[1, 2]);
    let m1 = decoded(&m)?;
    assert!(NominationAttr::default().get_from(&m1).is_err());
    assert_eq!(
        nomination_of(&m1),
        0,
        "a malformed NOMINATION is not a nomination"
    );
    Ok(())
}

#[test]
fn test_nomination_of() -> Result<()> {
    let mut none = Message::new();
    none.build(&[Box::new(BINDING_REQUEST)])?;
    assert_eq!(nomination_of(&decoded(&none)?), 0);

    let mut regular = Message::new();
    regular.build(&[Box::new(BINDING_REQUEST), Box::new(UseCandidateAttr::new())])?;
    assert_eq!(nomination_of(&decoded(&regular)?), 1);

    let mut renominated = Message::new();
    renominated.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(UseCandidateAttr::new()),
        Box::new(NominationAttr(42)),
    ])?;
    assert_eq!(nomination_of(&decoded(&renominated)?), 42);

    // libwebrtc counts NOMINATION on its own as well.
    let mut bare = Message::new();
    bare.build(&[Box::new(BINDING_REQUEST), Box::new(NominationAttr(3))])?;
    assert_eq!(nomination_of(&decoded(&bare)?), 3);
    Ok(())
}

#[test]
fn test_nomination_after_message_integrity_is_ignored() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TextAttribute::new(
            stun::attributes::ATTR_USERNAME,
            "a:b".to_owned(),
        )),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            "pwd".to_owned(),
            crypto::default_provider()
                .expect("a built-in crypto provider must be enabled for tests")
                .crypto(),
        )),
    ])?;
    // Appended past MESSAGE-INTEGRITY: not covered by it.
    m.add(ATTR_USE_CANDIDATE, &[]);
    m.add(ATTR_NOMINATION, &9u32.to_be_bytes());
    assert_eq!(nomination_of(&decoded(&m)?), 0);
    Ok(())
}
