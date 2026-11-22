use super::*;
use crate::checks::*;
use shared::error::*;

use std::io::BufReader;

#[test]
fn test_software_get_from() -> Result<()> {
    let mut m = Message::new();
    let v = "Client v0.0.1".to_owned();
    m.add(ATTR_SOFTWARE, v.as_bytes());
    m.write_header();

    let mut m2 = Message {
        raw: Vec::with_capacity(256),
        ..Default::default()
    };

    let mut reader = BufReader::new(m.raw.as_slice());
    m2.read_from(&mut reader)?;
    let software = TextAttribute::get_from_as(&m, ATTR_SOFTWARE)?;
    assert_eq!(software.to_string(), v, "Expected {v}, got {software}.");

    let (s_attr, ok) = m.attributes.get(ATTR_SOFTWARE);
    assert!(ok, "sowfware attribute should be found");

    let s = s_attr.to_string();
    assert!(s.starts_with("SOFTWARE:"), "bad string representation {s}");

    Ok(())
}

#[test]
fn test_software_add_to_invalid() -> Result<()> {
    let mut m = Message::new();
    let s = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: String::from_utf8(vec![0; 1024]).unwrap(),
    };
    let result = s.add_to(&mut m);
    if let Err(err) = result {
        assert!(
            is_attr_size_overflow(&err),
            "add_to should return AttrOverflowErr, got: {err}"
        );
    } else {
        panic!("expected error, but got ok");
    }

    let result = TextAttribute::get_from_as(&m, ATTR_SOFTWARE);
    if let Err(err) = result {
        assert_eq!(
            Error::ErrAttributeNotFound,
            err,
            "GetFrom should return {}, got: {}",
            Error::ErrAttributeNotFound,
            err
        );
    } else {
        panic!("expected error, but got ok");
    }

    Ok(())
}

#[test]
fn test_software_add_to_regression() -> Result<()> {
    // s.add_to checked len(m.Raw) instead of len(s.Raw).
    let mut m = Message {
        raw: vec![0u8; 2048],
        ..Default::default()
    };
    let s = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: String::from_utf8(vec![0; 100]).unwrap(),
    };
    s.add_to(&mut m)?;

    Ok(())
}

#[test]
fn test_username() -> Result<()> {
    let username = "username".to_owned();
    let u = TextAttribute {
        attr: ATTR_USERNAME,
        text: username.clone(),
    };
    let mut m = Message::new();
    m.write_header();
    //"Bad length"
    {
        let bad_u = TextAttribute {
            attr: ATTR_USERNAME,
            text: String::from_utf8(vec![0; 600]).unwrap(),
        };
        let result = bad_u.add_to(&mut m);
        if let Err(err) = result {
            assert!(
                is_attr_size_overflow(&err),
                "add_to should return *AttrOverflowErr, got: {err}"
            );
        } else {
            panic!("expected error, but got ok");
        }
    }
    //"add_to"
    {
        u.add_to(&mut m)?;

        //"GetFrom"
        {
            let got = TextAttribute::get_from_as(&m, ATTR_USERNAME)?;
            assert_eq!(
                got.to_string(),
                username,
                "expedted: {username}, got: {got}"
            );
            //"Not found"
            {
                let m = Message::new();
                let result = TextAttribute::get_from_as(&m, ATTR_USERNAME);
                if let Err(err) = result {
                    assert_eq!(Error::ErrAttributeNotFound, err, "Should error");
                } else {
                    panic!("expected error, but got ok");
                }
            }
        }
    }

    //"No allocations"
    {
        let mut m = Message::new();
        m.write_header();
        let u = TextAttribute {
            attr: ATTR_USERNAME,
            text: "username".to_owned(),
        };

        u.add_to(&mut m)?;
        m.reset();
    }

    Ok(())
}

#[test]
fn test_realm_get_from() -> Result<()> {
    let mut m = Message::new();
    let v = "realm".to_owned();
    m.add(ATTR_REALM, v.as_bytes());
    m.write_header();

    let mut m2 = Message {
        raw: Vec::with_capacity(256),
        ..Default::default()
    };

    let result = TextAttribute::get_from_as(&m2, ATTR_REALM);
    if let Err(err) = result {
        assert_eq!(
            Error::ErrAttributeNotFound,
            err,
            "GetFrom should return {}, got: {}",
            Error::ErrAttributeNotFound,
            err
        );
    } else {
        panic!("Expected error, but got ok");
    }

    let mut reader = BufReader::new(m.raw.as_slice());
    m2.read_from(&mut reader)?;

    let r = TextAttribute::get_from_as(&m, ATTR_REALM)?;
    assert_eq!(r.to_string(), v, "Expected {v}, got {r}.");

    let (r_attr, ok) = m.attributes.get(ATTR_REALM);
    assert!(ok, "realm attribute should be found");

    let s = r_attr.to_string();
    assert!(s.starts_with("REALM:"), "bad string representation {s}");

    Ok(())
}

#[test]
fn test_realm_add_to_invalid() -> Result<()> {
    let mut m = Message::new();
    let s = TextAttribute {
        attr: ATTR_REALM,
        text: String::from_utf8(vec![0; 1024]).unwrap(),
    };
    let result = s.add_to(&mut m);
    if let Err(err) = result {
        assert!(
            is_attr_size_overflow(&err),
            "add_to should return AttrOverflowErr, got: {err}"
        );
    } else {
        panic!("expected error, but got ok");
    }

    let result = TextAttribute::get_from_as(&m, ATTR_REALM);
    if let Err(err) = result {
        assert_eq!(
            Error::ErrAttributeNotFound,
            err,
            "GetFrom should return {}, got: {}",
            Error::ErrAttributeNotFound,
            err
        );
    } else {
        panic!("expected error, but got ok");
    }

    Ok(())
}

#[test]
fn test_nonce_get_from() -> Result<()> {
    let mut m = Message::new();
    let v = "example.org".to_owned();
    m.add(ATTR_NONCE, v.as_bytes());
    m.write_header();

    let mut m2 = Message {
        raw: Vec::with_capacity(256),
        ..Default::default()
    };

    let result = TextAttribute::get_from_as(&m2, ATTR_NONCE);
    if let Err(err) = result {
        assert_eq!(
            Error::ErrAttributeNotFound,
            err,
            "GetFrom should return {}, got: {}",
            Error::ErrAttributeNotFound,
            err
        );
    } else {
        panic!("Expected error, but got ok");
    }

    let mut reader = BufReader::new(m.raw.as_slice());
    m2.read_from(&mut reader)?;

    let r = TextAttribute::get_from_as(&m, ATTR_NONCE)?;
    assert_eq!(r.to_string(), v, "Expected {v}, got {r}.");

    let (r_attr, ok) = m.attributes.get(ATTR_NONCE);
    assert!(ok, "realm attribute should be found");

    let s = r_attr.to_string();
    assert!(s.starts_with("NONCE:"), "bad string representation {s}");

    Ok(())
}

#[test]
fn test_nonce_add_to_invalid() -> Result<()> {
    let mut m = Message::new();
    let s = TextAttribute {
        attr: ATTR_NONCE,
        text: String::from_utf8(vec![0; 1024]).unwrap(),
    };
    let result = s.add_to(&mut m);
    if let Err(err) = result {
        assert!(
            is_attr_size_overflow(&err),
            "add_to should return AttrOverflowErr, got: {err}"
        );
    } else {
        panic!("expected error, but got ok");
    }

    let result = TextAttribute::get_from_as(&m, ATTR_NONCE);
    if let Err(err) = result {
        assert_eq!(
            Error::ErrAttributeNotFound,
            err,
            "GetFrom should return {}, got: {}",
            Error::ErrAttributeNotFound,
            err
        );
    } else {
        panic!("expected error, but got ok");
    }

    Ok(())
}

#[test]
fn test_nonce_add_to() -> Result<()> {
    let mut m = Message::new();
    let n = TextAttribute {
        attr: ATTR_NONCE,
        text: "example.org".to_owned(),
    };
    n.add_to(&mut m)?;

    let v = m.get(ATTR_NONCE)?;
    assert_eq!(v.as_slice(), b"example.org", "bad nonce {v:?}");

    Ok(())
}

/// RFC 8489 section 14.3: a USERNAME is fewer than 509 bytes.
#[test]
fn test_username_of_509_bytes_is_refused() -> Result<()> {
    let mut m = Message::new();
    m.write_header();
    TextAttribute::new(ATTR_USERNAME, "u".repeat(508)).add_to(&mut m)?;
    let result = TextAttribute::new(ATTR_USERNAME, "u".repeat(509)).add_to(&mut m);
    assert_eq!(result, Err(Error::ErrAttributeSizeOverflow));
    Ok(())
}

/// RFC 8489 sections 14.9, 14.10 and 14.14: REALM, NONCE and SOFTWARE are fewer than 128
/// characters when sent, which is at most 509 bytes.
#[test]
fn test_realm_nonce_and_software_are_fewer_than_128_characters() {
    for attr in [ATTR_REALM, ATTR_NONCE, ATTR_SOFTWARE] {
        let add = |text: String| {
            let mut m = Message::new();
            m.write_header();
            TextAttribute::new(attr, text).add_to(&mut m)
        };
        assert!(add("x".repeat(127)).is_ok(), "{attr}");
        assert_eq!(
            add("x".repeat(128)),
            Err(Error::ErrAttributeSizeOverflow),
            "{attr}"
        );
        // 127 characters can take 508 bytes.
        assert!(add("\u{1f600}".repeat(127)).is_ok(), "{attr}");
        assert_eq!(
            add("\u{1f600}".repeat(128)),
            Err(Error::ErrAttributeSizeOverflow),
            "{attr}"
        );
    }
}

/// RFC 8489 section 14.3: a USERNAME of up to 763 bytes is parsed, for compatibility with RFC
/// 5389; so are a REALM, a NONCE and a SOFTWARE of that length (sections 14.9, 14.10, 14.14).
#[test]
fn test_text_attributes_of_763_bytes_are_parsed() -> Result<()> {
    for attr in [ATTR_USERNAME, ATTR_REALM, ATTR_NONCE, ATTR_SOFTWARE] {
        let text = "u".repeat(763);
        let mut m = Message::new();
        m.write_header();
        m.add(attr, text.as_bytes());
        let mut decoded = Message::new();
        decoded.unmarshal_binary(&m.raw)?;
        assert_eq!(TextAttribute::get_from_as(&decoded, attr)?.text, text);
    }
    // Not UTF-8: not a text attribute.
    let mut m = Message::new();
    m.write_header();
    m.add(ATTR_USERNAME, &[0xff, 0xfe, 0xfd]);
    assert!(TextAttribute::get_from_as(&m, ATTR_USERNAME).is_err());
    Ok(())
}
