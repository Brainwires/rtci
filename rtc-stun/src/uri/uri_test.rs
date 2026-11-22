use super::*;

#[test]
fn test_parse_uri() -> Result<()> {
    let tests = vec![
        (
            "default",
            "stun:example.org",
            Uri {
                host: "example.org".to_owned(),
                scheme: SCHEME.to_owned(),
                port: None,
            },
            "stun:example.org",
        ),
        (
            "secure",
            "stuns:example.org",
            Uri {
                host: "example.org".to_owned(),
                scheme: SCHEME_SECURE.to_owned(),
                port: None,
            },
            "stuns:example.org",
        ),
        (
            "with port",
            "stun:example.org:8000",
            Uri {
                host: "example.org".to_owned(),
                scheme: SCHEME.to_owned(),
                port: Some(8000),
            },
            "stun:example.org:8000",
        ),
        (
            "ipv6 address",
            "stun:[::1]:123",
            Uri {
                host: "::1".to_owned(),
                scheme: SCHEME.to_owned(),
                port: Some(123),
            },
            "stun:[::1]:123",
        ),
    ];

    for (name, input, output, expected_str) in tests {
        let out = Uri::parse_uri(input)?;
        assert_eq!(out, output, "{name}: {out} != {output}");
        assert_eq!(out.to_string(), expected_str, "{name}");
    }

    //"MustFail"
    {
        let tests = vec![
            ("hierarchical", "stun://example.org"),
            ("bad scheme", "tcp:example.org"),
            ("invalid uri scheme", "stun_s:test"),
        ];
        for (name, input) in tests {
            let result = Uri::parse_uri(input);
            assert!(result.is_err(), "{name} should fail, but did not");
        }
    }

    Ok(())
}

/// RFC 7064 section 3.1 (RFC 3986 IP-literal): an IPv6 host is written in brackets, so what
/// `Display` writes parses back to the same URI.
#[test]
fn test_an_ipv6_host_is_displayed_in_brackets() -> Result<()> {
    for input in [
        "stun:[2001:db8:1:2:3:4:5:6]:3478",
        "stuns:[2001:db8:1:2:3:4:5:6]",
    ] {
        let uri = Uri::parse_uri(input)?;
        assert_eq!(uri.host, "2001:db8:1:2:3:4:5:6");
        assert_eq!(uri.to_string(), input);
        assert_eq!(Uri::parse_uri(&uri.to_string())?, uri);
    }
    Ok(())
}

/// RFC 8489 section 8.1: the default port is 3478 for `stun` and 5349 for `stuns`.
#[test]
fn test_default_ports() -> Result<()> {
    assert_eq!(Uri::parse_uri("stun:example.org")?.port_or_default(), 3478);
    assert_eq!(Uri::parse_uri("stuns:example.org")?.port_or_default(), 5349);
    assert_eq!(
        Uri::parse_uri("stuns:example.org:8443")?.port_or_default(),
        8443
    );
    Ok(())
}

/// RFC 8489 section 8.1: "A 'stuns' URI containing an IP address MUST be rejected". The strict
/// parser does; `parse_uri` keeps accepting it, as browsers do.
#[test]
fn test_strict_parser_rejects_stuns_with_an_ip_address() -> Result<()> {
    for input in [
        "stuns:192.0.2.1",
        "stuns:192.0.2.1:5349",
        "stuns:[2001:db8::1]:5349",
    ] {
        assert_eq!(Uri::parse_uri_strict(input), Err(Error::ErrHost), "{input}");
        let lenient = Uri::parse_uri(input)?;
        assert!(lenient.is_secure() && lenient.host_is_ip());
    }
    for input in [
        "stuns:example.org",
        "stun:192.0.2.1",
        "stun:[2001:db8::1]:3478",
    ] {
        assert_eq!(Uri::parse_uri_strict(input)?, Uri::parse_uri(input)?);
    }
    Ok(())
}

/// RFC 8489 section 8.1: a domain name is resolved through SRV records whose service is the
/// scheme and whose protocol is the transport; an IP address is not looked up.
#[test]
fn test_srv_query_name_is_scheme_and_transport() -> Result<()> {
    use shared::TransportProtocol;

    let stun = Uri::parse_uri("stun:example.org")?;
    assert_eq!(
        stun.srv_query_name(TransportProtocol::UDP).as_deref(),
        Some("_stun._udp.example.org")
    );
    assert_eq!(
        stun.srv_query_name(TransportProtocol::TCP).as_deref(),
        Some("_stun._tcp.example.org")
    );
    let stuns = Uri::parse_uri("stuns:example.org:5349")?;
    assert_eq!(
        stuns.srv_query_name(TransportProtocol::TCP).as_deref(),
        Some("_stuns._tcp.example.org")
    );
    assert_eq!(
        stuns.srv_query_name(TransportProtocol::UDP).as_deref(),
        Some("_stuns._udp.example.org"),
        "STUN over DTLS"
    );
    for literal in ["stun:192.0.2.1", "stun:[2001:db8::1]:3478"] {
        assert_eq!(
            Uri::parse_uri(literal)?.srv_query_name(TransportProtocol::UDP),
            None
        );
    }
    Ok(())
}
