//! The DTLS 1.3 cookie exchange over a link that loses chosen datagrams (RFC 9147 sections
//! 5.1 and 5.8): a ClientHello too long for one datagram (the X25519MLKEM768 hybrid key
//! share, or a small MTU), whose HelloRetryRequest, fragments, second ClientHello or the
//! server's flight are lost. A server MUST answer a ClientHello without a valid cookie with a
//! HelloRetryRequest every time, and a repeated flight with its answer again; the handshake
//! completes as soon as one copy of each flight gets through.
//!
//! A lossy-link run of the whole stack found it: with the hybrid share the server endpoint
//! hands a fragmented ClientHello to an association that runs the cookie exchange itself, and
//! that association sent its HelloRetryRequest once and forgot it; when it was lost, every
//! retransmitted ClientHello was taken for a repeat and answered with nothing, until the
//! handshake deadline.

use super::handshake_test::*;
use super::messages::HELLO_RETRY_REQUEST_RANDOM;
use super::record::CONTENT_TYPE_HANDSHAKE;
use crate::config::{ConfigBuilder, DtlsVersion};
use crate::crypto::Certificate;
use bytes::BytesMut;
use crypto::RTCCryptoProvider;
use shared::error::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// What the first record of a datagram is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    /// A plaintext ClientHello fragment: its message_seq and fragment offset.
    ClientHello {
        message_seq: u16,
        offset: usize,
    },
    HelloRetryRequest,
    /// The ServerHello, which starts the server's flight.
    ServerHello,
    /// Anything else (protected records, ACKs).
    Other,
}

fn kind(datagram: &[u8]) -> Kind {
    if datagram.len() < 59 || datagram[0] != CONTENT_TYPE_HANDSHAKE {
        return Kind::Other;
    }
    match datagram[13] {
        1 => Kind::ClientHello {
            message_seq: u16::from_be_bytes([datagram[17], datagram[18]]),
            offset: usize::from(datagram[19]) << 16
                | usize::from(datagram[20]) << 8
                | usize::from(datagram[21]),
        },
        2 if datagram[27..59] == HELLO_RETRY_REQUEST_RANDOM => Kind::HelloRetryRequest,
        2 => Kind::ServerHello,
        _ => Kind::Other,
    }
}

/// A datagram on its way, for the loss rule to judge.
#[derive(Debug)]
struct Seen {
    from_client: bool,
    kind: Kind,
    /// How many datagrams of this kind, from this side, went before it.
    nth: usize,
    /// Virtual time since the client's first ClientHello.
    elapsed: Duration,
}

/// Runs the handshake of `pair`, dropping each datagram `lose` says to drop and firing each
/// side's timers when nothing is in flight, until both sides have completed. Returns the
/// virtual time it took; an error if it did not complete within `limit` or both sides went
/// quiet with no timer armed.
fn handshake_losing(
    pair: &mut Pair,
    first: Vec<BytesMut>,
    limit: Duration,
    mut lose: impl FnMut(&Seen) -> bool,
) -> std::result::Result<Duration, String> {
    let start = pair.now;
    let mut counts: HashMap<(bool, Kind), usize> = HashMap::new();
    let mut pass = |from_client: bool, datagrams: Vec<BytesMut>, now| -> Vec<BytesMut> {
        datagrams
            .into_iter()
            .filter(|datagram| {
                let kind = kind(datagram);
                let nth = counts.entry((from_client, kind)).or_default();
                let seen = Seen {
                    from_client,
                    kind,
                    nth: *nth,
                    elapsed: now - start,
                };
                *nth += 1;
                !lose(&seen)
            })
            .collect()
    };
    let mut first = Some(first);
    loop {
        loop {
            let mut up = first.take().unwrap_or_default();
            up.extend(take(&mut pair.client));
            let sent_up = !up.is_empty();
            let up = pass(true, up, pair.now);
            pair.deliver_to_server(up);
            let down = take(&mut pair.server);
            let sent_down = !down.is_empty();
            let down = pass(false, down, pair.now);
            pair.deliver_to_client(down);
            if !sent_up && !sent_down {
                break;
            }
        }
        if pair.client_complete && pair.server_complete {
            return Ok(pair.now - start);
        }
        let client_at = pair.client.poll_timeout(&server_addr());
        let server_at = pair.server.poll_timeout(&client_addr());
        let Some(at) = client_at.into_iter().chain(server_at).min() else {
            return Err(format!(
                "stalled after {:?} with no timer armed (client {:?}, server {:?})",
                pair.now - start,
                pair.client_error,
                pair.server_error
            ));
        };
        if at - start > limit {
            return Err(format!(
                "not complete within {limit:?} (client complete: {}, {:?}; server complete: \
                 {}, {:?}; datagrams by kind: {counts:?})",
                pair.client_complete, pair.client_error, pair.server_complete, pair.server_error
            ));
        }
        pair.now = pair.now.max(at);
        if client_at == Some(at) {
            let _ = pair.client.handle_timeout(server_addr(), at);
        }
        if server_at == Some(at) {
            let _ = pair.server.handle_timeout(client_addr(), at);
        }
    }
}

/// A client whose first ClientHello is more than one datagram, and a server with the cookie
/// exchange on (the default), for each crypto backend built: the hybrid key share where the
/// provider has it, a small MTU otherwise.
fn fragmenting_pairs() -> Vec<(&'static str, Pair, Vec<BytesMut>)> {
    fn builders(
        provider: Arc<dyn RTCCryptoProvider>,
        hybrid: bool,
        mtu: Option<usize>,
    ) -> (ConfigBuilder, ConfigBuilder) {
        let mut client = ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_insecure_skip_verify(true)
            .with_post_quantum_key_share(hybrid);
        let mut server = ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_insecure_skip_verify(true)
            .with_post_quantum_key_share(hybrid)
            .with_certificates(vec![
                Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
                    .expect("a certificate"),
            ]);
        if let Some(mtu) = mtu {
            client = client.with_mtu(mtu);
            server = server.with_mtu(mtu);
        }
        (client, server)
    }
    let mut setups: Vec<(&'static str, ConfigBuilder, ConfigBuilder)> = vec![];
    #[cfg(feature = "crypto-ring")]
    {
        let ring: Arc<dyn RTCCryptoProvider> = Arc::new(crypto::providers::RingProvider::new());
        let (client, server) = builders(ring, false, Some(200));
        setups.push(("ring, small MTU", client, server));
    }
    #[cfg(feature = "crypto-aws-lc-rs")]
    {
        let aws: Arc<dyn RTCCryptoProvider> = Arc::new(crypto::providers::AwsLcRsProvider::new());
        let (client, server) = builders(aws.clone(), true, None);
        setups.push(("aws-lc-rs, hybrid key share", client, server));
        let (client, server) = builders(aws, false, Some(200));
        setups.push(("aws-lc-rs, small MTU", client, server));
    }
    setups
        .into_iter()
        .map(|(name, client, server)| {
            let mut pair = Pair::new(client, server).expect("a pair");
            let client_hello = take(&mut pair.client);
            assert!(
                client_hello.len() >= 2,
                "{name}: the first ClientHello takes more than one datagram"
            );
            assert!(
                client_hello
                    .iter()
                    .all(|datagram| matches!(kind(datagram), Kind::ClientHello { .. })),
                "{name}"
            );
            (name, pair, client_hello)
        })
        .collect()
}

fn check(name: &str, result: std::result::Result<Duration, String>, within: Duration) {
    match result {
        Ok(took) => assert!(
            took <= within,
            "{name}: the handshake took {took:?}, more than {within:?}"
        ),
        Err(err) => panic!("{name}: {err}"),
    }
}

/// The first HelloRetryRequest is lost: the client sends its ClientHello again when its timer
/// expires (one second), and the server answers it with the HelloRetryRequest again.
#[test]
fn a_lost_hello_retry_request_is_sent_again_for_the_repeated_client_hello() {
    for (name, mut pair, first) in fragmenting_pairs() {
        let result = handshake_losing(&mut pair, first, Duration::from_secs(300), |seen| {
            seen.kind == Kind::HelloRetryRequest && seen.nth == 0
        });
        check(name, result, Duration::from_secs(5));
        assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_3), "{name}");
        assert_eq!(
            pair.client_sends(b"after"),
            vec![b"after".to_vec()],
            "{name}"
        );
    }
}

/// Twice: 1 + 2 seconds of the client's timer, and the third answer gets through.
#[test]
fn a_hello_retry_request_lost_twice_is_sent_a_third_time() {
    for (name, mut pair, first) in fragmenting_pairs() {
        let result = handshake_losing(&mut pair, first, Duration::from_secs(300), |seen| {
            seen.kind == Kind::HelloRetryRequest && seen.nth < 2
        });
        check(name, result, Duration::from_secs(8));
    }
}

/// One fragment of the first ClientHello is lost (the first, then the last): the server holds
/// the other and puts the message together from the retransmission.
#[test]
fn a_lost_fragment_of_the_first_client_hello_is_made_up_by_the_retransmission() {
    for first_fragment in [true, false] {
        for (name, mut pair, first) in fragmenting_pairs() {
            let result = handshake_losing(&mut pair, first, Duration::from_secs(300), |seen| {
                let Kind::ClientHello {
                    message_seq: 0,
                    offset,
                } = seen.kind
                else {
                    return false;
                };
                // The first transmission only: its fragments are the first few seen.
                seen.elapsed.is_zero() && ((offset == 0) == first_fragment)
            });
            check(name, result, Duration::from_secs(5));
        }
    }
}

/// The second ClientHello, the one with the cookie, is lost: the client sends it again, the
/// server takes it.
#[test]
fn a_lost_second_client_hello_is_sent_again() {
    for (name, mut pair, first) in fragmenting_pairs() {
        let mut lost_at = None;
        let result = handshake_losing(&mut pair, first, Duration::from_secs(300), |seen| {
            if !matches!(seen.kind, Kind::ClientHello { message_seq: 1, .. }) {
                return false;
            }
            // Every fragment of its first transmission.
            *lost_at.get_or_insert(seen.elapsed) == seen.elapsed
        });
        check(name, result, Duration::from_secs(5));
    }
}

/// The server's flight is lost: the client repeats its second ClientHello, which draws the
/// flight again.
#[test]
fn a_lost_server_flight_is_sent_again() {
    for (name, mut pair, first) in fragmenting_pairs() {
        let mut server_hellos = 0;
        let result = handshake_losing(&mut pair, first, Duration::from_secs(300), |seen| {
            if seen.from_client {
                return false;
            }
            if seen.kind == Kind::ServerHello {
                server_hellos += 1;
            }
            // The whole first transmission of the flight.
            server_hellos == 1 && seen.kind != Kind::HelloRetryRequest
        });
        check(name, result, Duration::from_secs(8));
    }
}

/// Everything at once: each of the first two copies of every handshake datagram is lost.
#[test]
fn the_handshake_completes_when_every_flight_is_lost_twice() {
    for (name, mut pair, first) in fragmenting_pairs() {
        let result = handshake_losing(&mut pair, first, Duration::from_secs(300), |seen| {
            seen.kind != Kind::Other && seen.nth < 2
        });
        check(name, result, Duration::from_secs(60));
    }
}

/// The association a server endpoint makes for a fragmented ClientHello holds state for an
/// address nobody has verified: it goes two minutes after the last datagram from that address,
/// whatever the handshake deadline (none by default), and a client that is still there loses
/// nothing by it: its next ClientHello gets a new association and a new HelloRetryRequest.
#[test]
fn an_association_for_an_unverified_address_goes_and_the_handshake_still_completes() {
    for (name, mut pair, first) in fragmenting_pairs() {
        let mut silent = false;
        let result = handshake_losing(&mut pair, first, Duration::from_secs(600), |seen| {
            // The first ClientHello arrives; then nothing of the handshake, either way, for
            // more than two minutes.
            if seen.elapsed.is_zero() && seen.from_client {
                return false;
            }
            let lose = seen.kind != Kind::Other && seen.elapsed < Duration::from_secs(125);
            silent |= lose;
            lose
        });
        check(name, result, Duration::from_secs(300));
        assert!(silent, "{name}");
    }

    // A ClientHello that fits one datagram is answered by the endpoint without state; the
    // second, longer by the cookie, may not fit, and goes to an association that puts it
    // together. That association verifies the endpoint's cookie (it used to know only its
    // own, and refused the client with illegal_parameter).
    let probe = take(
        &mut Pair::new(client_builder(), server_builder())
            .expect("a pair")
            .client,
    );
    assert_eq!(probe.len(), 1);
    let mtu = probe[0].len();
    let mut pair = Pair::new(client_builder().with_mtu(mtu), server_builder()).expect("a pair");
    let (first, retry) = pair.round();
    assert_eq!(first.len(), 1, "the first ClientHello fits");
    assert_eq!(kind(&retry[0]), Kind::HelloRetryRequest);
    assert!(
        pair.server.connection_mut(&client_addr()).is_none(),
        "answered without state"
    );
    let second = take(&mut pair.client);
    assert!(second.len() >= 2, "the second ClientHello does not fit");
    pair.deliver_to_server(second);
    let mut pair = pair.complete();
    assert_eq!(pair.client_sends(b"cookie"), vec![b"cookie".to_vec()]);

    // A lone fragment, never completed: the association goes at the end of its time, and
    // with it every timer of the endpoint for that address.
    for (name, mut pair, first) in fragmenting_pairs() {
        let mut first = first;
        first.truncate(1);
        pair.deliver_to_server(first);
        assert!(
            pair.server.connection_mut(&client_addr()).is_some(),
            "{name}: the fragment is held by an association"
        );
        // Its own timers may fire before (with nothing to send: it has sent nothing); two
        // minutes after the fragment it goes.
        let start = pair.now;
        let mut at = start;
        for _ in 0..256 {
            if pair.server.connection_mut(&client_addr()).is_none() {
                break;
            }
            at = pair
                .server
                .poll_timeout(&client_addr())
                .expect("a timer, its expiry at the latest");
            pair.server
                .handle_timeout(client_addr(), at)
                .expect("an expiry is not an error");
            assert!(
                take(&mut pair.server).is_empty(),
                "{name}: nothing is sent for a ClientHello not yet whole"
            );
        }
        assert_eq!(at - start, Duration::from_secs(120), "{name}");
        assert!(
            pair.server.connection_mut(&client_addr()).is_none(),
            "{name}"
        );
        assert!(
            take(&mut pair.server).is_empty(),
            "{name}: it goes silently"
        );
        assert_eq!(pair.server.poll_timeout(&client_addr()), None, "{name}");
    }
}

/// Where the first ClientHello fits one datagram the endpoint answers it without state: a
/// lost HelloRetryRequest is answered again from the repeated ClientHello there too.
#[test]
fn a_lost_stateless_hello_retry_request_is_sent_again() {
    let mut pair = Pair::new(client_builder(), server_builder()).expect("a pair");
    let result = handshake_losing(&mut pair, vec![], Duration::from_secs(300), |seen| {
        seen.kind == Kind::HelloRetryRequest && seen.nth == 0
    });
    check("one datagram", result, Duration::from_secs(5));
}

/// RFC 9147 section 5.8 and RFC 6347 section 4.2.4 set no total limit on a handshake, and by
/// default neither does this crate: a DTLS 1.3 flight nobody answers goes out at most once a
/// minute for as long as the association lives.
#[test]
fn by_default_a_dtls_1_3_handshake_nobody_answers_is_never_given_up() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?;
    let start = pair.now;
    take(&mut pair.client);
    let mut at = start;
    for _ in 0..100 {
        at = pair
            .client
            .poll_timeout(&server_addr())
            .expect("the retransmission timer stays armed");
        pair.client.handle_timeout(server_addr(), at)?;
        // The ClientHello again: in one datagram, or cut smaller after a few unanswered
        // retransmissions (section 4.4).
        assert!(!take(&mut pair.client).is_empty(), "the ClientHello, again");
        assert!(!pair.client.is_connection_failed(&server_addr()));
    }
    assert!(at - start > Duration::from_secs(90 * 60));
    assert_eq!(
        pair.client.handshake_retransmissions(&server_addr()),
        Some(100),
        "a handshake that goes on shows it"
    );
    Ok(())
}

/// The fragments of the first ClientHello add up across its transmissions, also when the
/// client has cut it smaller after unanswered retransmissions (RFC 9147 section 4.4): the
/// server holds what arrived of one transmission and completes the message from a later one.
#[test]
fn fragments_of_different_transmissions_add_up() {
    for (name, mut pair, first) in fragmenting_pairs() {
        let mut transmission = 0;
        let mut last = None;
        let result = handshake_losing(&mut pair, first, Duration::from_secs(600), |seen| {
            let Kind::ClientHello {
                message_seq: 0,
                offset,
            } = seen.kind
            else {
                return false;
            };
            if last.is_some_and(|last| last != seen.elapsed) {
                transmission += 1;
            }
            last = Some(seen.elapsed);
            // The start of the message from the first transmission, the rest from the fifth,
            // cut for a smaller MTU.
            let keep = (transmission == 0 && offset == 0) || (transmission >= 4 && offset != 0);
            !keep
        });
        check(name, result, Duration::from_secs(60));
    }
}
