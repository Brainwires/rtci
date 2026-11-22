//! Connection ids in DTLS 1.2 (RFC 9146): the `connection_id` extension, the `tls12_cid`
//! record and its protection, what a receiver discards, and when an association follows its
//! peer to a new address.

use crate::cipher_suite::CipherSuiteId;
use crate::config::{ConfigBuilder, DtlsVersion};
use crate::content::ContentType;
use crate::dtls13::handshake_test::{
    Pair, application_data, client_addr, client_builder, server_addr, server_builder, take,
};
use crate::extension::EXTENSION_CONNECTION_ID;
use bytes::BytesMut;
use shared::error::Result;
use std::net::SocketAddr;

const TLS12_CID: u8 = 25;

fn dtls12(builder: ConfigBuilder, connection_id: Option<usize>) -> ConfigBuilder {
    builder
        .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
        .with_connection_id(connection_id)
}

fn pair(client: Option<usize>, server: Option<usize>) -> Result<Pair> {
    Ok(Pair::new(
        dtls12(client_builder(), client),
        dtls12(server_builder(), server),
    )?
    .complete())
}

/// (local, remote) at the client, then at the server; `None` where nothing was negotiated.
type Ids = Option<(Vec<u8>, Vec<u8>)>;

fn connection_ids(pair: &mut Pair) -> (Ids, Ids) {
    let ids = |conn: &crate::conn::DTLSConn| {
        conn.connection_ids()
            .map(|(local, remote)| (local.to_vec(), remote.to_vec()))
    };
    (
        ids(pair.client.connection_mut(&server_addr()).unwrap()),
        ids(pair.server.connection_mut(&client_addr()).unwrap()),
    )
}

/// The records of a DTLS 1.2 datagram whose `tls12_cid` records carry `cid_length` bytes of
/// connection id: (content type, connection id, the whole record).
fn records(datagram: &[u8], cid_length: usize) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    let mut out = vec![];
    let mut rest = datagram;
    while !rest.is_empty() {
        let header = if rest[0] == TLS12_CID {
            13 + cid_length
        } else {
            13
        };
        let length = u16::from_be_bytes([rest[header - 2], rest[header - 1]]) as usize;
        let cid = if rest[0] == TLS12_CID {
            rest[11..11 + cid_length].to_vec()
        } else {
            vec![]
        };
        out.push((rest[0], cid, rest[..header + length].to_vec()));
        rest = &rest[header + length..];
    }
    out
}

/// The extension types of the ClientHello in the first record of `datagram`.
fn client_hello_extension_types(datagram: &[u8]) -> Vec<u16> {
    assert_eq!(datagram[0], ContentType::Handshake as u8);
    assert_eq!(datagram[13], 1, "a ClientHello");
    let body = &datagram[13 + 12..];
    let mut at = 2 + 32;
    at += 1 + body[at] as usize; // session id
    at += 1 + body[at] as usize; // cookie
    at += 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize; // cipher suites
    at += 1 + body[at] as usize; // compression methods
    let end = at + 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 2;
    let mut types = vec![];
    while at < end {
        types.push(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 4 + u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
    }
    types
}

/// RFC 9146 sections 3 and 4: with the extension in both hellos, every protected record a
/// side sends is a `tls12_cid` record with the id the receiver asked for, after the
/// sequence number; the content type is inside the protection. Every cipher family.
#[test]
fn connection_ids_are_negotiated_and_carried_in_tls12_cid_records() -> Result<()> {
    for suite in [
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
    ] {
        let mut pair = Pair::new(
            dtls12(client_builder(), Some(4)).with_cipher_suites(vec![suite]),
            dtls12(server_builder(), Some(6))
                .with_cipher_suites(vec![suite])
                .with_cookie_exchange(false),
        )?;
        let (_, server_flight) = pair.round();
        let (client_flight, server_final) = pair.round();
        assert!(pair.client_complete && pair.server_complete, "{suite}");
        let (client, server) = connection_ids(&mut pair);
        let ((client_local, client_remote), (server_local, server_remote)) =
            (client.unwrap(), server.unwrap());
        assert_eq!((client_local.len(), server_local.len()), (4, 6));
        assert_eq!(client_local, server_remote);
        assert_eq!(server_local, client_remote);
        // The server's first flight is in the clear.
        assert!(
            server_flight
                .iter()
                .flat_map(|datagram| records(datagram, 4))
                .all(|(content_type, _, _)| content_type == ContentType::Handshake as u8)
        );
        // The client's Finished, and the server's, are tls12_cid records with the
        // receiver's id; the ChangeCipherSpec in front of each is not protected.
        let types = |datagrams: &[BytesMut], cid_length: usize| {
            datagrams
                .iter()
                .flat_map(|datagram| records(datagram, cid_length))
                .map(|(content_type, cid, _)| (content_type, cid))
                .collect::<Vec<_>>()
        };
        let up = types(&client_flight, 6);
        assert_eq!(
            up.last(),
            Some(&(TLS12_CID, server_local.clone())),
            "{suite}"
        );
        assert_eq!(up[up.len() - 2].0, ContentType::ChangeCipherSpec as u8);
        let down = types(&server_final, 4);
        assert_eq!(
            down,
            vec![
                (ContentType::ChangeCipherSpec as u8, vec![]),
                (TLS12_CID, client_local.clone())
            ],
            "{suite}"
        );

        pair.client
            .write(pair.now, server_addr(), b"with a connection id")?;
        let data = take(&mut pair.client);
        assert_eq!(data[0][0], TLS12_CID);
        assert_eq!(&data[0][11..17], &server_local[..]);
        pair.deliver_to_server(data);
        assert_eq!(
            application_data(&pair.to_server),
            vec![b"with a connection id".to_vec()],
            "{suite}"
        );
        assert_eq!(
            pair.server_sends(b"back"),
            vec![b"back".to_vec()],
            "{suite}"
        );
    }
    Ok(())
}

/// RFC 9146 section 3: an empty id means "send me none"; a side without the extension
/// negotiates nothing, and its records stay ordinary.
#[test]
fn an_empty_connection_id_or_a_missing_extension_keeps_ordinary_records() -> Result<()> {
    // The client wants none; the server wants one.
    let mut pair = pair(Some(0), Some(5))?;
    let (client, server) = connection_ids(&mut pair);
    let (client_local, client_remote) = client.unwrap();
    assert!(client_local.is_empty());
    assert_eq!(client_remote, server.unwrap().0);
    pair.client.write(pair.now, server_addr(), b"up")?;
    let up = take(&mut pair.client);
    assert_eq!(up[0][0], TLS12_CID);
    pair.deliver_to_server(up);
    assert_eq!(application_data(&pair.to_server), vec![b"up".to_vec()]);
    pair.server.write(pair.now, client_addr(), b"down")?;
    let down = take(&mut pair.server);
    assert_eq!(down[0][0], ContentType::ApplicationData as u8);
    pair.deliver_to_client(down);
    assert_eq!(application_data(&pair.to_client), vec![b"down".to_vec()]);

    for (client, server) in [(Some(4), None), (None, Some(4)), (None, None)] {
        let mut pair = pair_of(client, server)?;
        assert_eq!(
            connection_ids(&mut pair),
            (None, None),
            "{client:?} {server:?}"
        );
        pair.client.write(pair.now, server_addr(), b"plain")?;
        let up = take(&mut pair.client);
        assert_eq!(up[0][0], ContentType::ApplicationData as u8);
        pair.deliver_to_server(up);
        assert_eq!(application_data(&pair.to_server), vec![b"plain".to_vec()]);
    }
    Ok(())
}

fn pair_of(client: Option<usize>, server: Option<usize>) -> Result<Pair> {
    pair(client, server)
}

/// RFC 9146 sections 3 and 4: a record under another connection id, a protected record
/// without the id this side asked for, and a `tls12_cid` record in epoch 0 are not this
/// association's, and are dropped without an alert; the association goes on.
#[test]
fn records_without_the_negotiated_connection_id_are_discarded() -> Result<()> {
    let mut pair = pair(Some(4), Some(4))?;
    pair.client.write(pair.now, server_addr(), b"genuine")?;
    let genuine = take(&mut pair.client);
    let record = genuine[0].clone();

    // Another connection id.
    let mut other = record.clone();
    other[11] ^= 0xff;
    // The same record with its id taken out and its ordinary type put back: what a peer that
    // ignored the negotiation would send.
    let mut without = BytesMut::from(&record[..11]);
    without[0] = ContentType::ApplicationData as u8;
    without.extend_from_slice(&record[15..]);
    // A tls12_cid record in epoch 0.
    let mut epoch_zero = record.clone();
    epoch_zero[3] = 0;
    epoch_zero[4] = 0;

    pair.to_server.clear();
    for forged in [other, without, epoch_zero] {
        pair.deliver_to_server(vec![forged]);
        assert!(pair.server_error.is_none());
        assert!(take(&mut pair.server).is_empty(), "no alert");
        assert!(!pair.server.is_connection_failed(&client_addr()));
    }
    assert!(application_data(&pair.to_server).is_empty());
    pair.deliver_to_server(genuine);
    assert_eq!(application_data(&pair.to_server), vec![b"genuine".to_vec()]);
    Ok(())
}

/// RFC 9146 section 3, RFC 9147 section 5.1: a ClientHello that offers DTLS 1.3 and 1.2
/// carries one `connection_id` extension for both, and a DTLS 1.2 server that negotiates
/// with it uses the id of that offer.
#[test]
fn a_hello_for_both_versions_carries_one_connection_id_and_falls_back_with_it() -> Result<()> {
    let mut pair = Pair::new(
        client_builder().with_connection_id(Some(4)),
        dtls12(server_builder(), Some(3)).with_cookie_exchange(false),
    )?;
    let hello = take(&mut pair.client);
    let types = client_hello_extension_types(&hello[0]);
    assert_eq!(
        types
            .iter()
            .filter(|extension_type| **extension_type == EXTENSION_CONNECTION_ID)
            .count(),
        1,
        "{types:?}"
    );
    pair.deliver_to_server(hello);
    let mut pair = pair.complete();
    assert_eq!(
        pair.versions(),
        (Some(DtlsVersion::Dtls1_2), Some(DtlsVersion::Dtls1_2))
    );
    let (client, server) = connection_ids(&mut pair);
    let ((client_local, client_remote), (server_local, server_remote)) =
        (client.unwrap(), server.unwrap());
    assert_eq!(client_local.len(), 4);
    assert_eq!(server_remote, client_local);
    assert_eq!(client_remote, server_local);
    assert_eq!(pair.client_sends(b"up"), vec![b"up".to_vec()]);
    assert_eq!(pair.server_sends(b"down"), vec![b"down".to_vec()]);

    // By default a dual hello asks for no id (`Some(0)`), and still carries the extension.
    let mut pair = Pair::new(client_builder(), server_builder())?;
    let hello = take(&mut pair.client);
    assert!(client_hello_extension_types(&hello[0]).contains(&EXTENSION_CONNECTION_ID));
    Ok(())
}

/// A protected record that arrives ahead of the flight that makes it readable is held and
/// read afterwards (RFC 6347 4.1), with its connection id.
#[test]
fn an_early_tls12_cid_record_is_held_until_it_can_be_read() -> Result<()> {
    let mut pair = Pair::new(
        dtls12(client_builder(), Some(4)),
        dtls12(server_builder(), Some(4)).with_cookie_exchange(false),
    )?;
    pair.round();
    let client_final = take(&mut pair.client);
    pair.deliver_to_server(client_final);
    assert!(pair.server_complete);
    let server_final = take(&mut pair.server);
    pair.server.write(pair.now, client_addr(), b"early")?;
    let early = take(&mut pair.server);
    assert_eq!(early[0][0], TLS12_CID);
    pair.deliver_to_client(early);
    assert!(!pair.client_complete);
    assert!(application_data(&pair.to_client).is_empty());
    pair.deliver_to_client(server_final);
    assert!(pair.client_complete);
    assert_eq!(application_data(&pair.to_client), vec![b"early".to_vec()]);
    Ok(())
}

/// RFC 9146 section 6: the address an association sends to changes only for a record that
/// is authentic and newer than any received before, and only where the application allows
/// it (`with_connection_id_migration`, off by default).
#[test]
fn a_dtls12_association_follows_its_peer_only_for_a_newer_authentic_record() -> Result<()> {
    let moved: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 7100));
    let elsewhere: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 7101));
    for migration in [true, false] {
        let mut pair = Pair::new(
            dtls12(client_builder(), Some(4)),
            dtls12(server_builder(), Some(4)).with_connection_id_migration(migration),
        )?
        .complete();
        pair.client.write(pair.now, server_addr(), b"first")?;
        let first = take(&mut pair.client);
        pair.client.write(pair.now, server_addr(), b"second")?;
        let second = take(&mut pair.client);
        // The newer record is read at the old address first.
        pair.deliver_to_server(second);

        // An authentic but older record from another address moves nothing.
        let events = pair
            .server
            .read(pair.now, elsewhere, None, first[0].clone())?;
        if migration {
            assert_eq!(application_data(&events), vec![b"first".to_vec()]);
        }
        assert!(pair.server.connection_mut(&elsewhere).is_none());
        // Neither does a forgery under the right connection id.
        pair.client.write(pair.now, server_addr(), b"third")?;
        let third = take(&mut pair.client);
        let mut forged = third[0].clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let _ = pair.server.read(pair.now, elsewhere, None, forged);
        assert!(pair.server.connection_mut(&elsewhere).is_none());
        assert!(pair.server.connection_mut(&client_addr()).is_some());

        // A newer authentic record from a new address.
        let events = pair.server.read(pair.now, moved, None, third[0].clone())?;
        if migration {
            assert_eq!(application_data(&events), vec![b"third".to_vec()]);
            assert!(pair.server.connection_mut(&client_addr()).is_none());
            assert!(pair.server.connection_mut(&moved).is_some());
            pair.server.write(pair.now, moved, b"to the new address")?;
            let transmit = pair.server.poll_transmit().unwrap();
            assert_eq!(transmit.transport.peer_addr, moved);
            pair.deliver_to_client(vec![transmit.message]);
            assert_eq!(
                application_data(&pair.to_client),
                vec![b"to the new address".to_vec()]
            );
        } else {
            assert!(pair.server.connection_mut(&moved).is_none());
            assert!(pair.server.connection_mut(&client_addr()).is_some());
        }
    }
    Ok(())
}

/// Serialising an association keeps its connection ids (`State::serialize`).
#[test]
fn a_serialized_dtls12_state_keeps_its_connection_ids() -> Result<()> {
    let mut pair = pair(Some(4), Some(2))?;
    let state = pair.client.get_connection_state(server_addr()).unwrap();
    let bytes = state.marshal_binary()?;
    let mut restored = crate::state::State::new(crate::dtls13::handshake_test::provider(), true);
    restored.unmarshal_binary(&bytes)?;
    assert_eq!(restored.send_connection_id(), state.send_connection_id());
    assert_eq!(
        restored.receive_connection_id(),
        state.receive_connection_id()
    );
    assert!(restored.receive_connection_id().is_some());
    let _ = connection_ids(&mut pair);
    Ok(())
}

/// RFC 9146 section 5: the DTLSInnerPlaintext of a `tls12_cid` record is at most 2^14
/// bytes. A write that would make it longer is refused; a record that opens to more ends
/// the association with record_overflow.
#[test]
fn a_tls12_cid_record_holds_at_most_two_to_the_fourteen_inner_bytes() -> Result<()> {
    use super::{MAX_RECORD_PAYLOAD, Packet};
    use crate::application_data::ApplicationData;
    use crate::content::Content;
    use crate::record_layer::RecordLayer;
    use crate::record_layer::record_layer_header::PROTOCOL_VERSION1_2;

    let mut pair = pair(Some(4), Some(4))?;
    assert!(
        pair.client
            .write(pair.now, server_addr(), &vec![0x11; MAX_RECORD_PAYLOAD])
            .is_err()
    );
    assert_eq!(
        pair.client_sends(&vec![0x22; MAX_RECORD_PAYLOAD - 1]),
        vec![vec![0x22; MAX_RECORD_PAYLOAD - 1]]
    );

    // A sender that ignores the limit: 2^14 bytes of content, and its type.
    let conn = pair.client.connection_mut(&server_addr()).unwrap();
    let epoch = conn.get_local_epoch();
    let oversize = conn.process_packet(Packet {
        record: RecordLayer::new(
            PROTOCOL_VERSION1_2,
            epoch,
            Content::ApplicationData(ApplicationData {
                data: BytesMut::from(&vec![0x33; MAX_RECORD_PAYLOAD][..]),
            }),
        ),
        should_encrypt: true,
        reset_local_sequence_number: false,
    })?;
    assert_eq!(oversize[0], TLS12_CID);
    pair.to_server.clear();
    pair.deliver_to_server(vec![BytesMut::from(&oversize[..])]);
    assert!(application_data(&pair.to_server).is_empty());
    assert!(pair.server.is_connection_failed(&client_addr()));
    Ok(())
}
