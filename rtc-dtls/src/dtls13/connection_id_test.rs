//! Connection ids in DTLS 1.3 (RFC 9147 section 9, on the `connection_id` extension of RFC
//! 9146): negotiation, the id in every protected record, NewConnectionId and
//! RequestConnectionId, and when an association follows its peer to a new address.

use super::handshake_test::*;
use crate::config::{ConfigBuilder, DtlsVersion};
use bytes::BytesMut;
use shared::error::Result;
use std::net::SocketAddr;

fn dtls13(builder: ConfigBuilder, connection_id: Option<usize>) -> ConfigBuilder {
    builder
        .with_protocol_versions(DtlsVersion::Dtls1_3, DtlsVersion::Dtls1_3)
        .with_connection_id(connection_id)
}

fn pair(client: Option<usize>, server: Option<usize>) -> Result<Pair> {
    Ok(Pair::new(
        dtls13(client_builder(), client),
        dtls13(server_builder(), server).with_cookie_exchange(false),
    )?
    .complete())
}

fn connection_ids(pair: &mut Pair) -> ((Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>)) {
    let ids = |conn: &crate::conn::DTLSConn| {
        let (local, remote) = conn.connection_ids().expect("a DTLS 1.3 association");
        (local.to_vec(), remote.to_vec())
    };
    (
        ids(pair.client.connection_mut(&server_addr()).unwrap()),
        ids(pair.server.connection_mut(&client_addr()).unwrap()),
    )
}

/// The first byte and the connection id of the first record of `datagram`, if it is a
/// protected record with the C bit.
fn connection_id_of(datagram: &[u8], length: usize) -> Option<&[u8]> {
    (datagram[0] & 0xf0 == 0x30).then(|| &datagram[1..1 + length])
}

#[test]
fn connection_ids_are_negotiated_and_carried_in_every_protected_record() -> Result<()> {
    let mut pair = Pair::new(
        dtls13(client_builder(), Some(4)),
        dtls13(server_builder(), Some(6)).with_cookie_exchange(false),
    )?;
    let (_, server_flight) = pair.round();
    let (client_flight, ack) = pair.round();
    assert!(pair.client_complete && pair.server_complete);
    let ((client_local, client_remote), (server_local, server_remote)) = connection_ids(&mut pair);
    assert_eq!((client_local.len(), server_local.len()), (4, 6));
    assert_eq!(client_local, server_remote);
    assert_eq!(server_local, client_remote);

    // RFC 9147 section 9.1: from the first protected record on, each side's records carry
    // the id the other asked for. The ServerHello is in the clear and has none.
    assert_eq!(server_flight[0][0], 22);
    let after_server_hello =
        13 + u16::from_be_bytes([server_flight[0][11], server_flight[0][12]]) as usize;
    assert_eq!(
        connection_id_of(&server_flight[0][after_server_hello..], 4),
        Some(&client_local[..])
    );
    assert_eq!(
        connection_id_of(&client_flight[0], 6),
        Some(&server_local[..])
    );
    assert_eq!(connection_id_of(&ack[0], 4), Some(&client_local[..]));

    pair.client
        .write(pair.now, server_addr(), b"with a connection id")?;
    let data = take(&mut pair.client);
    assert_eq!(data[0][0], 0x3f, "C, S and L set, epoch 3");
    assert_eq!(&data[0][1..7], &server_local[..]);

    // A record under another connection id is not this association's (section 4).
    let mut other = data[0].clone();
    other[1] ^= 0xff;
    pair.to_server.clear();
    pair.deliver_to_server(vec![other]);
    assert!(pair.to_server.is_empty());
    pair.deliver_to_server(data);
    assert_eq!(
        application_data(&pair.to_server),
        vec![b"with a connection id".to_vec()]
    );
    assert_eq!(pair.server_sends(b"back"), vec![b"back".to_vec()]);
    Ok(())
}

#[test]
fn a_side_can_ask_for_no_connection_id_and_a_side_can_leave_the_extension_out() -> Result<()> {
    // The client offers the extension and wants no id itself; the server wants one.
    let mut pair = pair(Some(0), Some(5))?;
    let ((client_local, client_remote), (server_local, _)) = connection_ids(&mut pair);
    assert!(client_local.is_empty());
    assert_eq!(client_remote, server_local);
    pair.client.write(pair.now, server_addr(), b"up")?;
    let up = take(&mut pair.client);
    assert_eq!(up[0][0], 0x3f);
    pair.deliver_to_server(up);
    pair.server.write(pair.now, client_addr(), b"down")?;
    let down = take(&mut pair.server);
    assert_eq!(down[0][0], 0x2f, "no connection id towards the client");
    pair.deliver_to_client(down);
    assert_eq!(application_data(&pair.to_client), vec![b"down".to_vec()]);
    // A side that receives no connection id has none to renew, and one that sends none
    // has none to ask for (section 9).
    assert!(
        pair.client
            .new_connection_ids(pair.now, server_addr(), 1, false)
            .is_err()
    );
    assert!(
        pair.server
            .request_connection_ids(pair.now, client_addr(), 1)
            .is_err()
    );

    // Only one side uses the extension: nothing is negotiated.
    // (`Some(0)` is the default.)
    for (client, server) in [(Some(4), None), (None, Some(4)), (None, None)] {
        let mut pair = pair_of(client, server)?;
        let ((client_local, client_remote), (server_local, server_remote)) =
            connection_ids(&mut pair);
        assert!(client_local.is_empty() && client_remote.is_empty());
        assert!(server_local.is_empty() && server_remote.is_empty());
        assert!(
            pair.client
                .new_connection_ids(pair.now, server_addr(), 1, false)
                .is_err()
        );
        assert!(
            pair.client
                .request_connection_ids(pair.now, server_addr(), 1)
                .is_err()
        );
        assert_eq!(pair.client_sends(b"plain"), vec![b"plain".to_vec()]);
    }

    // A hello that also offers DTLS 1.2 leaves the extension out: the DTLS 1.2 record
    // format of RFC 9146 is not implemented.
    let both = client_builder()
        .with_connection_id(Some(4))
        .build(true, None)?;
    assert_eq!(both.connection_id, None);
    Ok(())
}

fn pair_of(client: Option<usize>, server: Option<usize>) -> Result<Pair> {
    pair(client, server)
}

/// RFC 9147 section 9: NewConnectionId hands the peer further ids, spare or to be used at
/// once, and RequestConnectionId asks for some.
#[test]
fn connection_ids_are_renewed_and_requested() -> Result<()> {
    let mut pair = pair(Some(4), Some(4))?;
    let ((client_first, _), _) = connection_ids(&mut pair);

    // Spare ids: the server keeps them, and goes on with the one it has until it chooses.
    pair.client
        .new_connection_ids(pair.now, server_addr(), 2, false)?;
    // One NewConnectionId at a time.
    assert!(
        pair.client
            .new_connection_ids(pair.now, server_addr(), 1, false)
            .is_err()
    );
    pair.run();
    assert_eq!(
        pair.client_conn().unacknowledged_post_handshake_messages(),
        0
    );
    let (_, (_, server_remote)) = connection_ids(&mut pair);
    assert_eq!(server_remote, client_first);
    assert!(
        pair.server
            .connection_mut(&client_addr())
            .unwrap()
            .use_next_connection_id()
    );
    let (_, (_, server_remote)) = connection_ids(&mut pair);
    assert_ne!(server_remote, client_first, "a spare id is in use");
    assert_eq!(
        pair.server_sends(b"under a spare id"),
        vec![b"under a spare id".to_vec()]
    );

    // cid_immediate: the peer uses one of the new ids for every record from then on.
    pair.client
        .new_connection_ids(pair.now, server_addr(), 1, true)?;
    pair.run();
    let (_, (_, immediate)) = connection_ids(&mut pair);
    assert_ne!(immediate, server_remote);
    assert_eq!(
        pair.server_sends(b"under the new id"),
        vec![b"under the new id".to_vec()]
    );

    // RequestConnectionId: the server answers with that many spare ids, and until it has,
    // a second request is not made.
    pair.client
        .request_connection_ids(pair.now, server_addr(), 3)?;
    assert!(
        pair.client
            .request_connection_ids(pair.now, server_addr(), 1)
            .is_err()
    );
    pair.run();
    let mut spares = 0;
    while pair
        .client
        .connection_mut(&server_addr())
        .unwrap()
        .use_next_connection_id()
    {
        spares += 1;
    }
    assert_eq!(spares, 3);
    assert_eq!(
        pair.client_sends(b"under a requested id"),
        vec![b"under a requested id".to_vec()]
    );
    pair.client
        .request_connection_ids(pair.now, server_addr(), 1)?;
    Ok(())
}

/// RFC 9146 section 6: the address an association sends to changes only for a record that is
/// authentic and newer than any received before, and only where the application has said it
/// can tell that the new address receives.
#[test]
fn an_association_follows_its_peer_to_a_new_address_only_for_a_newer_authentic_record() -> Result<()>
{
    let moved: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 7000));
    let elsewhere: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 7001));
    for migration in [true, false] {
        let mut pair = Pair::new(
            dtls13(client_builder(), Some(4)),
            dtls13(server_builder(), Some(4))
                .with_cookie_exchange(false)
                .with_connection_id_migration(migration),
        )?
        .complete();
        pair.client.write(pair.now, server_addr(), b"first")?;
        let first = take(&mut pair.client);
        pair.deliver_to_server(first.clone());

        // A replay of that record from another address moves nothing.
        let events = pair
            .server
            .read(pair.now, elsewhere, None, first[0].clone())?;
        assert!(events.is_empty());
        assert!(pair.server.connection_mut(&elsewhere).is_none());
        // Neither does a forgery under the right connection id.
        let mut forged = first[0].clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let _ = pair.server.read(pair.now, elsewhere, None, forged);
        assert!(pair.server.connection_mut(&elsewhere).is_none());
        assert!(pair.server.connection_mut(&client_addr()).is_some());

        // A new record from a new address.
        pair.client.write(pair.now, server_addr(), b"second")?;
        let second = take(&mut pair.client);
        let events = pair.server.read(pair.now, moved, None, second[0].clone())?;
        if migration {
            assert_eq!(application_data(&events), vec![b"second".to_vec()]);
            assert!(pair.server.connection_mut(&client_addr()).is_none());
            assert!(pair.server.connection_mut(&moved).is_some());
            // What the server sends now goes to the new address.
            pair.server.write(pair.now, moved, b"to the new address")?;
            let transmit = pair.server.poll_transmit().unwrap();
            assert_eq!(transmit.transport.peer_addr, moved);
            pair.deliver_to_client(vec![transmit.message]);
            assert_eq!(
                application_data(&pair.to_client),
                vec![b"to the new address".to_vec()]
            );
        } else {
            assert!(events.is_empty());
            assert!(pair.server.connection_mut(&moved).is_none());
            assert!(pair.server.connection_mut(&client_addr()).is_some());
            let _ = BytesMut::new();
        }
    }
    Ok(())
}
