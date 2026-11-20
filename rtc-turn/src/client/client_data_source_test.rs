//! Relayed peer data is believed from the TURN server holding the allocation only, not from a
//! separately configured STUN server.
use super::test_server::*;
use super::*;
use sansio::Protocol;

#[test]
fn test_data_indication_from_the_stun_server_is_ignored() -> Result<()> {
    let stun_server: SocketAddr = "127.0.0.1:3479".parse().unwrap();
    assert_ne!(stun_server, server_addr());
    let mut client = Client::new(
        ClientConfig {
            stun_serv_addr: stun_server.to_string(),
            turn_serv_addr: server_addr().to_string(),
            local_addr: local_addr(),
            transport_protocol: TransportProtocol::UDP,
            username: USERNAME.to_owned(),
            password: PASSWORD.to_owned(),
            ..Default::default()
        },
        test_crypto_provider(),
    )?;

    let indication = |from: SocketAddr| -> Result<TransportMessage<BytesMut>> {
        let mut msg = Message::new();
        msg.build(&[
            Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
            Box::new(TransactionId::new()),
            Box::new(PeerAddress {
                ip: "10.0.0.1".parse().unwrap(),
                port: 5000,
            }),
            Box::new(Data(b"hello".to_vec())),
        ])?;
        Ok(TransportMessage {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: local_addr(),
                peer_addr: from,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(&msg.raw[..]),
        })
    };

    client.handle_read(indication(stun_server)?)?;
    assert!(
        client.poll_event().is_none(),
        "a Data indication from the STUN server was delivered as relayed data"
    );

    client.handle_read(indication(server_addr())?)?;
    assert!(
        matches!(
            client.poll_event(),
            Some(Event::DataIndicationOrChannelData(None, peer, _))
                if peer == "10.0.0.1:5000".parse::<SocketAddr>().unwrap()
        ),
        "a Data indication from the TURN server is still delivered"
    );

    client.close()
}

/// When the STUN and TURN servers are one address, that address is the TURN server.
#[test]
fn test_data_indication_from_a_shared_server_address_is_delivered() -> Result<()> {
    let mut client = Client::new(
        ClientConfig {
            stun_serv_addr: server_addr().to_string(),
            turn_serv_addr: server_addr().to_string(),
            local_addr: local_addr(),
            transport_protocol: TransportProtocol::UDP,
            ..Default::default()
        },
        test_crypto_provider(),
    )?;

    let mut msg = Message::new();
    msg.build(&[
        Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
        Box::new(TransactionId::new()),
        Box::new(PeerAddress {
            ip: "10.0.0.1".parse().unwrap(),
            port: 5000,
        }),
        Box::new(Data(b"hello".to_vec())),
    ])?;
    client.handle_read(TransportMessage {
        now: Instant::now(),
        transport: TransportContext {
            local_addr: local_addr(),
            peer_addr: server_addr(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(&msg.raw[..]),
    })?;
    assert!(matches!(
        client.poll_event(),
        Some(Event::DataIndicationOrChannelData(None, _, _))
    ));

    client.close()
}
