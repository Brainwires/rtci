//! The engine's connection race to a TURN server over TCP (RFC 8305 section 5, RFC 8656
//! section 3.9), driven through the stream interface with no network: the test answers the
//! engine's `Resolve` and `Connect` commands itself, on a virtual clock.

use anyhow::Result;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::transport::RTCIceServer;
use rtci::shared::stream::{StreamCommand, StreamEvent, StreamId};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn connects(commands: &[StreamCommand]) -> Vec<(StreamId, SocketAddr)> {
    commands
        .iter()
        .filter_map(|c| match c {
            StreamCommand::Connect { id, remote, .. } => Some((*id, *remote)),
            _ => None,
        })
        .collect()
}

fn drain(pc: &mut rtci::peer_connection::RTCPeerConnection) -> Vec<StreamCommand> {
    let mut out = vec![];
    while let Some(command) = pc.poll_stream_command() {
        out.push(command);
    }
    out
}

/// RFC 8305 section 5: the attempts to a server's addresses are staggered by the Connection
/// Attempt Delay, but "if the connection attempt fails, the next one starts immediately":
/// the engine connects to the second address of a `turn:...?transport=tcp` server at the
/// instant the first is refused, not 250 ms later.
#[test]
fn a_refused_turn_connection_attempt_starts_the_next_address_at_once() -> Result<()> {
    let start = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec!["turn:turn.example:3478?transport=tcp".to_owned()],
                    username: "user".to_owned(),
                    credential: "pass".to_owned(),
                }])
                .build(),
        )
        .build(start)?;
    pc.create_data_channel("race", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(start, offer)?;

    let query = drain(&mut pc)
        .into_iter()
        .find_map(|c| match c {
            StreamCommand::Resolve { query, host, port } => {
                assert_eq!((host.as_str(), port), ("turn.example", 3478));
                Some(query)
            }
            _ => None,
        })
        .expect("the server's name is resolved through the driver");
    let first: SocketAddr = "192.0.2.1:3478".parse()?;
    let second: SocketAddr = "192.0.2.2:3478".parse()?;
    pc.handle_stream_event(
        start,
        StreamEvent::Resolved {
            query,
            addresses: vec![first, second],
        },
    )?;
    let attempts = connects(&drain(&mut pc));
    assert_eq!(
        attempts.iter().map(|(_, a)| *a).collect::<Vec<_>>(),
        vec![first],
        "one attempt at a time (section 5)"
    );

    // 10 ms later the first attempt is refused: the second starts then, well inside the
    // 250 ms delay.
    let refused = start + Duration::from_millis(10);
    pc.handle_stream_event(refused, StreamEvent::ConnectFailed { id: attempts[0].0 })?;
    let next = connects(&drain(&mut pc));
    assert_eq!(
        next.iter().map(|(_, a)| *a).collect::<Vec<_>>(),
        vec![second],
        "the next address is tried as soon as the first failed"
    );
    Ok(())
}
