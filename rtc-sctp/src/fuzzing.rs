//! Entry points for fuzz targets and benchmarks.
//!
//! Each function drives one encode or decode step over a raw byte slice, so a fuzzer or a
//! benchmark can reach the packet codec without establishing an association first. Gated behind
//! `cfg(fuzzing)` or the `bench` feature; not part of the supported API and not subject to the
//! crate's stability guarantees.
#![allow(missing_docs)] // one-line codec entry points; the module doc covers them
use bytes::Bytes;
use shared::error::Result;

use crate::chunk::Chunk;
use crate::chunk::ErrorCause;
use crate::chunk::chunk_abort::ChunkAbort;
use crate::chunk::chunk_cookie_ack::ChunkCookieAck;
use crate::chunk::chunk_cookie_echo::ChunkCookieEcho;
use crate::chunk::chunk_error::ChunkError;
use crate::chunk::chunk_forward_tsn::{ChunkForwardTsn, ChunkForwardTsnStream};
use crate::chunk::chunk_header::ChunkHeader;
use crate::chunk::chunk_heartbeat::ChunkHeartbeat;
use crate::chunk::chunk_heartbeat_ack::ChunkHeartbeatAck;
use crate::chunk::chunk_init::ChunkInit;
use crate::chunk::chunk_payload_data::ChunkPayloadData;
use crate::chunk::chunk_reconfig::ChunkReconfig;
use crate::chunk::chunk_selective_ack::ChunkSelectiveAck;
use crate::chunk::chunk_shutdown::ChunkShutdown;
use crate::chunk::chunk_shutdown_ack::ChunkShutdownAck;
use crate::chunk::chunk_shutdown_complete::ChunkShutdownComplete;
use crate::chunk::chunk_unknown::ChunkUnknown;
use crate::packet::{Packet, PartialDecode};
use crate::param::Param;
use crate::param::param_add_streams_request::ParamAddStreamsRequest;
use crate::param::param_chunk_list::ParamChunkList;
use crate::param::param_forward_tsn_supported::ParamForwardTsnSupported;
use crate::param::param_header::ParamHeader;
use crate::param::param_heartbeat_info::ParamHeartbeatInfo;
use crate::param::param_incoming_reset_request::ParamIncomingResetRequest;
use crate::param::param_outgoing_reset_request::ParamOutgoingResetRequest;
use crate::param::param_random::ParamRandom;
use crate::param::param_reconfig_response::ParamReconfigResponse;
use crate::param::param_requested_hmac_algorithm::ParamRequestedHmacAlgorithm;
use crate::param::param_ssn_tsn_reset_request::ParamSsnTsnResetRequest;
use crate::param::param_state_cookie::ParamStateCookie;
use crate::param::param_supported_extensions::ParamSupportedExtensions;
use crate::param::param_uknown::ParamUnknown;

fn to_bytes(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(data)
}

pub fn packet_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = Packet::unmarshal(&raw)?;
    Ok(())
}

/// Differential/roundtrip helper: unmarshal a raw SCTP packet and marshal it
/// back to the wire. Exposed so fuzzers and benchmarks can exercise the
/// marshalling path (which is otherwise `pub(crate)`).
pub fn packet_marshal(data: &[u8]) -> Result<Vec<u8>> {
    let pkt = Packet::unmarshal(&to_bytes(data))?;
    Ok(pkt.marshal()?.to_vec())
}

/// Build the wire bytes of a representative DATA packet carrying `num_chunks`
/// payload-data chunks of `payload_len` bytes each. Used to seed marshalling
/// micro-benchmarks with a valid (correctly check-summed) packet.
#[doc(hidden)]
pub fn sample_data_packet(payload_len: usize, num_chunks: usize) -> Vec<u8> {
    use crate::chunk::chunk_payload_data::PayloadProtocolIdentifier;
    use crate::packet::CommonHeader;

    let chunks: Vec<Box<dyn Chunk>> = (0..num_chunks)
        .map(|i| {
            Box::new(ChunkPayloadData {
                beginning_fragment: true,
                ending_fragment: true,
                tsn: i as u32 + 1,
                stream_identifier: 0,
                stream_sequence_number: i as u16,
                payload_type: PayloadProtocolIdentifier::Binary,
                user_data: Bytes::from(vec![0x42u8; payload_len]),
                ..Default::default()
            }) as Box<dyn Chunk>
        })
        .collect();

    let pkt = Packet {
        common_header: CommonHeader {
            source_port: 5000,
            destination_port: 5000,
            verification_tag: 0x1234_5678,
        },
        chunks,
    };
    pkt.marshal().unwrap().to_vec()
}

/// Marshal a fixed, pre-parsed packet `iterations` times into a fresh buffer.
/// Isolated marshalling micro-benchmark surface for `perf`/`poop` (parsing is
/// done once, outside the timed loop).
#[doc(hidden)]
pub fn bench_packet_marshal(data: &[u8], iterations: u64) -> Result<usize> {
    use crate::packet::PACKET_HEADER_SIZE;
    use bytes::BytesMut;

    let pkt = Packet::unmarshal(&to_bytes(data))?;
    let mut last = 0;
    for _ in 0..iterations {
        let mut buf = BytesMut::with_capacity(data.len() + PACKET_HEADER_SIZE);
        last = pkt.marshal_to(&mut buf)?;
        std::hint::black_box(&buf);
    }
    Ok(last)
}

pub fn packet_partial_decode_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = PartialDecode::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_header_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeader::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_abort_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkAbort::unmarshal(&raw)?;
    Ok(())
}

/// A chunk of a type the engine does not recognize is kept as it arrived (RFC 9260 3.2): it
/// must parse whatever its type and be written back as it was read.
pub fn chunk_chunk_unknown_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let chunk = ChunkUnknown::unmarshal(&raw)?;
    let written = chunk.marshal()?;
    assert_eq!(&raw[..written.len()], &written[..]);
    let _ = (chunk.stops_processing(), chunk.is_reported());
    Ok(())
}

pub fn chunk_chunk_cookie_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkCookieAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_cookie_echo_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkCookieEcho::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_error_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkError::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_forward_tsn_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkForwardTsn::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_forward_tsn_stream_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkForwardTsnStream::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_heartbeat_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeartbeat::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_heartbeat_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeartbeatAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_init_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkInit::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_payload_data_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkPayloadData::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_reconfig_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkReconfig::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_selective_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkSelectiveAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdown::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdownAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_complete_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdownComplete::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_error_cause_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ErrorCause::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_header_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamHeader::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_forward_tsn_supported_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamForwardTsnSupported::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_supported_extensions_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamSupportedExtensions::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_random_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamRandom::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_requested_hmac_algorithm_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamRequestedHmacAlgorithm::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_chunk_list_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamChunkList::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_state_cookie_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamStateCookie::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_heartbeat_info_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamHeartbeatInfo::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_outgoing_reset_request_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamOutgoingResetRequest::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_reconfig_response_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamReconfigResponse::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_incoming_reset_request_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamIncomingResetRequest::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_ssn_tsn_reset_request_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamSsnTsnResetRequest::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_add_streams_request_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamAddStreamsRequest::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_unknown_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamUnknown::unmarshal(&raw)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_data_packet_roundtrips() {
        // sample_data_packet builds a valid, check-summed packet; packet_marshal
        // unmarshals then re-marshals it, so the bytes must round-trip exactly.
        let pkt = sample_data_packet(1200, 2);
        assert_eq!(packet_marshal(&pkt).unwrap(), pkt);
        // exercise the perf-harness entry point as well.
        assert!(bench_packet_marshal(&pkt, 3).is_ok());
    }
}

/// Rewrites the CRC-32C field (bytes 8..12) of a raw SCTP packet so it verifies. Without this a
/// fuzzer almost never gets past the checksum to the chunk parsers.
pub fn fix_checksum(data: &[u8]) -> Vec<u8> {
    let mut packet = data.to_vec();
    if packet.len() >= 12 {
        packet[8..12].fill(0);
        let checksum = crc32c::crc32c(&packet);
        packet[8..12].copy_from_slice(&checksum.to_le_bytes());
    }
    packet
}

/// [`packet_unmarshal`] on a packet whose checksum has been made valid.
pub fn packet_unmarshal_fixed_checksum(data: &[u8]) -> Result<()> {
    packet_unmarshal(&fix_checksum(data))
}

/// Stateful target: drives a server endpoint, and the association it accepts, with a sequence of
/// datagrams. The input is split into datagrams by a 2-byte big-endian length prefix; each gets
/// a valid checksum. Every association event, timer and transmit is drained so the whole receive
/// path (INIT handling, DATA, SACK, FORWARD-TSN, RECONFIG, ...) is reachable. `start` is the
/// base instant (sans-I/O: the harness supplies the time).
pub fn endpoint_handle_datagrams(mut data: &[u8], start: std::time::Instant) {
    use crate::{DatagramEvent, Endpoint, EndpointConfig, ServerConfig};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();
    let mut endpoint = Endpoint::new(
        local,
        shared::TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(ServerConfig::default())),
    );
    let mut association = None;
    let mut step = 0u64;

    while data.len() >= 2 {
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        data = &data[2..];
        let len = len.min(data.len());
        let datagram = fix_checksum(&data[..len]);
        data = &data[len..];
        step += 1;
        let now = start + Duration::from_millis(step * 10);

        match endpoint.handle(now, remote, None, Bytes::from(datagram)) {
            Some((ch, DatagramEvent::NewAssociation(a))) => association = Some((ch, a)),
            Some((_, DatagramEvent::AssociationEvent(event))) => {
                if let Some((_, a)) = association.as_mut() {
                    a.handle_event(event);
                }
            }
            None => {}
        }
        // The endpoint's own answers to packets that belong to no association (RFC 9260 8.4).
        while endpoint.poll_transmit().is_some() {}
        if let Some((ch, a)) = association.as_mut() {
            a.handle_timeout(now);
            while a.poll().is_some() {}
            while a.poll_transmit(now).is_some() {}
            // An association that ends gives its place back to the endpoint, which then
            // accepts the next INIT: the fuzzer reaches more than one handshake per input.
            let mut drained = false;
            while let Some(event) = a.poll_endpoint_event() {
                drained |= event.is_drained();
                endpoint.handle_event(*ch, event);
            }
            if drained || a.is_ended() {
                association = None;
            }
        }
    }
}

/// Stateful target: an association that has completed its handshake, fed a sequence of
/// packets as its peer would send them.
///
/// [`endpoint_handle_datagrams`] cannot get past the handshake: the Verification Tag and the
/// State Cookie are random. Here a real client completes it first, then every input datagram
/// (the same framing: a big-endian `u16` length, then the datagram) gets the Verification Tag
/// the association expects and a correct checksum, so its chunks reach the handlers of an
/// established association: DATA, SACK, FORWARD TSN, RE-CONFIG, HEARTBEAT, ERROR, ABORT, the
/// shutdown chunks, and chunks and parameters of types the engine does not know. Time moves
/// with each datagram, by an amount the input chooses, so the timers run too.
pub fn association_handle_chunks(mut data: &[u8], start: std::time::Instant) {
    use crate::{ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Payload, ServerConfig};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    let client_addr: SocketAddr = "127.0.0.1:5001".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let mut client_endpoint = Endpoint::new(
        client_addr,
        shared::TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let mut server_endpoint = Endpoint::new(
        server_addr,
        shared::TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(ServerConfig::default())),
    );
    let Ok((_, mut client)) = client_endpoint.connect(start, ClientConfig::default(), server_addr)
    else {
        return;
    };
    let mut server: Option<(crate::AssociationHandle, crate::Association)> = None;

    fn drain(a: &mut crate::Association, now: std::time::Instant) -> Vec<Bytes> {
        let mut out = vec![];
        while let Some(transmit) = a.poll_transmit(now) {
            if let Payload::RawEncode(datagrams) = transmit.message {
                out.extend(datagrams);
            }
        }
        out
    }

    // INIT, INIT ACK, COOKIE ECHO, COOKIE ACK.
    for _ in 0..4 {
        for datagram in drain(&mut client, start) {
            match server_endpoint.handle(start, client_addr, None, datagram) {
                Some((ch, DatagramEvent::NewAssociation(a))) => server = Some((ch, a)),
                Some((_, DatagramEvent::AssociationEvent(event))) => {
                    if let Some((_, a)) = server.as_mut() {
                        a.handle_event(event);
                    }
                }
                None => {}
            }
        }
        let Some((_, a)) = server.as_mut() else {
            return;
        };
        for datagram in drain(a, start) {
            if let Some((_, DatagramEvent::AssociationEvent(event))) =
                client_endpoint.handle(start, server_addr, None, datagram)
            {
                client.handle_event(event);
            }
        }
    }
    let Some((ch, mut association)) = server else {
        return;
    };
    if association.is_handshaking() {
        return;
    }
    let tag = association.verification_tag();
    // A stream with something to send, so SACKs and resets have state to act on.
    if let Ok(mut stream) = association.open_stream(1, crate::PayloadProtocolIdentifier::Binary) {
        let _ = stream.write_sctp(
            start,
            &Bytes::from_static(&[0x5a; 3000]),
            crate::PayloadProtocolIdentifier::Binary,
        );
    }

    let mut now = start;
    while data.len() >= 3 {
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        // 0 to 255 steps of 250 ms: up to about a minute, enough for any timer to expire.
        now += Duration::from_millis(u64::from(data[2]) * 250);
        data = &data[3..];
        let len = len.min(data.len());
        let mut datagram = data[..len].to_vec();
        data = &data[len..];
        if datagram.len() >= 12 {
            datagram[4..8].copy_from_slice(&tag.to_be_bytes());
        }
        let datagram = fix_checksum(&datagram);

        if let Some((_, DatagramEvent::AssociationEvent(event))) =
            server_endpoint.handle(now, client_addr, None, Bytes::from(datagram))
        {
            association.handle_event(event);
        }
        while server_endpoint.poll_transmit().is_some() {}
        association.handle_timeout(now);
        while let Some(event) = association.poll() {
            if let crate::Event::Stream(crate::StreamEvent::Readable { id }) = event
                && let Ok(mut stream) = association.stream(id)
            {
                while let Ok(Some(_)) = stream.read_sctp() {}
            }
        }
        while association.poll_transmit(now).is_some() {}
        while let Some(event) = association.poll_endpoint_event() {
            server_endpoint.handle_event(ch, event);
        }
    }
}

/// An association with `count` messages in flight at `now`, for `bench_recovery_flushes`.
pub fn bench_recovery_setup(count: u32, now: std::time::Instant) -> Result<crate::Association> {
    crate::association::recovery_bench::recovery_setup(count, now)
}

/// Runs `count` one-chunk SCTP recovery flushes on an association from `bench_recovery_setup`
/// (T3-rtx retransmissions, or fast retransmissions with `fast`). The caller times it.
pub fn bench_recovery_flushes(
    association: &mut crate::Association,
    count: u32,
    fast: bool,
    now: std::time::Instant,
) {
    crate::association::recovery_bench::recovery_flushes(association, count, fast, now)
}
