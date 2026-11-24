//! The sans-I/O layer of the C ABI end to end: two peer connections that only see each other
//! through `rtci_pc_*` calls (declared in `abi/mod.rs` as C declares them), on a virtual clock.

mod abi;

use abi::*;
use std::ptr;

const MINIMAL: &str = r#"{"interceptors":"minimal"}"#;

fn open_channel(pair: &mut Pair, label: &str) -> u64 {
    let mut id = 0u64;
    let label = c(label);
    ok(unsafe {
        rtci_pc_create_data_channel(pair.offerer.pc, label.as_ptr(), ptr::null(), &mut id)
    });
    pair.negotiate();
    assert!(
        pair.run_until(
            |p| !p.offerer.events_of("open").is_empty() && !p.answerer.events_of("open").is_empty()
        ),
        "the channel never opened; offerer {:?}, answerer {:?}",
        pair.offerer.events,
        pair.answerer.events
    );
    id
}

#[test]
fn a_data_channel_opens_and_echoes_strings_and_binary_through_the_c_abi() {
    let mut pair = Pair::new(MINIMAL);
    let channel = open_channel(&mut pair, "chat");
    assert!(
        pair.connected(),
        "{} / {}",
        pair.offerer.states(),
        pair.answerer.states()
    );

    // The answerer learned of the channel from the in-band DCEP open, with its label.
    let announced = pair.answerer.events_of("datachannel");
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0]["label"], "chat");
    let remote = announced[0]["channel"].as_u64().unwrap();
    let info = json(&out_string(|out| unsafe {
        rtci_pc_data_channel_info(pair.offerer.pc, channel, out)
    }));
    assert_eq!(info["label"], "chat");
    assert_eq!(info["readyState"], "open");
    assert_eq!(info["ordered"], true);

    let now = pair.now_ns;
    pair.offerer
        .send(now, channel, "hello, rtc".as_bytes(), true);
    let binary: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    pair.offerer.send(now, channel, &binary, false);
    assert!(pair.run_until(|p| p.answerer.data_messages().len() == 2));
    assert_eq!(
        pair.answerer.data_messages(),
        vec![(true, b"hello, rtc".to_vec()), (false, binary.clone())]
    );

    // The answerer echoes each message back on its side of the channel.
    let now = pair.now_ns;
    for (is_string, data) in pair.answerer.data_messages() {
        pair.answerer.send(now, remote, &data, is_string);
    }
    assert!(pair.run_until(|p| p.offerer.data_messages().len() == 2));
    assert_eq!(
        pair.offerer.data_messages(),
        vec![(true, b"hello, rtc".to_vec()), (false, binary)]
    );
    pair.free();
}

/// Adds an Opus track with a fixed SSRC; returns its sender.
fn add_audio(peer: &Peer, id: &str, ssrc: u32) -> u64 {
    let mut sender = 0u64;
    let track = c(&format!(
        r#"{{"kind":"audio","id":"{id}","label":"{id}","streamIds":["s-{id}"],"ssrc":{ssrc}}}"#
    ));
    ok(unsafe { rtci_pc_add_track(peer.pc, track.as_ptr(), &mut sender) });
    sender
}

/// The receiver of the first `track` event.
fn track_receiver(peer: &Peer) -> u64 {
    peer.events_of("track")[0]["receiver"].as_u64().unwrap()
}

#[test]
fn a_media_track_carries_rtp_both_ways_written_as_packets_and_as_frames() {
    let mut pair = Pair::new("{}");
    let offerer_sender = add_audio(&pair.offerer, "mic-a", 0x1111_0001);
    let answerer_sender = add_audio(&pair.answerer, "mic-b", 0x2222_0002);
    pair.negotiate();
    assert!(pair.run_until(Pair::connected));
    assert_eq!(pair.offerer.events_of("track").len(), 1);
    assert_eq!(pair.answerer.events_of("track").len(), 1);
    let at_answerer = track_receiver(&pair.answerer);
    let at_offerer = track_receiver(&pair.offerer);

    // The negotiated codec is reported with its payload type.
    let info = json(&out_string(|out| unsafe {
        rtci_pc_sender_info(pair.offerer.pc, offerer_sender, out)
    }));
    assert_eq!(info["ssrcs"][0], 0x1111_0001u32);
    assert_eq!(info["codecs"][0]["mimeType"], "audio/opus");
    let receiver = json(&out_string(|out| unsafe {
        rtci_pc_receiver_info(pair.answerer.pc, at_answerer, out)
    }));
    assert_eq!(receiver["kind"], "audio");

    // Offerer to answerer: RTP packets the application built.
    for i in 0..5u16 {
        let payload = [0xa0, i as u8, 1, 2, 3];
        let packet = rtp(0, 100 + i, 960 * u32::from(i), 0x1111_0001, &payload);
        let now = pair.now_ns;
        ok(unsafe {
            rtci_pc_sender_write_rtp(
                pair.offerer.pc,
                now,
                offerer_sender,
                packet.as_ptr(),
                packet.len(),
            )
        });
        pair.run_for(20_000_000);
    }
    // Answerer to offerer: encoded frames the library packetizes.
    for i in 0..5u8 {
        let frame = [0xb0, i, 9, 8, 7, 6];
        let now = pair.now_ns;
        ok(unsafe {
            rtci_pc_sender_write_frame(
                pair.answerer.pc,
                now,
                answerer_sender,
                frame.as_ptr(),
                frame.len(),
                960,
            )
        });
        pair.run_for(20_000_000);
    }
    assert!(
        pair.run_until(|p| p.answerer.rtp_payloads(at_answerer).len() >= 5
            && p.offerer.rtp_payloads(at_offerer).len() >= 5)
    );
    let got: Vec<Vec<u8>> = pair.answerer.rtp_payloads(at_answerer);
    assert_eq!(got[0], vec![0xa0, 0, 1, 2, 3]);
    assert_eq!(got[4], vec![0xa0, 4, 1, 2, 3]);
    let got: Vec<Vec<u8>> = pair.offerer.rtp_payloads(at_offerer);
    assert_eq!(got[0], vec![0xb0, 0, 9, 8, 7, 6]);
    assert_eq!(got[4], vec![0xb0, 4, 9, 8, 7, 6]);

    // getStats reports the streams.
    let now = pair.now_ns;
    let stats = json(&out_string(|out| unsafe {
        rtci_pc_get_stats(pair.answerer.pc, now, 0, 0, out)
    }));
    let types: Vec<&str> = stats
        .as_object()
        .unwrap()
        .values()
        .filter_map(|s| s["type"].as_str())
        .collect();
    assert!(types.contains(&"inbound-rtp"), "{types:?}");
    assert!(types.contains(&"outbound-rtp"), "{types:?}");
    pair.free();
}

#[test]
fn renegotiation_adds_a_video_transceiver_to_a_connected_pair() {
    let mut pair = Pair::new(MINIMAL);
    open_channel(&mut pair, "control");
    let before = pair.offerer.events_of("negotiationneeded").len();

    let mut transceiver = 0u64;
    let kind = c("video");
    let init = c(r#"{"direction":"sendonly","streams":["cam"]}"#);
    ok(unsafe {
        rtci_pc_add_transceiver(
            pair.offerer.pc,
            kind.as_ptr(),
            init.as_ptr(),
            &mut transceiver,
        )
    });
    assert!(pair.run_until(|p| p.offerer.events_of("negotiationneeded").len() > before));
    pair.negotiate();
    assert!(pair.run_until(|p| !p.answerer.events_of("track").is_empty()));
    assert_eq!(pair.offerer.states()["signalingState"], "stable");
    assert_eq!(pair.answerer.states()["signalingState"], "stable");

    let list = json(&out_string(|out| unsafe {
        rtci_pc_transceivers(pair.offerer.pc, out)
    }));
    let video = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == transceiver)
        .unwrap();
    assert_eq!(video["direction"], "sendonly");
    assert_eq!(video["currentDirection"], "sendonly");
    let at_answerer = track_receiver(&pair.answerer);
    let receiver = json(&out_string(|out| unsafe {
        rtci_pc_receiver_info(pair.answerer.pc, at_answerer, out)
    }));
    assert_eq!(receiver["kind"], "video");
    assert_eq!(receiver["streams"][0], "cam");

    // The new sender carries RTP to the answerer over the existing connection.
    let sender = video["sender"].as_u64().unwrap();
    let ssrc = json(&out_string(|out| unsafe {
        rtci_pc_sender_info(pair.offerer.pc, sender, out)
    }))["ssrcs"][0]
        .as_u64()
        .unwrap() as u32;
    let packet = rtp(96, 7, 9000, ssrc, &[0x10, 0x55, 0x66]);
    let now = pair.now_ns;
    ok(unsafe {
        rtci_pc_sender_write_rtp(pair.offerer.pc, now, sender, packet.as_ptr(), packet.len())
    });
    assert!(pair.run_until(|p| !p.answerer.rtp_payloads(at_answerer).is_empty()));
    assert_eq!(
        pair.answerer.rtp_payloads(at_answerer)[0],
        vec![0x10, 0x55, 0x66]
    );
    pair.free();
}

#[test]
fn close_ends_the_channel_on_both_sides_and_refuses_later_calls() {
    let mut pair = Pair::new(MINIMAL);
    let channel = open_channel(&mut pair, "bye");
    ok(unsafe { rtci_pc_close(pair.offerer.pc) });
    assert_eq!(pair.offerer.states()["connectionState"], "closed");
    assert_eq!(pair.offerer.states()["signalingState"], "closed");
    assert!(
        pair.run_until(|p| !p.answerer.events_of("close").is_empty()),
        "the remote channel never closed: {:?}",
        pair.answerer.events
    );
    // A closed connection refuses to create anything, with a code and a message.
    let mut id = 0u64;
    let label = c("late");
    let code = unsafe {
        rtci_pc_create_data_channel(pair.offerer.pc, label.as_ptr(), ptr::null(), &mut id)
    };
    assert_eq!(code, RTCI_ERR_ENGINE);
    assert!(!last_error().is_empty());
    let data = b"x";
    let code = unsafe {
        rtci_pc_data_channel_send(pair.offerer.pc, pair.now_ns, channel, data.as_ptr(), 1, 0)
    };
    assert!(code < 0, "a send on a closed connection: {code}");
    pair.free();
}

#[test]
fn errors_are_codes_with_a_message_and_a_small_buffer_keeps_the_item() {
    assert_eq!(unsafe { rtci_abi_version() }, 1);
    let mut pc = ptr::null_mut();
    let bad = c("{\"iceServers\": 5}");
    assert_eq!(
        unsafe { rtci_pc_new(bad.as_ptr(), ptr::null(), 0, &mut pc) },
        RTCI_ERR_JSON
    );
    assert!(last_error().contains("iceServers") || !last_error().is_empty());
    let unknown = c("{\"noSuchSetting\": true}");
    assert_eq!(
        unsafe { rtci_pc_new(ptr::null(), unknown.as_ptr(), 0, &mut pc) },
        RTCI_ERR_JSON,
        "an unknown member is refused"
    );
    assert!(last_error().contains("noSuchSetting"), "{}", last_error());
    assert_eq!(
        unsafe { rtci_pc_close(ptr::null_mut()) },
        RTCI_ERR_INVALID_ARGUMENT
    );

    ok(unsafe { rtci_pc_new(ptr::null(), ptr::null(), 0, &mut pc) });
    let label = c("x");
    let mut id = 0u64;
    ok(unsafe { rtci_pc_create_data_channel(pc, label.as_ptr(), ptr::null(), &mut id) });
    assert_eq!(
        unsafe { rtci_pc_data_channel_close(pc, 999) },
        RTCI_ERR_NOT_FOUND
    );
    let garbage = c("{\"type\":\"answer\",\"sdp\":\"not sdp\"}");
    assert!(unsafe { rtci_pc_set_remote_description(pc, 0, garbage.as_ptr()) } < 0);

    // An event does not fit in 4 bytes: the length needed comes back and the same event is
    // delivered on the retry.
    let mut small = [0u8; 4];
    let mut len = 0usize;
    let code = unsafe { rtci_pc_poll_event(pc, small.as_mut_ptr().cast(), small.len(), &mut len) };
    assert_eq!(code, RTCI_ERR_BUFFER_TOO_SMALL);
    let mut big = vec![0u8; len];
    let mut again = 0usize;
    ok(unsafe { rtci_pc_poll_event(pc, big.as_mut_ptr().cast(), big.len(), &mut again) });
    assert_eq!(again, len);
    assert!(json(std::str::from_utf8(&big).unwrap())["type"].is_string());

    // Descriptions are absent until set.
    let mut out = ptr::null_mut();
    assert_eq!(unsafe { rtci_pc_description(pc, 0, &mut out) }, RTCI_EMPTY);
    unsafe { rtci_pc_free(pc) };
}
