//! The packets a stream sent, as they left: what an FEC encoder protects.
//!
//! FEC protects the source packets as they are on the wire: the receiver XORs the packets that
//! arrived, so the sender has to XOR the same bytes (RFC 8627 section 4.1, RFC 5109 section 8).
//! An encoder is a generator and sits above the pacer, where a media packet is not final yet: the
//! TWCC sender below it writes the transport-wide sequence number into the packet, adding the
//! header extension when the packet has none. An encoder that reads the packet at its own slot
//! protects an image the receiver never sees.
//!
//! [`WireImageTap`] sits below everything that edits a departing packet
//! ([`Slot::FecWireImage`](crate::Slot::FecWireImage)) and copies the packets of the streams an
//! encoder asked for. The encoder, still at [`Slot::FecEncoder`](crate::Slot::FecEncoder), takes
//! them from its [`WireImages`] handle the next time the chain polls it, and its repair packets
//! travel the whole chain: paced, numbered and recorded like any other packet.

use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

/// The most wire images held for an encoder that is not taking them.
///
/// An encoder takes them every time the chain is polled, so more than a few is already unusual;
/// the bound is there so a chain whose encoder was dropped does not grow without limit. The
/// oldest go first: FEC for packets that left long ago is worth least.
pub const MAX_HELD_WIRE_IMAGES: usize = 1024;

#[derive(Default)]
struct Shared {
    watched: HashSet<u32>,
    images: VecDeque<TaggedPacket>,
    dropped: u64,
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    // Nothing is left half-done under this lock, so a panic elsewhere does not spoil the state.
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A tap and the handle that reads it.
///
/// Register the tap at [`Slot::FecWireImage`](crate::Slot::FecWireImage); give the handle to the
/// encoder. The FEC send interceptors build the pair themselves
/// ([`FlexFec03SendInterceptor::wire_tap`](crate::FlexFec03SendInterceptor::wire_tap)); this is
/// for an encoder of your own.
pub fn wire_image_tap() -> (WireImageTap, WireImages) {
    let shared = Arc::new(Mutex::new(Shared::default()));
    (
        WireImageTap {
            shared: shared.clone(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        },
        WireImages { shared },
    )
}

/// The reading end of a [`WireImageTap`].
#[derive(Clone)]
pub struct WireImages {
    shared: Arc<Mutex<Shared>>,
}

impl WireImages {
    /// Start copying the packets `ssrc` sends.
    pub fn watch(&self, ssrc: u32) {
        lock(&self.shared).watched.insert(ssrc);
    }

    /// Stop copying the packets `ssrc` sends. Images already held stay until taken.
    pub fn unwatch(&self, ssrc: u32) {
        lock(&self.shared).watched.remove(&ssrc);
    }

    /// The packets that left since the last call, oldest first, each with the instant it was
    /// released to the network.
    pub fn take(&self) -> Vec<TaggedPacket> {
        lock(&self.shared).images.drain(..).collect()
    }

    /// How many images were given up because nothing took them.
    pub fn dropped(&self) -> u64 {
        lock(&self.shared).dropped
    }
}

/// Copies departing RTP packets of the watched streams, as they leave. Changes nothing: every
/// packet passes through as it came.
pub struct WireImageTap {
    shared: Arc<Mutex<Shared>>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for WireImageTap {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp_packet) = &msg.message.packet {
            let mut shared = lock(&self.shared);
            if shared.watched.contains(&rtp_packet.header.ssrc) {
                if shared.images.len() >= MAX_HELD_WIRE_IMAGES {
                    shared.images.pop_front();
                    shared.dropped += 1;
                }
                shared.images.push_back(TaggedPacket {
                    now: msg.now,
                    transport: msg.transport,
                    message: msg.message.clone(),
                });
            }
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for WireImageTap {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttributedPacket;
    use shared::TransportContext;

    fn rtp(ssrc: u32, sequence_number: u16) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    ssrc,
                    sequence_number,
                    ..Default::default()
                },
                payload: vec![1, 2, 3].into(),
            })),
        }
    }

    fn sequence_numbers(images: &[TaggedPacket]) -> Vec<u16> {
        images
            .iter()
            .filter_map(|image| match &image.message.packet {
                Packet::Rtp(rtp) => Some(rtp.header.sequence_number),
                Packet::Rtcp(_) => None,
            })
            .collect()
    }

    #[test]
    fn only_watched_streams_are_copied_and_every_packet_passes_through() {
        let (mut tap, images) = wire_image_tap();
        images.watch(1);

        tap.handle_write(rtp(1, 10)).unwrap();
        tap.handle_write(rtp(2, 20)).unwrap();
        tap.handle_write(rtp(1, 11)).unwrap();

        let mut passed = Vec::new();
        while let Some(out) = tap.poll_write() {
            passed.push(out);
        }
        assert_eq!(vec![10, 20, 11], sequence_numbers(&passed));
        assert_eq!(vec![10, 11], sequence_numbers(&images.take()));
        assert!(images.take().is_empty(), "taken once");
    }

    #[test]
    fn an_unwatched_stream_is_no_longer_copied() {
        let (mut tap, images) = wire_image_tap();
        images.watch(1);
        images.unwatch(1);

        tap.handle_write(rtp(1, 10)).unwrap();
        assert!(images.take().is_empty());
    }

    #[test]
    fn images_nothing_takes_are_bounded() {
        let (mut tap, images) = wire_image_tap();
        images.watch(1);

        for sequence_number in 0..(MAX_HELD_WIRE_IMAGES as u16 + 5) {
            tap.handle_write(rtp(1, sequence_number)).unwrap();
            while tap.poll_write().is_some() {}
        }

        let held = images.take();
        assert_eq!(MAX_HELD_WIRE_IMAGES, held.len());
        assert_eq!(5, sequence_numbers(&held)[0], "the oldest were given up");
        assert_eq!(5, images.dropped());
    }
}
