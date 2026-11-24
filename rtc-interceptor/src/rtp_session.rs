//! One interceptor instance per RTP session.
//!
//! A peer connection whose m= sections are not all in one BUNDLE group runs several RTP
//! sessions, each on a transport of its own (RFC 8834 section 4.4, RFC 9429 section 5.2.1).
//! What is kept per session must then be kept per transport: the RTCP session's members,
//! bandwidth and reduced-size use (RFC 3550 section 6, RFC 5506), the transport-wide sequence
//! numbers and the feedback about them, the congestion controller's estimate and the pacer's
//! budget (each path has its own capacity, RFC 8836 section 2).
//!
//! [`PerRtpSession`] holds one instance of an interceptor per session and routes to it:
//!
//! - a stream (bind / unbind) goes to the session its SSRCs were assigned to
//!   ([`RtpSessionAssignment`]), or to the first session while none is known;
//! - a packet carrying [`RtpSession`] goes to that session (the peer connection tags what
//!   it reads with the transport it arrived on), an RTP packet without one to the session of
//!   its SSRC, an RTCP packet to that of the first SSRC it names that has one;
//! - an empty RTCP packet without a tag (a control message for the chain) goes to every
//!   session, and leaves the wrapper once; a session started later is given the ones it
//!   missed.
//!
//! What an instance writes or reads out is tagged with its session, so the interceptors
//! further along and the peer connection route it to that session's transport. With one
//! session (every section bundled) the wrapper holds one instance and changes nothing.

use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Interceptor, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

/// Names the RTP session (the transport) a packet belongs to. Carried as an
/// [`Attribute::Custom`]; read it with [`RtpSession::of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RtpSession(pub usize);

impl RtpSession {
    /// The session `packet` is tagged with.
    pub fn of(packet: &AttributedPacket) -> Option<usize> {
        packet.custom::<RtpSession>().map(|session| session.0)
    }

    /// The attribute that tags a packet with this session.
    pub fn attribute(self) -> Attribute {
        Attribute::Custom(Arc::new(self))
    }
}

/// A control message: the SSRCs (local and remote, media and repair) of the m= sections that
/// run in RTP session `session`. Written into the chain as an empty RTCP packet
/// ([`RtpSessionAssignment::into_packet`]); every [`PerRtpSession`] on the way takes note and
/// moves a stream it holds in another session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpSessionAssignment {
    /// The session.
    pub session: usize,
    /// The SSRCs that belong to it.
    pub ssrcs: Vec<u32>,
}

impl RtpSessionAssignment {
    /// The packet that carries this into the chain at `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(self))),
        }
    }
}

/// A control message: the transport moved to another selected candidate pair (an ICE restart,
/// a switch to another pair, a move to another network), after its first one. The peer
/// connection reads it into the chain on the read leg, as an empty RTCP packet
/// ([`PathChanged::into_packet`]), so it passes the congestion controllers first: they sit
/// wire-most. Each starts its estimate over and forgets what it sent before (RFC 8836
/// section 2, requirement 1: a congestion controller reacts to a change of the path; as
/// libwebrtc's `RtpTransportControllerSend::OnNetworkRouteChanged` restarts the bandwidth
/// estimate and has its feedback adapter report only the packets sent on the new route).
///
/// The congestion controllers also follow the addresses inbound packets arrive between, which
/// shows most changes; this one is told also when the addresses do not change (a TURN relay
/// that keeps them, or an application that hands every datagram over with one placeholder
/// address pair). With several transports it is tagged with the session ([`RtpSession`]) of
/// the transport whose pair changed, and reaches only that session's instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathChanged;

impl PathChanged {
    /// The packet that carries this into the chain's read leg at `now`, tagged with
    /// `session` when the peer connection runs several transports.
    pub fn into_packet(self, now: Instant, session: Option<usize>) -> TaggedPacket {
        let mut message =
            AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(Arc::new(self)));
        if let Some(session) = session {
            message.add(RtpSession(session).attribute());
        }
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message,
        }
    }
}

/// Marks a copy of a broadcast control message given to a session other than the first:
/// whatever of it comes out again is dropped, so the message leaves the wrapper once. The
/// mark goes on last: what an instance attaches after it is its own and leaves on a carrier
/// tagged with its session.
#[derive(Debug)]
struct BroadcastCopy;

/// Marks the copy of a broadcast control message given to the first session: it leaves the
/// wrapper as it came, untagged; what an instance attaches to it leaves as for
/// [`BroadcastCopy`].
#[derive(Debug)]
struct Passthrough;

/// The most broadcast control messages kept for a session that starts later.
const MAX_REPLAYED_CONTROLS: usize = 512;

/// The most SSRCs whose session is learned from the reports they send.
const MAX_LEARNED_SSRCS: usize = 4096;

/// The SSRC that sent a sender or receiver report.
fn rtcp_sender_ssrc(packet: &dyn rtcp::Packet) -> Option<u32> {
    let any = packet.as_any();
    any.downcast_ref::<rtcp::receiver_report::ReceiverReport>()
        .map(|rr| rr.ssrc)
        .or_else(|| {
            any.downcast_ref::<rtcp::sender_report::SenderReport>()
                .map(|sr| sr.ssrc)
        })
}

fn duplicate(msg: &TaggedPacket) -> TaggedPacket {
    TaggedPacket {
        now: msg.now,
        transport: msg.transport,
        message: msg.message.clone(),
    }
}

type Factory<T> = Box<dyn FnMut(usize) -> T + Send + Sync>;

/// An interceptor instance per RTP session; see the `rtp_session` module's source documentation.
pub struct PerRtpSession<T: Interceptor> {
    factory: Factory<T>,
    instances: BTreeMap<usize, T>,
    /// The session of each SSRC, from assignments and tagged reads.
    sessions: HashMap<u32, usize>,
    /// The streams bound, by media SSRC and direction (`true`: local), with the session
    /// each is bound in.
    streams: HashMap<(bool, u32), (StreamInfo, usize)>,
    /// Broadcast control messages, for a session that starts later.
    controls: VecDeque<TaggedPacket>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl<T: Interceptor> PerRtpSession<T> {
    /// A wrapper whose sessions are each given an instance `factory` makes. The first is
    /// made now, for session 0.
    pub fn new(mut factory: impl FnMut() -> T + Send + Sync + 'static) -> Self {
        let first = factory();
        Self::with_first(first, factory)
    }

    /// A wrapper whose session 0 is `first` and whose other sessions each get an instance
    /// `factory` makes.
    pub fn with_first(first: T, mut factory: impl FnMut() -> T + Send + Sync + 'static) -> Self {
        Self::with_first_for_sessions(first, move |_| factory())
    }

    /// A wrapper whose session 0 is `first` and whose other sessions each get the instance
    /// `factory` makes for the session's number (to hand out a per-session handle).
    pub fn with_first_for_sessions(
        first: T,
        factory: impl FnMut(usize) -> T + Send + Sync + 'static,
    ) -> Self {
        Self {
            factory: Box::new(factory),
            instances: BTreeMap::from([(0, first)]),
            sessions: HashMap::new(),
            streams: HashMap::new(),
            controls: VecDeque::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// The sessions that have an instance, in order.
    pub fn sessions(&self) -> Vec<usize> {
        self.instances.keys().copied().collect()
    }

    /// The instance of `session`, if it has one.
    pub fn instance(&self, session: usize) -> Option<&T> {
        self.instances.get(&session)
    }

    /// The first session's instance (the only one while every section is bundled).
    pub fn first(&self) -> &T {
        self.instances
            .values()
            .next()
            .expect("a wrapper always holds an instance")
    }

    fn home(&self) -> usize {
        *self
            .instances
            .keys()
            .next()
            .expect("a wrapper always holds an instance")
    }

    /// The instance of `session`, made (and given the control messages it missed) when it
    /// has none yet.
    fn ensure(&mut self, session: usize) -> &mut T {
        if !self.instances.contains_key(&session) {
            let mut instance = (self.factory)(session);
            for control in &self.controls {
                let mut copy = duplicate(control);
                copy.message.add(Attribute::Custom(Arc::new(BroadcastCopy)));
                let _ = instance.handle_write(copy);
            }
            self.instances.insert(session, instance);
        }
        self.instances
            .get_mut(&session)
            .expect("the instance was just made")
    }

    fn session_of_info(&self, info: &StreamInfo) -> usize {
        std::iter::once(info.ssrc)
            .chain(info.ssrc_rtx)
            .chain(info.ssrc_fec)
            .find_map(|ssrc| self.sessions.get(&ssrc).copied())
            .unwrap_or_else(|| self.home())
    }

    fn bind(&mut self, local: bool, info: &StreamInfo, session: usize) {
        let instance = self.ensure(session);
        if local {
            instance.bind_local_stream(info);
        } else {
            instance.bind_remote_stream(info);
        }
        self.streams
            .insert((local, info.ssrc), (info.clone(), session));
    }

    fn unbind(&mut self, local: bool, ssrc: u32) -> Option<StreamInfo> {
        let (info, session) = self.streams.remove(&(local, ssrc))?;
        if let Some(instance) = self.instances.get_mut(&session) {
            if local {
                instance.unbind_local_stream(&info);
            } else {
                instance.unbind_remote_stream(&info);
            }
        }
        self.drop_if_empty(session);
        Some(info)
    }

    /// A session left with no stream goes, unless it is the only one: its transport is gone
    /// or its sections moved to another.
    fn drop_if_empty(&mut self, session: usize) {
        if self.instances.len() > 1
            && !self.streams.values().any(|(_, s)| *s == session)
            && let Some(mut instance) = self.instances.remove(&session)
        {
            self.drain_instance(session, &mut instance);
        }
    }

    /// Moves every stream with an SSRC in `ssrcs` that is bound in another session to
    /// `session`.
    fn reassign(&mut self, session: usize, ssrcs: &[u32]) {
        for ssrc in ssrcs {
            self.sessions.insert(*ssrc, session);
        }
        let moving: Vec<(bool, u32)> = self
            .streams
            .iter()
            .filter(|(_, (info, bound))| {
                *bound != session
                    && std::iter::once(info.ssrc)
                        .chain(info.ssrc_rtx)
                        .chain(info.ssrc_fec)
                        .any(|ssrc| ssrcs.contains(&ssrc))
            })
            .map(|(key, _)| *key)
            .collect();
        // Bound in the new session first, so the old one is not the last and kept.
        for (local, ssrc) in moving {
            if let Some((info, from)) = self.streams.get(&(local, ssrc)).cloned() {
                let instance = self.ensure(session);
                if local {
                    instance.bind_local_stream(&info);
                } else {
                    instance.bind_remote_stream(&info);
                }
                self.streams.insert((local, ssrc), (info.clone(), session));
                if let Some(old) = self.instances.get_mut(&from) {
                    if local {
                        // The stream goes on in the other session: it moves, it does not
                        // leave (no BYE on the old transport, RFC 3550 6.6).
                        old.move_local_stream_out(&info);
                    } else {
                        old.unbind_remote_stream(&info);
                    }
                }
                self.drop_if_empty(from);
            }
        }
    }

    /// The session a packet without a tag belongs to; `None` for a broadcast control message.
    fn session_of_packet(&self, packet: &Packet) -> Option<usize> {
        match packet {
            Packet::Rtp(rtp) => Some(
                self.sessions
                    .get(&rtp.header.ssrc)
                    .copied()
                    .or_else(|| self.stream_session(rtp.header.ssrc))
                    .unwrap_or_else(|| self.home()),
            ),
            Packet::Rtcp(packets) if packets.is_empty() => None,
            // The session of the first SSRC the compound packet is about, else that of its
            // sender (a receiver report without blocks names no stream, only who sent it), else
            // the first session.
            Packet::Rtcp(packets) => Some(
                packets
                    .iter()
                    .flat_map(|packet| packet.destination_ssrc())
                    .chain(
                        packets
                            .iter()
                            .filter_map(|packet| rtcp_sender_ssrc(packet.as_ref())),
                    )
                    .find_map(|ssrc| {
                        self.sessions
                            .get(&ssrc)
                            .copied()
                            .or_else(|| self.stream_session(ssrc))
                    })
                    .unwrap_or_else(|| self.home()),
            ),
            #[allow(unreachable_patterns)]
            _ => Some(self.home()),
        }
    }

    fn stream_session(&self, ssrc: u32) -> Option<usize> {
        self.streams.values().find_map(|(info, session)| {
            std::iter::once(info.ssrc)
                .chain(info.ssrc_rtx)
                .chain(info.ssrc_fec)
                .any(|s| s == ssrc)
                .then_some(*session)
        })
    }

    /// What an instance hands on, tagged with its session (or, for a broadcast control
    /// message, as it came, once).
    fn emit(session: usize, mut packet: TaggedPacket, queue: &mut VecDeque<TaggedPacket>) {
        // What an instance attached to a broadcast copy (an estimate riding on a carrier
        // that every session was given) is that session's: it leaves on a carrier of its own,
        // tagged with the session, whatever becomes of the copy.
        // The mark goes on last, so what follows it was attached by the instance.
        let mark = packet.message.attributes.iter().position(|a| {
            matches!(a, Attribute::Custom(value)
                if value.is::<BroadcastCopy>() || value.is::<Passthrough>())
        });
        if let Some(mark) = mark
            && packet.message.attributes.len() > mark + 1
        {
            let added = packet.message.attributes.split_off(mark + 1);
            let mut carrier = AttributedPacket::new(Packet::Rtcp(vec![]));
            for attribute in added {
                carrier.add(attribute);
            }
            carrier.add(RtpSession(session).attribute());
            queue.push_back(TaggedPacket {
                now: packet.now,
                transport: packet.transport,
                message: carrier,
            });
        }
        let tagged = RtpSession::of(&packet.message).is_some();
        let attributes = &mut packet.message.attributes;
        let marked = |attribute: &Attribute, copy: bool| match attribute {
            Attribute::Custom(value) => {
                if copy {
                    value.downcast_ref::<BroadcastCopy>().is_some()
                } else {
                    value.downcast_ref::<Passthrough>().is_some()
                }
            }
            _ => false,
        };
        if attributes.iter().any(|a| marked(a, true)) {
            return;
        }
        if attributes.iter().any(|a| marked(a, false)) {
            attributes.retain(|a| !marked(a, false));
        } else if !tagged {
            attributes.push(RtpSession(session).attribute());
        }
        queue.push_back(packet);
    }

    fn drain_instance(&mut self, session: usize, instance: &mut T) {
        while let Some(packet) = instance.poll_read() {
            Self::emit(session, packet, &mut self.read_queue);
        }
        while let Some(packet) = instance.poll_write() {
            Self::emit(session, packet, &mut self.write_queue);
        }
    }

    fn drain(&mut self) {
        for (session, instance) in self.instances.iter_mut() {
            while let Some(packet) = instance.poll_read() {
                Self::emit(*session, packet, &mut self.read_queue);
            }
            while let Some(packet) = instance.poll_write() {
                Self::emit(*session, packet, &mut self.write_queue);
            }
        }
    }

    /// Hands `msg` to its session, or to all of them.
    fn dispatch(&mut self, msg: TaggedPacket, write: bool) -> Result<(), Error> {
        if let Some(assignment) = msg.message.custom::<RtpSessionAssignment>() {
            let assignment = assignment.clone();
            self.reassign(assignment.session, &assignment.ssrcs);
            // Every wrapper on the way takes note: it goes on as it came.
            if write {
                self.write_queue.push_back(msg);
            } else {
                self.read_queue.push_back(msg);
            }
            return Ok(());
        }
        let session =
            RtpSession::of(&msg.message).or_else(|| self.session_of_packet(&msg.message.packet));
        let handle = |instance: &mut T, msg: TaggedPacket| {
            if write {
                instance.handle_write(msg)
            } else {
                instance.handle_read(msg)
            }
        };
        match session {
            Some(session) => {
                // A read names the transport it arrived on: its media SSRC belongs to that
                // session from now on.
                if !write
                    && RtpSession::of(&msg.message).is_some()
                    && let Packet::Rtp(rtp) = &msg.message.packet
                    && self.sessions.get(&rtp.header.ssrc) != Some(&session)
                {
                    let ssrc = rtp.header.ssrc;
                    self.reassign(session, &[ssrc]);
                }
                // The sender of a report read on a transport is in that transport's session,
                // so a later report from it routes there without a tag.
                if !write
                    && RtpSession::of(&msg.message).is_some()
                    && let Packet::Rtcp(packets) = &msg.message.packet
                {
                    for ssrc in packets.iter().filter_map(|p| rtcp_sender_ssrc(p.as_ref())) {
                        if !self.sessions.contains_key(&ssrc)
                            && self.sessions.len() < MAX_LEARNED_SSRCS
                        {
                            self.sessions.insert(ssrc, session);
                        }
                    }
                }
                handle(self.ensure(session), msg)?;
            }
            None => {
                if write {
                    if self.controls.len() == MAX_REPLAYED_CONTROLS {
                        self.controls.pop_front();
                    }
                    self.controls.push_back(duplicate(&msg));
                }
                let home = self.home();
                for (session, instance) in self.instances.iter_mut() {
                    let mut copy = duplicate(&msg);
                    copy.message.add(Attribute::Custom(if *session == home {
                        Arc::new(Passthrough) as Arc<dyn std::any::Any + Send + Sync>
                    } else {
                        Arc::new(BroadcastCopy)
                    }));
                    handle(instance, copy)?;
                }
            }
        }
        self.drain();
        Ok(())
    }
}

impl<T: Interceptor> Protocol<TaggedPacket, TaggedPacket, ()> for PerRtpSession<T> {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.dispatch(msg, false)
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        if self.read_queue.is_empty() {
            self.drain();
        }
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.dispatch(msg, true)
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        if self.write_queue.is_empty() {
            self.drain();
        }
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        for instance in self.instances.values_mut() {
            instance.handle_timeout(now)?;
        }
        self.drain();
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.instances
            .values_mut()
            .filter_map(|instance| instance.poll_timeout())
            .min()
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        for instance in self.instances.values_mut() {
            instance.close()?;
        }
        self.drain();
        Ok(())
    }
}

impl<T: Interceptor> Interceptor for PerRtpSession<T> {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let session = match self.streams.get(&(true, info.ssrc)) {
            Some((_, bound)) => *bound,
            None => self.session_of_info(info),
        };
        self.bind(true, info, session);
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.unbind(true, info.ssrc);
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        let session = match self.streams.get(&(false, info.ssrc)) {
            Some((_, bound)) => *bound,
            None => self.session_of_info(info),
        };
        self.bind(false, info, session);
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.unbind(false, info.ssrc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RtcpSessionBuilder, RtcpSessionControl};
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::time::Duration;

    /// What each instance was given: (instance number, SSRC or `None` for a control).
    type Log = Arc<Mutex<Vec<(usize, Option<u32>)>>>;

    struct Recorder {
        number: usize,
        log: Log,
        queue: VecDeque<TaggedPacket>,
        read: VecDeque<TaggedPacket>,
    }

    impl Protocol<TaggedPacket, TaggedPacket, ()> for Recorder {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;
        fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Error> {
            // An estimate riding on a carrier, as a congestion controller attaches one.
            if matches!(&msg.message.packet, Packet::Rtcp(packets) if packets.is_empty()) {
                msg.message.add(Attribute::TargetBitrateChanged {
                    bits_per_second: self.number as f64,
                });
            }
            self.read.push_back(msg);
            Ok(())
        }
        fn poll_read(&mut self) -> Option<TaggedPacket> {
            self.read.pop_front()
        }
        fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Error> {
            let ssrc = match &msg.message.packet {
                Packet::Rtp(rtp) => Some(rtp.header.ssrc),
                _ => None,
            };
            self.log.lock().unwrap().push((self.number, ssrc));
            self.queue.push_back(msg);
            Ok(())
        }
        fn poll_write(&mut self) -> Option<TaggedPacket> {
            self.queue.pop_front()
        }
    }

    impl Interceptor for Recorder {
        fn bind_local_stream(&mut self, _: &StreamInfo) {}
        fn unbind_local_stream(&mut self, _: &StreamInfo) {}
        fn bind_remote_stream(&mut self, _: &StreamInfo) {}
        fn unbind_remote_stream(&mut self, _: &StreamInfo) {}
    }

    fn recorders(log: &Log) -> PerRtpSession<Recorder> {
        let log = log.clone();
        let mut number = 0;
        PerRtpSession::new(move || {
            number += 1;
            Recorder {
                number,
                log: log.clone(),
                queue: VecDeque::new(),
                read: VecDeque::new(),
            }
        })
    }

    fn rtp(now: Instant, ssrc: u32, sequence_number: u16) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    ssrc,
                    sequence_number,
                    payload_type: 111,
                    ..Default::default()
                },
                payload: vec![0u8; 100].into(),
            })),
        }
    }

    fn stream(ssrc: u32) -> StreamInfo {
        StreamInfo {
            ssrc,
            clock_rate: 48_000,
            mime_type: "audio/opus".to_owned(),
            payload_type: 111,
            ..Default::default()
        }
    }

    #[test]
    fn packets_reach_the_instance_of_their_session_and_leave_tagged_with_it() {
        let log = Log::default();
        let mut wrapper = recorders(&log);
        let now = Instant::now();
        for (session, ssrc) in [(0, 1), (1, 2)] {
            wrapper
                .handle_write(
                    RtpSessionAssignment {
                        session,
                        ssrcs: vec![ssrc],
                    }
                    .into_packet(now),
                )
                .unwrap();
        }
        wrapper.bind_local_stream(&stream(1));
        wrapper.bind_local_stream(&stream(2));
        for n in 0..3 {
            wrapper.handle_write(rtp(now, 1, n)).unwrap();
            wrapper.handle_write(rtp(now, 2, n)).unwrap();
        }
        assert_eq!(wrapper.sessions(), vec![0, 1]);
        let got = log.lock().unwrap().clone();
        assert!(
            got.iter()
                .filter(|(_, s)| s.is_some())
                .all(|(n, s)| *s == Some(*n as u32)),
            "{got:?}"
        );
        let mut out = vec![];
        while let Some(packet) = wrapper.poll_write() {
            if let Packet::Rtp(rtp) = &packet.message.packet {
                out.push((rtp.header.ssrc, RtpSession::of(&packet.message)));
            }
        }
        assert_eq!(out.len(), 6);
        assert!(
            out.iter()
                .all(|(ssrc, session)| *session == Some(*ssrc as usize - 1)),
            "{out:?}"
        );
    }

    #[test]
    fn a_control_message_reaches_every_session_and_leaves_once() {
        let log = Log::default();
        let mut wrapper = recorders(&log);
        let now = Instant::now();
        wrapper
            .handle_write(
                RtpSessionAssignment {
                    session: 1,
                    ssrcs: vec![2],
                }
                .into_packet(now),
            )
            .unwrap();
        wrapper.bind_local_stream(&stream(1));
        wrapper.bind_local_stream(&stream(2));
        while wrapper.poll_write().is_some() {}
        log.lock().unwrap().clear();
        wrapper
            .handle_write(RtcpSessionControl::Start.into_packet(now))
            .unwrap();
        let got = log.lock().unwrap().clone();
        assert_eq!(got, vec![(1, None), (2, None)]);
        let out: Vec<_> = std::iter::from_fn(|| wrapper.poll_write()).collect();
        assert_eq!(out.len(), 1, "the control leaves the wrapper once");
        assert_eq!(
            RtpSession::of(&out[0].message),
            None,
            "as it came, untagged"
        );
        assert!(out[0].message.custom::<RtcpSessionControl>().is_some());
        assert!(out[0].message.custom::<Passthrough>().is_none());
    }

    #[test]
    fn a_session_made_later_is_given_the_control_messages_it_missed() {
        let log = Log::default();
        let mut wrapper = recorders(&log);
        let now = Instant::now();
        wrapper
            .handle_write(RtcpSessionControl::Start.into_packet(now))
            .unwrap();
        while wrapper.poll_write().is_some() {}
        wrapper
            .handle_write(
                RtpSessionAssignment {
                    session: 4,
                    ssrcs: vec![9],
                }
                .into_packet(now),
            )
            .unwrap();
        wrapper.bind_local_stream(&stream(9));
        let got = log.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![(1, None), (2, None)],
            "the new instance got the Start it missed"
        );
        let out: Vec<_> = std::iter::from_fn(|| wrapper.poll_write()).collect();
        assert!(
            out.iter()
                .all(|p| p.message.custom::<RtcpSessionControl>().is_none()),
            "a replayed control does not leave the wrapper again"
        );
        // The first session lost its last stream to none: it stays while it is not empty.
        assert_eq!(wrapper.sessions(), vec![0, 4]);
    }

    #[test]
    fn a_read_moves_a_remote_stream_to_the_transport_it_arrived_on() {
        let log = Log::default();
        let mut wrapper = recorders(&log);
        let now = Instant::now();
        wrapper.bind_remote_stream(&stream(7));
        wrapper.bind_local_stream(&stream(1));
        let mut packet = rtp(now, 7, 0);
        packet.message.add(RtpSession(3).attribute());
        wrapper.handle_read(packet).unwrap();
        assert_eq!(wrapper.sessions(), vec![0, 3]);
        assert_eq!(wrapper.stream_session(7), Some(3));
        let out = wrapper.poll_read().expect("the packet goes on");
        assert_eq!(RtpSession::of(&out.message), Some(3));
    }

    /// RFC 3550 section 6 and RFC 8834 section 4.4: each RTP session has its own RTCP
    /// session. With the sections of two transports, each compound packet reports on the
    /// streams of one transport only and is tagged with it.
    #[test]
    fn each_rtcp_session_reports_on_the_streams_of_its_own_transport() {
        let mut wrapper = RtcpSessionBuilder::new()
            .with_t_rr_interval(Duration::ZERO)
            .build_per_rtp_session();
        let mut now = Instant::now();
        // Session 0: local 0x10, remote 0x20; session 1: local 0x11, remote 0x21.
        let sessions = [(0usize, [0x10u32, 0x20u32]), (1, [0x11, 0x21])];
        for (session, ssrcs) in sessions {
            wrapper
                .handle_write(
                    RtpSessionAssignment {
                        session,
                        ssrcs: ssrcs.to_vec(),
                    }
                    .into_packet(now),
                )
                .unwrap();
            wrapper.bind_local_stream(&stream(ssrcs[0]));
            wrapper.bind_remote_stream(&stream(ssrcs[1]));
        }
        wrapper
            .handle_write(RtcpSessionControl::Start.into_packet(now))
            .unwrap();
        let mut reports = vec![];
        for step in 0..400u16 {
            now += Duration::from_millis(20);
            for (session, ssrcs) in sessions {
                wrapper.handle_write(rtp(now, ssrcs[0], step)).unwrap();
                let mut arrival = rtp(now, ssrcs[1], step);
                arrival.message.add(RtpSession(session).attribute());
                wrapper.handle_read(arrival).unwrap();
            }
            wrapper.handle_timeout(now).unwrap();
            while wrapper.poll_read().is_some() {}
            while let Some(packet) = wrapper.poll_write() {
                if let Packet::Rtcp(packets) = &packet.message.packet
                    && !packets.is_empty()
                {
                    let named: HashSet<u32> =
                        packets.iter().flat_map(|p| p.destination_ssrc()).collect();
                    reports.push((RtpSession::of(&packet.message), named));
                }
            }
        }
        assert!(reports.len() > 10, "{}", reports.len());
        for (tag, named) in &reports {
            let session = tag.expect("tagged with its session");
            let own: HashSet<u32> = sessions[session].1.into_iter().collect();
            assert!(named.is_subset(&own), "session {session} named {named:x?}");
        }
        for session in [0, 1] {
            assert!(reports.iter().any(|(tag, _)| *tag == Some(session)));
        }
    }

    /// A receiver report without report blocks names no stream: it is routed by its sender,
    /// to the session the sender's stream is bound in (not to the first session).
    #[test]
    fn a_receiver_report_without_blocks_goes_to_its_senders_session() {
        let log = Log::default();
        let mut wrapper = recorders(&log);
        let now = Instant::now();
        wrapper
            .handle_write(
                RtpSessionAssignment {
                    session: 1,
                    ssrcs: vec![0x21],
                }
                .into_packet(now),
            )
            .unwrap();
        wrapper.bind_remote_stream(&stream(0x21));
        wrapper.bind_local_stream(&stream(0x10));
        while wrapper.poll_write().is_some() {}
        while wrapper.poll_read().is_some() {}
        let report = TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(
                rtcp::receiver_report::ReceiverReport {
                    ssrc: 0x21,
                    ..Default::default()
                },
            )])),
        };
        wrapper.handle_read(report).unwrap();
        let out = wrapper.poll_read().expect("the report goes on");
        assert_eq!(RtpSession::of(&out.message), Some(1));
    }

    /// RFC 3550 section 6.6: BYE is for a source leaving the session. A stream whose section
    /// moves to another transport (a bundling answer) carries on in that session: the session
    /// it leaves, which keeps another section, says no BYE for it, and the session it joins
    /// reports on it.
    #[test]
    fn a_stream_moving_to_another_session_says_no_goodbye() {
        let mut wrapper = RtcpSessionBuilder::new()
            .with_t_rr_interval(Duration::ZERO)
            .build_per_rtp_session();
        let mut now = Instant::now();
        let sections = [(0usize, 0x10u32, 0x20u32), (1, 0x11, 0x21), (1, 0x12, 0x22)];
        for (session, local, remote) in sections {
            wrapper
                .handle_write(
                    RtpSessionAssignment {
                        session,
                        ssrcs: vec![local, remote],
                    }
                    .into_packet(now),
                )
                .unwrap();
            wrapper.bind_local_stream(&stream(local));
            wrapper.bind_remote_stream(&stream(remote));
        }
        wrapper
            .handle_write(RtcpSessionControl::Start.into_packet(now))
            .unwrap();
        let mut goodbyes = vec![];
        let mut reported_in_zero = false;
        for step in 0..600u16 {
            now += Duration::from_millis(20);
            if step == 200 {
                // The section of 0x11 moves to the first transport; 0x12's stays.
                wrapper
                    .handle_write(
                        RtpSessionAssignment {
                            session: 0,
                            ssrcs: vec![0x10, 0x20, 0x11, 0x21],
                        }
                        .into_packet(now),
                    )
                    .unwrap();
            }
            for (_, local, remote) in sections {
                wrapper.handle_write(rtp(now, local, step)).unwrap();
                wrapper.handle_read(rtp(now, remote, step)).unwrap();
            }
            wrapper.handle_timeout(now).unwrap();
            while wrapper.poll_read().is_some() {}
            while let Some(packet) = wrapper.poll_write() {
                if let Packet::Rtcp(packets) = &packet.message.packet {
                    for p in packets {
                        if let Some(bye) = p.as_any().downcast_ref::<rtcp::goodbye::Goodbye>() {
                            goodbyes.extend(bye.sources.iter().copied());
                        }
                        if step > 300
                            && RtpSession::of(&packet.message) == Some(0)
                            && p.as_any()
                                .downcast_ref::<rtcp::sender_report::SenderReport>()
                                .is_some_and(|sr| sr.ssrc == 0x11)
                        {
                            reported_in_zero = true;
                        }
                    }
                }
            }
        }
        assert!(
            !goodbyes.contains(&0x11),
            "no BYE for the stream that moved: {goodbyes:x?}"
        );
        assert!(
            reported_in_zero,
            "the session it moved to sends its sender report"
        );
        assert_eq!(
            wrapper.sessions(),
            vec![0, 1],
            "the second session keeps its section"
        );
    }

    /// A carrier read without a tag goes to every session. What each session's instance
    /// attaches to it (a congestion controller's estimate) leaves tagged with that session, the
    /// first session's included: it is that transport's, not the transport the connection
    /// happens to be working on.
    #[test]
    fn what_a_session_attaches_to_a_broadcast_leaves_tagged_with_it() {
        let log = Log::default();
        let mut wrapper = recorders(&log);
        let now = Instant::now();
        wrapper
            .handle_write(
                RtpSessionAssignment {
                    session: 1,
                    ssrcs: vec![2],
                }
                .into_packet(now),
            )
            .unwrap();
        wrapper.bind_local_stream(&stream(1));
        wrapper.bind_local_stream(&stream(2));
        while wrapper.poll_read().is_some() {}
        let carrier = TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        };
        wrapper.handle_read(carrier).unwrap();
        let mut estimates = vec![];
        while let Some(packet) = wrapper.poll_read() {
            for attribute in &packet.message.attributes {
                if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                    estimates.push((RtpSession::of(&packet.message), *bits_per_second));
                }
            }
        }
        estimates.sort_by(|a, b| a.partial_cmp(b).unwrap());
        // Instance 1 serves session 0, instance 2 session 1.
        assert_eq!(estimates, vec![(Some(0), 1.0), (Some(1), 2.0)]);
    }
}
