//! The inner end of a nested interceptor placed in a registry slot.

use crate::Interceptor;
use crate::TaggedPacket;
use crate::stream_info::StreamInfo;
use sansio::Protocol;
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// Hands every packet on unchanged, in both directions: the inner end of a nested interceptor
/// (one written with the [`Interceptor`](derive@crate::Interceptor) derive, such as
/// [`GccInterceptor`](crate::GccInterceptor)) placed in a [`Registry`](crate::Registry) slot.
///
/// # Why not [`NoopInterceptor`](crate::NoopInterceptor)
///
/// `NoopInterceptor` is the chain's terminus: it ends every inbound RTCP packet no interceptor
/// marked for the application. Wrapped inside a slot it does that *there*, so every interceptor
/// application-ward of the slot, and the application, stop seeing RTCP: in
/// [`Slot::CongestionControl`](crate::Slot::CongestionControl), the slot inbound packets reach
/// first, that is all of it (NACKs, receiver reports, PLI and FIR). This one ends nothing; the
/// terminus [`Registry::build`](crate::Registry::build) appends stays the only one.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{
///     GccInterceptorBuilder, Interceptor, PassThroughInterceptor, Registry, Slot,
///     TwccSenderBuilder,
/// };
///
/// let (gcc_builder, _gcc_handle) = GccInterceptorBuilder::new();
/// let chain = Registry::new()
///     .with(
///         Slot::CongestionControl,
///         PassThroughInterceptor::new().with(gcc_builder.build()),
///     )
///     .with(Slot::TwccSender, TwccSenderBuilder::new().build())
///     .build();
/// # let _ = chain;
/// ```
#[derive(Default)]
pub struct PassThroughInterceptor {
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl PassThroughInterceptor {
    /// An interceptor that passes everything on.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for PassThroughInterceptor {
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
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for PassThroughInterceptor {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
