#[cfg(test)]
mod binding_test;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How long a channel binding lasts on the server from the ChannelBind that made or refreshed
/// it (RFC 8656 §12).
pub(crate) const BINDING_LIFETIME: Duration = Duration::from_secs(600);
/// How long after a binding expires its channel number may not be bound to another peer
/// address, nor its peer address to another number (RFC 8656 §12).
pub(crate) const BINDING_REUSE_DELAY: Duration = Duration::from_secs(300);
/// The age at which a send on a binding rebinds it.
pub(crate) const BINDING_REFRESH_AGE: Duration = Duration::from_secs(300);

//  Channel number:
//    0x4000 through 0x4FFF: These values are the allowed channel
//    numbers (4,096 possible values).
const MIN_CHANNEL_NUMBER: u16 = 0x4000;
const MAX_CHANNEL_NUMBER: u16 = 0x4fff;

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum BindingState {
    Idle,
    Request,
    Ready,
    Refresh,
    /// The server refused the ChannelBind; it is not asked again before `retry_at`.
    Failed,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct Binding {
    pub(crate) number: u16,
    pub(crate) st: BindingState,
    pub(crate) addr: SocketAddr,
    /// When the server last confirmed the binding; meaningful once `bound`.
    pub(crate) refreshed_at: Instant,
    /// Whether a ChannelBind for this pair ever succeeded.
    pub(crate) bound: bool,
    /// Whether data went over the channel, either way, since it was last bound.
    pub(crate) used: bool,
    /// When a ChannelBind for this pair was last sent. The server may hold the binding for
    /// [`BINDING_LIFETIME`] from then, whatever became of the response.
    pub(crate) last_request_at: Option<Instant>,
    /// With [`BindingState::Failed`]: when the ChannelBind may be tried again.
    pub(crate) retry_at: Option<Instant>,
}

impl Binding {
    /// Whether the server still holds this binding at `now`, by the last ChannelBind it
    /// confirmed.
    pub(crate) fn is_live(&self, now: Instant) -> bool {
        self.bound && now.saturating_duration_since(self.refreshed_at) < BINDING_LIFETIME
    }

    /// Whether the number and the address are free for another binding at `now`: no ChannelBind
    /// is in flight, and the last one was sent long enough ago that the binding it may have made
    /// expired and the wait after that is over.
    fn is_reusable(&self, now: Instant) -> bool {
        !matches!(self.st, BindingState::Request | BindingState::Refresh)
            && self.last_request_at.is_some_and(|at| {
                now.saturating_duration_since(at) >= BINDING_LIFETIME + BINDING_REUSE_DELAY
            })
    }

    pub(crate) fn set_state(&mut self, state: BindingState) {
        self.st = state;
    }

    pub(crate) fn state(&self) -> BindingState {
        self.st
    }

    pub(crate) fn set_refreshed_at(&mut self, at: Instant) {
        self.refreshed_at = at;
    }

    pub(crate) fn refreshed_at(&self) -> Instant {
        self.refreshed_at
    }
}
/// Thread-safe Binding map.
#[derive(Default)]
pub(crate) struct BindingManager {
    chan_map: HashMap<u16, String>,
    addr_map: HashMap<String, Binding>,
    next: u16,
}

impl BindingManager {
    pub(crate) fn new() -> Self {
        BindingManager {
            chan_map: HashMap::new(),
            addr_map: HashMap::new(),
            next: MIN_CHANNEL_NUMBER,
        }
    }

    pub(crate) fn assign_channel_number(&mut self) -> u16 {
        let n = self.next;
        if self.next == MAX_CHANNEL_NUMBER {
            self.next = MIN_CHANNEL_NUMBER;
        } else {
            self.next += 1;
        }
        n
    }

    pub(crate) fn create(&mut self, now: Instant, addr: SocketAddr) -> Option<&Binding> {
        // RFC 8656 section 12 forbids assigning a channel that is still bound.
        let mut available = None;
        for _ in MIN_CHANNEL_NUMBER..=MAX_CHANNEL_NUMBER {
            let candidate = self.assign_channel_number();
            if !self.chan_map.contains_key(&candidate) {
                available = Some(candidate);
                break;
            }
        }
        // Every number is taken: take one whose binding expired at least five minutes ago.
        if available.is_none()
            && let Some(old) = self
                .addr_map
                .values()
                .find(|b| b.is_reusable(now))
                .map(|b| b.number)
        {
            self.delete_by_number(old);
            available = Some(old);
        }
        let number = available?;
        let b = Binding {
            number,
            st: BindingState::Idle,
            addr,
            refreshed_at: now,
            bound: false,
            used: false,
            last_request_at: None,
            retry_at: None,
        };

        self.chan_map.insert(b.number, b.addr.to_string());
        self.addr_map.insert(b.addr.to_string(), b);
        self.addr_map.get(&addr.to_string())
    }

    pub(crate) fn find_by_addr(&self, addr: &SocketAddr) -> Option<&Binding> {
        self.addr_map.get(&addr.to_string())
    }

    pub(crate) fn get_by_addr(&mut self, addr: &SocketAddr) -> Option<&mut Binding> {
        self.addr_map.get_mut(&addr.to_string())
    }

    pub(crate) fn find_by_number(&self, number: u16) -> Option<&Binding> {
        let s = self.chan_map.get(&number)?;
        self.addr_map.get(s)
    }

    pub(crate) fn get_by_number(&mut self, number: u16) -> Option<&mut Binding> {
        let s = self.chan_map.get(&number)?;
        self.addr_map.get_mut(s)
    }

    pub(crate) fn delete_by_addr(&mut self, addr: &SocketAddr) -> bool {
        if let Some(b) = self.addr_map.remove(&addr.to_string()) {
            self.chan_map.remove(&b.number);
            true
        } else {
            false
        }
    }

    pub(crate) fn delete_by_number(&mut self, number: u16) -> bool {
        if let Some(s) = self.chan_map.remove(&number) {
            self.addr_map.remove(&s);
            true
        } else {
            false
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.addr_map.len()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Binding> {
        self.addr_map.values_mut()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Binding> {
        self.addr_map.values()
    }
}
