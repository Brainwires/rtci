//! Which STUN / TURN servers each ICE generation of each transport gathers from.
//!
//! W3C webrtc-pc, "set the configuration": "Set the ICE Agent's ICE servers list to
//! iceServers. As defined in [RFC9429], if a new list of servers replaces the ICE Agent's
//! existing ICE servers list, no action will be taken until the next gathering phase. If a
//! script wants this to happen immediately, it should do an ICE restart." RFC 9429 section
//! 4.1.18 says the same. So the list `set_configuration` gives is the one a generation that
//! begins afterwards (an ICE restart, a new transport) gathers from; a generation already
//! gathering keeps the list it began with.

use crate::peer_connection::handler::transport_set::TransportId;
use ice::url::Url;

/// The latest list, and the list each transport's current generation took.
#[derive(Default)]
pub(crate) struct ServersInForce {
    latest: Vec<Url>,
    taken: Vec<(TransportId, String, Vec<Url>)>,
}

impl ServersInForce {
    pub(crate) fn new(urls: Vec<Url>) -> Self {
        Self {
            latest: urls,
            taken: vec![],
        }
    }

    /// The configuration's new list: generations that begin from now on take it.
    pub(crate) fn set(&mut self, urls: Vec<Url>) {
        self.latest = urls;
    }

    /// The list the generation `ufrag` of `transport` gathers from, and whether it took it
    /// just now (its first call: a new gathering phase).
    pub(crate) fn for_generation(
        &mut self,
        transport: TransportId,
        ufrag: &str,
    ) -> (Vec<Url>, bool) {
        match self.taken.iter_mut().find(|(t, _, _)| *t == transport) {
            Some((_, u, list)) if u == ufrag => (list.clone(), false),
            Some((_, u, list)) => {
                *u = ufrag.to_owned();
                *list = self.latest.clone();
                (list.clone(), true)
            }
            None => {
                self.taken
                    .push((transport, ufrag.to_owned(), self.latest.clone()));
                (self.latest.clone(), true)
            }
        }
    }

    /// Whether any generation could gather from a server: the latest list or one in use.
    pub(crate) fn any(&self) -> bool {
        !self.latest.is_empty() || self.taken.iter().any(|(_, _, l)| !l.is_empty())
    }

    /// Forgets the transports not in `ids`.
    pub(crate) fn retain_transports(&mut self, ids: &[TransportId]) {
        self.taken.retain(|(t, _, _)| ids.contains(t));
    }
}

/// The same server, credentials included (a TURN server given new credentials is a new
/// allocation).
pub(crate) fn same_url(a: &Url, b: &Url) -> bool {
    a.scheme == b.scheme
        && a.proto == b.proto
        && a.host.eq_ignore_ascii_case(&b.host)
        && a.port == b.port
        && a.username == b.username
        && a.password == b.password
}
