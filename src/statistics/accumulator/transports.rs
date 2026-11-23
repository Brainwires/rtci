//! Statistics of several transports (webrtc-stats 7.1: one `transport` object per
//! `RTCDtlsTransport`, with the `candidate-pair`, `local-candidate` and `remote-candidate`
//! objects that name it, and RTP stream and codec objects whose `transportId` is the one their
//! m= section runs over).
//!
//! The pipeline's handlers update [`RTCStatsAccumulator::transport`], which holds the
//! statistics of the *active* transport (the one the connection is working on); the others
//! are parked here until their transport becomes the active one. A transport is keyed by the
//! connection's internal transport number; transport 0, the one the connection is built with,
//! keeps the name `RTCTransport` it had when there was only one.

use super::{RTCStatsAccumulator, TransportStatsAccumulator};
use std::collections::{BTreeMap, HashMap};

/// The name the accumulators give the `transport` object of transport `key`.
pub(crate) fn transport_stats_name(key: usize) -> String {
    if key == 0 {
        "RTCTransport".to_owned()
    } else {
        format!("RTCTransport_{key}")
    }
}

/// The statistics of the transports that are not the active one, and which transport each m=
/// section runs over.
#[derive(Debug, Default)]
pub(crate) struct ParkedTransports {
    /// The key of the transport whose statistics are in `RTCStatsAccumulator::transport`.
    active: usize,
    /// Every other transport's, by key.
    parked: BTreeMap<usize, TransportStatsAccumulator>,
    /// The transport key of each m= section assigned to a transport.
    sections: HashMap<String, usize>,
    /// The key of the transport a section not in `sections` is on (the default transport).
    default: usize,
}

impl RTCStatsAccumulator {
    /// Has the handlers' updates go to the statistics of transport `key` from now on: the
    /// active transport's are parked, and `key`'s (new ones the first time) take their place.
    pub(crate) fn activate_transport(&mut self, key: usize) {
        if key == self.transports.active {
            return;
        }
        let incoming =
            self.transports
                .parked
                .remove(&key)
                .unwrap_or_else(|| TransportStatsAccumulator {
                    transport_id: transport_stats_name(key),
                    local_certificate_id: self.transport.local_certificate_id.clone(),
                    ..Default::default()
                });
        let outgoing = std::mem::replace(&mut self.transport, incoming);
        let previous = std::mem::replace(&mut self.transports.active, key);
        self.transports.parked.insert(previous, outgoing);
    }

    /// The key of the transport whose statistics the handlers update.
    pub(crate) fn active_transport(&self) -> usize {
        self.transports.active
    }

    /// Transport `key` is gone: its `transport` object, and the candidate pairs and candidates
    /// that name it, are deleted (webrtc-stats 4.3: the objects of a closed transport are not
    /// reported once it is gone). The active transport is never retired.
    pub(crate) fn retire_transport(&mut self, key: usize) {
        if key == self.transports.active {
            return;
        }
        let Some(gone) = self.transports.parked.remove(&key) else {
            return;
        };
        let name = gone.transport_id;
        self.ice_candidate_pairs
            .retain(|_, pair| pair.transport_id != name);
        self.local_candidates
            .retain(|_, candidate| candidate.transport_id != name);
        self.remote_candidates
            .retain(|_, candidate| candidate.transport_id != name);
        self.transports.sections.retain(|_, on| *on != key);
    }

    /// Records which transport each m= section runs over (`sections` names the sections
    /// assigned to a transport, with its key; any other is on transport `default`), and moves
    /// the RTP streams already counted onto the `transport` object of their section.
    pub(crate) fn set_section_transports(&mut self, sections: &[(String, usize)], default: usize) {
        self.transports.sections = sections.iter().cloned().collect();
        self.transports.default = default;
        let names: HashMap<String, String> = self
            .inbound_rtp_streams
            .values()
            .map(|stream| stream.mid.clone())
            .chain(self.outbound_rtp_streams.values().map(|s| s.mid.clone()))
            .map(|mid| {
                let name = self.section_transport_id(&mid);
                (mid, name)
            })
            .collect();
        for stream in self.inbound_rtp_streams.values_mut() {
            if let Some(name) = names.get(&stream.mid) {
                stream.transport_id.clone_from(name);
            }
        }
        for stream in self.outbound_rtp_streams.values_mut() {
            if let Some(name) = names.get(&stream.mid) {
                stream.transport_id.clone_from(name);
            }
        }
    }

    /// The `transport` object name of the m= section `mid`.
    pub(crate) fn section_transport_id(&self, mid: &str) -> String {
        let key = self
            .transports
            .sections
            .get(mid)
            .copied()
            .unwrap_or(self.transports.default);
        self.transport_name(key)
    }

    /// The key of the transport the m= section `mid` runs over.
    pub(crate) fn section_transport_key(&self, mid: &str) -> usize {
        self.transports
            .sections
            .get(mid)
            .copied()
            .unwrap_or(self.transports.default)
    }

    /// Whether the connection has one transport only (none parked).
    pub(crate) fn transports_are_one(&self) -> bool {
        self.transports.parked.is_empty()
    }

    /// The name of transport `key`'s `transport` object.
    pub(crate) fn transport_name(&self, key: usize) -> String {
        if key == self.transports.active {
            self.transport.transport_id.clone()
        } else {
            self.transports
                .parked
                .get(&key)
                .map_or_else(|| transport_stats_name(key), |t| t.transport_id.clone())
        }
    }

    /// Whether an object naming the transport `name` is the active transport's: it names it,
    /// or names no transport the connection has.
    pub(crate) fn of_active_transport(&self, name: &str) -> bool {
        name == self.transport.transport_id
            || !self
                .transports
                .parked
                .values()
                .any(|transport| transport.transport_id == name)
    }

    /// Every transport's statistics, the active one's included, by key.
    pub(crate) fn every_transport(&self) -> Vec<&TransportStatsAccumulator> {
        let mut all: Vec<(usize, &TransportStatsAccumulator)> = self
            .transports
            .parked
            .iter()
            .map(|(key, transport)| (*key, transport))
            .collect();
        all.push((self.transports.active, &self.transport));
        all.sort_by_key(|(key, _)| *key);
        all.into_iter().map(|(_, transport)| transport).collect()
    }

    /// The statistics of transport `key`, mutably, wherever they are.
    pub(crate) fn transport_mut(&mut self, key: usize) -> Option<&mut TransportStatsAccumulator> {
        if key == self.transports.active {
            Some(&mut self.transport)
        } else {
            self.transports.parked.get_mut(&key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// webrtc-stats 7.1: each transport has its own `transport` object; what is counted while
    /// one is active stays its own when another becomes active.
    #[test]
    fn each_transport_counts_into_its_own_transport_object() {
        let mut stats = RTCStatsAccumulator::new();
        stats.transport.on_packet_sent(100, true);
        stats.activate_transport(2);
        assert_eq!(stats.transport.transport_id, "RTCTransport_2");
        assert_eq!(stats.transport.packets_sent, 0);
        stats.transport.on_packet_sent(10, true);
        stats.transport.on_packet_sent(10, true);
        stats.activate_transport(0);
        assert_eq!(stats.transport.transport_id, "RTCTransport");
        assert_eq!(stats.transport.packets_sent, 1);
        let all = stats.every_transport();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].transport_id, "RTCTransport_2");
        assert_eq!(all[1].packets_sent, 2);
    }

    /// A candidate pair formed while a transport is active names that transport, and is
    /// deleted with it.
    #[test]
    fn a_retired_transport_takes_its_pairs_with_it() {
        let mut stats = RTCStatsAccumulator::new();
        stats.get_or_create_candidate_pair("a", "b");
        stats.activate_transport(1);
        stats.get_or_create_candidate_pair("c", "d");
        stats.activate_transport(0);
        let names: Vec<String> = stats
            .ice_candidate_pairs
            .values()
            .map(|pair| pair.transport_id.clone())
            .collect();
        assert!(names.contains(&"RTCTransport_1".to_owned()));
        stats.retire_transport(1);
        assert_eq!(stats.ice_candidate_pairs.len(), 1);
        assert_eq!(stats.every_transport().len(), 1);
    }
}
