//! rtci-ice against librice's sans-I/O agent (rice-proto 0.4.3, an independent RFC 8445
//! implementation), in memory with virtual time: full ICE with either side controlling,
//! trickled candidates (RFC 8838), rtci-ice as an ICE lite agent (RFC 8445 2.5) under a full
//! rice controller, and a role conflict (RFC 8445 7.3.1.1) resolved from both starting
//! roles. Candidates cross as SDP `a=candidate` lines (RFC 8839 5.1), as they would in an
//! offer or answer.

use bytes::BytesMut;
use ice::agent::Agent as RtcAgent;
use ice::agent::agent_config::AgentConfig;
use ice::candidate::candidate_host::CandidateHostConfig;
use ice::candidate::{CandidateConfig, CandidateType, unmarshal_candidate};
use ice::mdns::MulticastDnsMode;
use ice::state::ConnectionState;
use rice_proto::agent::{Agent as RiceAgent, AgentPoll};
use rice_proto::candidate::{Candidate as RiceCandidate, TransportType};
use rice_proto::component::ComponentConnectionState;
use rice_proto::stream::Credentials;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

const RTC_ADDR: &str = "192.168.10.1:5000";
const RICE_ADDR: &str = "192.168.10.2:6000";

struct Pair {
    rtc: RtcAgent,
    rice: RiceAgent,
    stream: usize,
    component: usize,
    now: Instant,
    start: Instant,
    rice_wait: Option<stun_proto::Instant>,
    rice_state: ComponentConnectionState,
    /// The pair rice selected (AgentPoll::SelectedPair): local and remote addresses.
    rice_selected: Option<(SocketAddr, SocketAddr)>,
    /// rice's gathered candidates, as SDP lines, not yet given to rtci-ice.
    rice_candidates: Vec<String>,
    /// Hold rice's candidates back from rtci-ice until released (trickle).
    hold: bool,
    /// Binding requests each side sent.
    to_rice: usize,
    to_rtc: usize,
}

fn rtc_host(addr: &str) -> R<ice::candidate::Candidate> {
    let a: SocketAddr = addr.parse()?;
    Ok(CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: a.ip().to_string(),
            port: a.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?)
}

impl Pair {
    fn new(rtc_controlling: bool, rice_controlling: bool, rtc_lite: bool, hold: bool) -> R<Pair> {
        let now = Instant::now();
        let mut config = AgentConfig {
            multicast_dns_mode: MulticastDnsMode::Disabled,
            lite: rtc_lite,
            is_controlling: rtc_controlling,
            ..Default::default()
        };
        if rtc_lite {
            // A lite agent has host candidates only (RFC 8445 2.5).
            config.candidate_types = vec![CandidateType::Host];
        }
        let mut rtc = RtcAgent::new(now, Arc::new(config), crypto::default_provider()?)?;
        rtc.add_local_candidate(rtc_host(RTC_ADDR)?)?;

        let mut rice = RiceAgent::builder()
            .controlling(rice_controlling)
            .trickle_ice(true)
            .build();
        let stream = rice.add_stream();
        let component;
        {
            let mut s = rice.mut_stream(stream).ok_or("no stream")?;
            component = s.add_component()?;
            s.set_local_credentials(Credentials::new(
                "riceufrag1234".into(),
                "ricepasswordricepassword".into(),
            ));
            let rc = rtc.get_local_credentials().clone();
            s.set_remote_credentials(Credentials::new(rc.ufrag, rc.pwd));
            // rtci-ice's candidate, as its description would carry it.
            let line = format!("a=candidate:{}", rtc_host(RTC_ADDR)?.marshal());
            s.add_remote_candidate(
                line.parse::<RiceCandidate>()
                    .map_err(|e| format!("{e:?}"))?,
            );
            s.end_of_remote_candidates();
            s.mut_component(component)
                .ok_or("no component")?
                .gather_candidates(&[(TransportType::Udp, RICE_ADDR.parse()?)], &[], &[])?;
        }
        rtc.start_connectivity_checks(
            now,
            rtc_controlling,
            "riceufrag1234".into(),
            "ricepasswordricepassword".into(),
        )?;
        Ok(Pair {
            rtc,
            rice,
            stream,
            component,
            now,
            start: now,
            rice_wait: None,
            rice_state: ComponentConnectionState::New,
            rice_selected: None,
            rice_candidates: vec![],
            hold,
            to_rice: 0,
            to_rtc: 0,
        })
    }

    /// rice's clock: the same virtual time, on its own `Instant`.
    fn rice_now(&self) -> stun_proto::Instant {
        stun_proto::Instant::from_nanos((self.now - self.start).as_nanos() as i64)
    }

    fn release(&mut self) -> R {
        self.hold = false;
        for line in std::mem::take(&mut self.rice_candidates) {
            let raw = line.trim_start_matches("a=candidate:");
            self.rtc.add_remote_candidate(unmarshal_candidate(raw)?)?;
        }
        Ok(())
    }

    fn poll_rice(&mut self) -> R<bool> {
        let mut moved = false;
        loop {
            match self.rice.poll(self.rice_now()) {
                AgentPoll::WaitUntil(t) => {
                    self.rice_wait = Some(t);
                    break;
                }
                AgentPoll::Closed => break,
                AgentPoll::GatheredCandidate(g) => {
                    moved = true;
                    self.rice_candidates
                        .push(g.gathered.candidate.to_sdp_string());
                    let mut s = self.rice.mut_stream(self.stream).ok_or("no stream")?;
                    s.add_local_gathered_candidate(g.gathered);
                }
                AgentPoll::GatheringComplete(_) => {
                    moved = true;
                    self.rice
                        .mut_stream(self.stream)
                        .ok_or("no stream")?
                        .end_of_local_candidates();
                }
                AgentPoll::ComponentStateChange(c) => {
                    moved = true;
                    self.rice_state = c.state;
                }
                AgentPoll::SelectedPair(sel) => {
                    moved = true;
                    let pair = sel.selected.candidate_pair();
                    self.rice_selected = Some((pair.local.address, pair.remote.address));
                }
                _ => moved = true,
            }
        }
        if !self.hold {
            self.release()?;
        }
        while let Some(t) = self.rice.poll_transmit(self.rice_now()) {
            moved = true;
            self.to_rtc += 1;
            let t = t.transmit;
            let _ = self.rtc.handle_read(TaggedBytesMut {
                now: self.now,
                transport: TransportContext {
                    local_addr: t.to,
                    peer_addr: t.from,
                    transport_protocol: TransportProtocol::UDP,
                    ecn: None,
                },
                message: BytesMut::from(&t.data[..]),
            });
        }
        Ok(moved)
    }

    fn poll_rtc(&mut self) -> R<bool> {
        let mut moved = false;
        while let Some(out) = self.rtc.poll_write() {
            moved = true;
            self.to_rice += 1;
            let transmit = stun_proto::agent::Transmit::new(
                out.message.to_vec(),
                TransportType::Udp,
                out.transport.local_addr,
                out.transport.peer_addr,
            );
            let now = self.rice_now();
            let mut s = self.rice.mut_stream(self.stream).ok_or("no stream")?;
            let _ = s.handle_incoming_data(self.component, transmit, now);
        }
        Ok(moved)
    }

    fn run_until(&mut self, what: &str, done: impl Fn(&Pair) -> bool) -> R {
        for _ in 0..2000 {
            for _ in 0..100 {
                let a = self.poll_rice()?;
                let b = self.poll_rtc()?;
                if !a && !b {
                    break;
                }
            }
            if done(self) {
                return Ok(());
            }
            self.now += Duration::from_millis(10);
            self.rtc.handle_timeout(self.now)?;
        }
        Err(format!(
            "{what} within 20 s of virtual time: rtci-ice {:?}, rice {:?}",
            self.rtc.state(),
            self.rice_state
        )
        .into())
    }

    fn both_connected(&self) -> bool {
        matches!(
            self.rtc.state(),
            ConnectionState::Connected | ConnectionState::Completed
        ) && self.rice_state == ComponentConnectionState::Connected
    }

    fn check_selected(&self) -> R {
        let (local, remote) = self
            .rtc
            .get_selected_candidate_pair()
            .ok_or("rtci-ice selected no pair")?;
        assert_eq!(format!("{}:{}", local.address(), local.port()), RTC_ADDR);
        assert_eq!(format!("{}:{}", remote.address(), remote.port()), RICE_ADDR);
        let (local, remote) = self.rice_selected.ok_or("rice selected no pair")?;
        assert_eq!(local.to_string(), RICE_ADDR);
        assert_eq!(remote.to_string(), RTC_ADDR);
        Ok(())
    }
}

#[test]
fn full_ice_rtc_controlling_rice_controlled_connects() -> R {
    let mut p = Pair::new(true, false, false, false)?;
    p.run_until("both connected", Pair::both_connected)?;
    p.check_selected()?;
    Ok(())
}

#[test]
fn full_ice_rice_controlling_rtc_controlled_connects() -> R {
    let mut p = Pair::new(false, true, false, false)?;
    p.run_until("both connected", Pair::both_connected)?;
    p.check_selected()?;
    Ok(())
}

/// rice's candidates reach rtci-ice only after a while: rtci-ice learns rice as a peer-reflexive
/// candidate from its checks first (RFC 8445 7.3.1.3), and the trickled candidate joins
/// the same pair (RFC 8838 11).
#[test]
fn trickled_candidates_arrive_after_the_checks_started() -> R {
    let mut p = Pair::new(true, false, false, true)?;
    for _ in 0..30 {
        p.poll_rice()?;
        p.poll_rtc()?;
        p.now += Duration::from_millis(10);
        p.rtc.handle_timeout(p.now)?;
    }
    assert!(!p.rice_candidates.is_empty(), "rice gathered no candidate");
    p.release()?;
    p.run_until("both connected", Pair::both_connected)?;
    p.check_selected()?;
    Ok(())
}

/// rtci-ice as a lite agent (only answers checks, RFC 8445 2.5) under rice controlling and
/// nominating.
#[test]
fn rtc_lite_agent_under_a_full_rice_controller_connects() -> R {
    let mut p = Pair::new(false, true, true, false)?;
    p.run_until("both connected", Pair::both_connected)?;
    p.check_selected()?;
    // A lite agent sends no checks of its own: everything rtci-ice sent answered rice.
    assert!(
        p.to_rice <= p.to_rtc,
        "rtci-ice (lite) sent {} for rice's {}",
        p.to_rice,
        p.to_rtc
    );
    Ok(())
}

/// Both sides start controlling (or both controlled): a 487 Role Conflict or a role switch
/// settles it (RFC 8445 7.3.1.1, 7.2.5.1), and the agents connect.
#[test]
fn role_conflict_both_controlling_is_resolved() -> R {
    let mut p = Pair::new(true, true, false, false)?;
    p.run_until("both connected", Pair::both_connected)?;
    assert_ne!(
        p.rtc.role(),
        p.rice.controlling(),
        "both kept the same role"
    );
    p.check_selected()?;
    Ok(())
}

#[test]
fn role_conflict_both_controlled_is_resolved() -> R {
    let mut p = Pair::new(false, false, false, false)?;
    p.run_until("both connected", Pair::both_connected)?;
    assert_ne!(
        p.rtc.role(),
        p.rice.controlling(),
        "both kept the same role"
    );
    p.check_selected()?;
    Ok(())
}
