use super::*;
use crate::rand::generate_cand_id;

/// The config required to create a new `CandidateHost`.
#[derive(Default)]
pub struct CandidateHostConfig {
    /// The fields shared by every candidate type.
    pub base_config: CandidateConfig,

    /// The TCP role, for ICE-TCP host candidates.
    pub tcp_type: TcpType,
}

impl CandidateHostConfig {
    /// Creates a new host candidate.
    pub fn new_candidate_host(self) -> Result<Candidate> {
        let component = checked_component_and_priority(&self.base_config)?;
        let mut candidate_id = self.base_config.candidate_id;
        if candidate_id.is_empty() {
            candidate_id = generate_cand_id();
        }

        let (resolved_addr, network_type) = if !self.base_config.address.ends_with(".local") {
            let ip: IpAddr = match self.base_config.address.parse() {
                Ok(ip) => ip,
                Err(_) => return Err(Error::ErrAddressParseFailed),
            };
            (
                SocketAddr::new(ip, self.base_config.port),
                determine_network_type(&self.base_config.network, &ip)?,
            )
        } else {
            // An mDNS name (draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.4): the family is
            // known only once the name resolves (`set_ip`), but the transport is the
            // candidate's own. A TCP candidate under a name stays TCP (RFC 6544 section 4.5),
            // or it would be signalled, and paired, as UDP on the TCP port.
            let network_type = if self.base_config.network.to_lowercase().starts_with("tcp") {
                NetworkType::Tcp4
            } else {
                NetworkType::Udp4
            };
            (SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0), network_type)
        };

        Ok(Candidate {
            id: candidate_id,
            network_type,
            candidate_type: CandidateType::Host,
            address: self.base_config.address,
            port: self.base_config.port,
            resolved_addr,
            component,
            foundation_override: self.base_config.foundation,
            priority_override: self.base_config.priority,
            network: self.base_config.network,
            tcp_type: self.tcp_type,
            ..Candidate::default()
        })
    }
}
