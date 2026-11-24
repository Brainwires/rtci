//! 1:1 NAT address mapping: advertising a host's public address for its local one.
//!
//! A server behind a 1:1 NAT (a cloud instance with an elastic / floating IP) is reachable at
//! a public address that no local interface carries. Configured with that address
//! (`AgentConfig::nat_1to1_ips`), the agent rewrites the host candidates the application adds:
//!
//! - as [`CandidateType::Host`] (the default), a host candidate on a mapped local address is
//!   advertised with the public address instead, while its base stays the local socket it is
//!   bound to;
//! - as [`CandidateType::ServerReflexive`], the host candidate is kept and a server-reflexive
//!   candidate on the public address (related address: the local one) is added beside it.
//!
//! Each entry of the list is `"<external ip>"` (the one external address for every local
//! address of that family) or `"<external ip>/<local ip>"` (an explicit mapping); the two forms
//! cannot be mixed within a family. Ported from webrtc-rs `ice::external_ip_mapper`.

#[cfg(test)]
mod external_ip_mapper_test;

use std::collections::HashMap;
use std::net::IpAddr;

use crate::candidate::CandidateType;
use shared::error::*;

pub(crate) fn validate_ip_string(ip_str: &str) -> Result<IpAddr> {
    ip_str
        .parse()
        .map_err(|_| Error::ErrInvalidNat1to1IpMapping)
}

/// The mapping of local to external addresses for one IP family.
#[derive(Default, PartialEq, Eq, Debug)]
pub(crate) struct IpMapping {
    /// When set, the one external address for every local address of the family.
    pub(crate) ip_sole: Option<IpAddr>,
    /// Local-to-external mapping.
    pub(crate) ip_map: HashMap<IpAddr, IpAddr>,
}

impl IpMapping {
    pub(crate) fn set_sole_ip(&mut self, ip: IpAddr) -> Result<()> {
        if self.ip_sole.is_some() || !self.ip_map.is_empty() {
            return Err(Error::ErrInvalidNat1to1IpMapping);
        }
        self.ip_sole = Some(ip);
        Ok(())
    }

    pub(crate) fn add_ip_mapping(&mut self, loc_ip: IpAddr, ext_ip: IpAddr) -> Result<()> {
        if self.ip_sole.is_some() || self.ip_map.contains_key(&loc_ip) {
            return Err(Error::ErrInvalidNat1to1IpMapping);
        }
        self.ip_map.insert(loc_ip, ext_ip);
        Ok(())
    }

    pub(crate) fn find_external_ip(&self, loc_ip: IpAddr) -> Result<IpAddr> {
        if let Some(ip_sole) = self.ip_sole {
            return Ok(ip_sole);
        }
        self.ip_map
            .get(&loc_ip)
            .copied()
            .ok_or(Error::ErrExternalMappedIpNotFound)
    }
}

/// Maps local addresses to the external addresses a 1:1 NAT gives them.
#[derive(Default, Debug)]
pub(crate) struct ExternalIpMapper {
    pub(crate) ipv4_mapping: IpMapping,
    pub(crate) ipv6_mapping: IpMapping,
    /// How the external address is advertised: `Host` or `ServerReflexive`.
    pub(crate) candidate_type: CandidateType,
}

impl ExternalIpMapper {
    /// Builds a mapper from `AgentConfig::nat_1to1_ips`; `None` when the list is empty.
    pub(crate) fn new(mut candidate_type: CandidateType, ips: &[String]) -> Result<Option<Self>> {
        if ips.is_empty() {
            return Ok(None);
        }
        if candidate_type == CandidateType::Unspecified {
            candidate_type = CandidateType::Host; // defaults to host
        } else if candidate_type != CandidateType::Host
            && candidate_type != CandidateType::ServerReflexive
        {
            return Err(Error::ErrUnsupportedNat1to1IpCandidateType);
        }

        let mut m = Self {
            ipv4_mapping: IpMapping::default(),
            ipv6_mapping: IpMapping::default(),
            candidate_type,
        };

        for ext_ip_str in ips {
            let ip_pair: Vec<&str> = ext_ip_str.split('/').collect();
            if ip_pair.is_empty() || ip_pair.len() > 2 {
                return Err(Error::ErrInvalidNat1to1IpMapping);
            }

            let ext_ip = validate_ip_string(ip_pair[0])?;
            if ip_pair.len() == 1 {
                if ext_ip.is_ipv4() {
                    m.ipv4_mapping.set_sole_ip(ext_ip)?;
                } else {
                    m.ipv6_mapping.set_sole_ip(ext_ip)?;
                }
            } else {
                let loc_ip = validate_ip_string(ip_pair[1])?;
                if ext_ip.is_ipv4() != loc_ip.is_ipv4() {
                    return Err(Error::ErrInvalidNat1to1IpMapping);
                }
                if ext_ip.is_ipv4() {
                    m.ipv4_mapping.add_ip_mapping(loc_ip, ext_ip)?;
                } else {
                    m.ipv6_mapping.add_ip_mapping(loc_ip, ext_ip)?;
                }
            }
        }

        Ok(Some(m))
    }

    /// The external address for the local address `local_ip_str`.
    pub(crate) fn find_external_ip(&self, local_ip_str: &str) -> Result<IpAddr> {
        let loc_ip = validate_ip_string(local_ip_str)?;
        self.find_external(loc_ip)
    }

    /// The external address for `loc_ip`.
    pub(crate) fn find_external(&self, loc_ip: IpAddr) -> Result<IpAddr> {
        if loc_ip.is_ipv4() {
            self.ipv4_mapping.find_external_ip(loc_ip)
        } else {
            self.ipv6_mapping.find_external_ip(loc_ip)
        }
    }
}
