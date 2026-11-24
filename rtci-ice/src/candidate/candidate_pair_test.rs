use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_pair::CandidatePair;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::candidate::{Candidate, CandidateConfig};

pub(crate) fn host_candidate() -> Result<Candidate> {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "0.0.0.0".to_owned(),
            component: COMPONENT_RTP,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
}

pub(crate) fn prflx_candidate() -> Result<Candidate> {
    CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "0.0.0.0".to_owned(),
            component: COMPONENT_RTP,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_peer_reflexive()
}

pub(crate) fn srflx_candidate() -> Result<Candidate> {
    CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "0.0.0.0".to_owned(),
            component: COMPONENT_RTP,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_server_reflexive()
}

pub(crate) fn relay_candidate() -> Result<Candidate> {
    CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "0.0.0.0".to_owned(),
            component: COMPONENT_RTP,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_relay()
}

/// RFC 8445 Section 6.1.2.3: pair priority = 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0),
/// G the controlling agent's candidate priority, D the controlled agent's.
#[test]
fn test_candidate_pair_priority() -> Result<()> {
    const HOST_INDEX: usize = 0;
    const PRFLX_INDEX: usize = 1;
    const SRFLX_INDEX: usize = 2;
    const RELAY_INDEX: usize = 3;

    let candidates = [
        host_candidate()?,
        prflx_candidate()?,
        srflx_candidate()?,
        relay_candidate()?,
    ];

    let tests = vec![
        (
            CandidatePair::new(
                HOST_INDEX,
                HOST_INDEX,
                candidates[HOST_INDEX].priority(),
                candidates[HOST_INDEX].priority(),
                false,
            ),
            9151314442783293438,
        ),
        (
            CandidatePair::new(
                HOST_INDEX,
                HOST_INDEX,
                candidates[HOST_INDEX].priority(),
                candidates[HOST_INDEX].priority(),
                true,
            ),
            9151314442783293438,
        ),
        (
            CandidatePair::new(
                HOST_INDEX,
                PRFLX_INDEX,
                candidates[HOST_INDEX].priority(),
                candidates[PRFLX_INDEX].priority(),
                true,
            ),
            7998392938176446463,
        ),
        (
            CandidatePair::new(
                HOST_INDEX,
                PRFLX_INDEX,
                candidates[HOST_INDEX].priority(),
                candidates[PRFLX_INDEX].priority(),
                false,
            ),
            7998392938176446462,
        ),
        (
            CandidatePair::new(
                HOST_INDEX,
                SRFLX_INDEX,
                candidates[HOST_INDEX].priority(),
                candidates[SRFLX_INDEX].priority(),
                true,
            ),
            7277816997797167103,
        ),
        (
            CandidatePair::new(
                HOST_INDEX,
                SRFLX_INDEX,
                candidates[HOST_INDEX].priority(),
                candidates[SRFLX_INDEX].priority(),
                false,
            ),
            7277816997797167102,
        ),
        (
            CandidatePair::new(
                HOST_INDEX,
                RELAY_INDEX,
                candidates[HOST_INDEX].priority(),
                candidates[RELAY_INDEX].priority(),
                true,
            ),
            72057594004373503,
        ),
        (
            CandidatePair::new(
                HOST_INDEX,
                RELAY_INDEX,
                candidates[HOST_INDEX].priority(),
                candidates[RELAY_INDEX].priority(),
                false,
            ),
            72057594004373502,
        ),
    ];

    for (pair, want) in tests {
        let got = pair.priority();
        assert_eq!(
            got, want,
            "CandidatePair({pair}).Priority() = {got}, want {want}"
        );
    }

    Ok(())
}

#[test]
fn test_candidate_pair_equality() -> Result<()> {
    const HOST_INDEX: usize = 0;
    const PRFLX_INDEX: usize = 1;
    const SRFLX_INDEX: usize = 2;
    const RELAY_INDEX: usize = 3;

    let candidates = [
        host_candidate()?,
        prflx_candidate()?,
        srflx_candidate()?,
        relay_candidate()?,
    ];

    let pair_a = CandidatePair::new(
        HOST_INDEX,
        SRFLX_INDEX,
        candidates[HOST_INDEX].priority(),
        candidates[SRFLX_INDEX].priority(),
        true,
    );
    let pair_b = CandidatePair::new(
        HOST_INDEX,
        SRFLX_INDEX,
        candidates[HOST_INDEX].priority(),
        candidates[SRFLX_INDEX].priority(),
        false,
    );

    assert_eq!(pair_a, pair_b, "Expected {pair_a} to equal {pair_b}");

    Ok(())
}

/// RFC 8445 Section 6.1.2.3 with the largest and smallest priorities a candidate can have
/// (Section 5.1.2: 1 to 2^31 - 1): the formula's 2^32 factor, and no overflow of 64 bits.
#[test]
fn test_candidate_pair_priority_bounds_and_role_bit() {
    const MAX: u32 = (1 << 31) - 1;
    let both_max = CandidatePair::new(0, 0, MAX, MAX, true);
    assert_eq!(
        both_max.priority(),
        (1u64 << 32) * u64::from(MAX) + 2 * u64::from(MAX)
    );
    assert_eq!(both_max.priority(), 9223372036854775806);

    // G = 5 (controlling), D = 3: 2^32 * 3 + 2 * 5 + 1.
    let controlling = CandidatePair::new(0, 0, 5, 3, true);
    assert_eq!(controlling.priority(), 12884901888 + 10 + 1);
    // The peer computes the same value from its side: its local candidate is D.
    let controlled = CandidatePair::new(0, 0, 3, 5, false);
    assert_eq!(controlled.priority(), controlling.priority());
    // G < D: no role bit.
    assert_eq!(
        CandidatePair::new(0, 0, 3, 5, true).priority(),
        12884901888 + 10
    );

    let both_min = CandidatePair::new(0, 0, 1, 1, false);
    assert_eq!(both_min.priority(), (1u64 << 32) + 2);
}
