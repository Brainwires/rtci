# Clause audit: draft-ietf-mmusic-mdns-ice-candidates

Spec: draft-ietf-mmusic-mdns-ice-candidates-03, 5 December 2021 (expired; -03 is the last
revision, no -04 exists). Audited against fork master 8916bc3. Code: `rtc-ice/src/mdns/`,
`rtc-ice/src/agent/{mod,agent_proto,agent_stats}.rs`, `rtc-mdns/src/proto/mod.rs`,
`src/peer_connection/{internal.rs,handler/demuxer.rs,sdp/mod.rs}`.

The engine is sans-I/O and gathers nothing: the application adds host candidates and the agent
(`MulticastDnsMode::QueryAndGather`) replaces their addresses with names. `QueryOnly` is the
default (resolve, do not publish). "proc" rows are procedure steps that carry no RFC 2119 keyword.

Totals (rows; MUST includes MUST NOT, SHOULD includes SHOULD NOT):

- MUST: tested 4 / untested 4 / partial 1 / missing 0 / violated 3 / n/a 0 (rows: 12)
- SHOULD: tested 2 / untested 2 / partial 1 / missing 4 / violated 1 / n/a 5 (rows: 15)
- MAY: tested 1 / untested 1 / partial 0 / missing 2 / violated 0 / n/a 1 (rows: 5)
- Procedure steps (no keyword): tested 5 / untested 1 / partial 2 / missing 2 / violated 0 / n/a 0 (rows: 10)

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| MDNSICE-3.1.1-1 | 3.1.1 step 3 | MUST | Generated name is a version 4 UUID followed by `.local` | tested | `rtc-ice/src/mdns/mod.rs:34` `generate_multicast_dns_name` | `mdns_test.rs::test_generate_multicast_dnsname`, `agent_test.rs::test_query_and_gather_hides_every_local_address` | `multicast_dns_local_name` lets an application publish a non-UUID name (fixed-IP mode); only the label syntax is checked (`is_valid_local_mdns_name`) |
| MDNSICE-3.1.1-2 | 3.1.1 step 4 | SHOULD | Send an mDNS announcement for the registered hostname | missing | `rtc-mdns/src/proto/mod.rs:346` `add_local_name` only stores the record | — | No unsolicited response is ever queued; see RFC6762-8.3-1 |
| MDNSICE-3.1.1-3 | 3.1.1 step 4 | SHOULD | Skip probing of the (unique) hostname | untested | no probing code exists | — | Nothing asserts that registering a name writes no packet |
| MDNSICE-3.1.1-4 | 3.1.1 steps 2, 5 | proc | Store name per IP and reuse it for that address | tested | `rtc-ice/src/agent/mod.rs:594-615` `mdns_name_for`, `mdns_local_names` | `test_query_and_gather_hides_every_local_address` (UDP and TCP on one address share a name) | Kept for the agent's life, ICE restarts included |
| MDNSICE-3.1.1-5 | 3.1.1 step 6 | proc | Replace the candidate's IP with the name and hand it to the application | tested | `rtc-ice/src/agent/mod.rs:480-499`; `src/peer_connection/internal.rs:1798-1840` | `test_query_and_gather_hides_every_local_address`; env `testenv_mdns` | |
| MDNSICE-3.1.1-6 | 3.1.1 | SHOULD | Still provide mDNS candidates when mDNS is unsupported or registration fails | partial | `rtc-ice/src/agent/mod.rs:490-498` | `mdns_test.rs::test_add_local_name_refuses_duplicates_and_caps` (cap only) | Registration cannot fail otherwise; past 64 names the host candidate is dropped instead of being provided |
| MDNSICE-3.1.1-7 | 3.1.1 | MUST | IPv4 and IPv6 addresses of an interface get different names | tested | `mdns_name_for` (one name per `IpAddr`) | `test_query_and_gather_hides_every_local_address`, `mdns_test.rs::test_registered_names_resolve_to_their_own_addresses` | Fixed-IP mode hides only that one IPv4 address; every other address stays literal |
| MDNSICE-3.1.2.1-1 | 3.1.2.1 | SHOULD | Provide the candidate as soon as the name is generated, whatever the announcement state | tested | `Agent::add_local_candidate` (synchronous) | `test_query_and_gather_hides_every_local_address` | |
| MDNSICE-3.1.2.2-1 | 3.1.2.2 | MUST NOT | A server-reflexive candidate is not redundant with the mDNS host candidate | untested | `rtc-ice/src/candidate/mod.rs:434-441` `equal` compares type and address string | — | Holds by construction; no test adds srflx beside a hidden host |
| MDNSICE-3.1.2.2-2 | 3.1.2.2 | MUST | That srflx candidate has raddr `0.0.0.0`/`::` and rport `9` | violated | `rtc-ice/src/agent/mod.rs:548-568` `apply_nat_1to1` sets `rel_addr: local_ip`; `agent_config.rs:62-65` refuses only the `Host` mapping with `QueryAndGather` | — | `nat_1to1_ips` with `Srflx` + `QueryAndGather` signals the hidden private IP in raddr. Application-added srflx/relay candidates keep whatever raddr they carry: nothing rewrites it |
| MDNSICE-3.1.2.2-3 | 3.1.2.2 | SHOULD | Provide mDNS-wrapped candidates first, server-reflexive ones after | n/a | — | — | Application gathers; order is its |
| MDNSICE-3.1.2.2-4 | 3.1.2.2 | MAY | Cache "address is public" and skip mDNS protection for it later | missing | — | — | No exposure policy at all: every host address is hidden (step 1 of 3.1.1 has no implementation) |
| MDNSICE-3.1.2.2-5 | 3.1.2.2 | SHOULD | Discard that cache when the STUN server set changes | n/a | — | — | No cache exists |
| MDNSICE-3.1.2.3-1 | 3.1.2.3 | MAY | Leave RFC 4941 temporary IPv6 addresses unconcealed | missing | — | — | No per-address policy; an application can only pass such a candidate with mDNS off |
| MDNSICE-3.1.2.4-1 | 3.1.2.4 | MUST | The mDNS name is the connection-address of the candidate attribute | tested | `rtc-ice/src/candidate/mod.rs:367-391` `marshal` | env `testenv_mdns` (asserts `.local ` in local candidate lines); `tests/mdns_query_and_gather_interop.rs` | |
| MDNSICE-3.1.2.4-2 | 3.1.2.4 | MUST NOT | The mDNS name is never used in the `c=` line | untested | `src/peer_connection/sdp/mod.rs:840-845`, `1015-1020`, `1505-1510` (constant `0.0.0.0`) | — | Constant by construction; no test asserts it with a hidden default candidate |
| MDNSICE-3.1.2.4-3 | 3.1.2.4 | MUST | `0.0.0.0`/`::` and port `9` in `c=` and `m=` instead | untested | same | — | Always `IN IP4 0.0.0.0`, port 9 |
| MDNSICE-3.1.2.4-4 | 3.1.2.4 | MUST | Candidates in local descriptions equal those given at gathering (no private host IPs) | tested | `src/peer_connection/internal.rs` `offered_local_candidates` (reads the agent's renamed candidates) | env `testenv_mdns` | Environment test only (Linux, `#[ignore]`d outside `run.sh`) |
| MDNSICE-3.2.1-1 | 3.2.1 step 1 | proc | Address not ending `.local`, or with more than one `.`, is processed per RFC 8445 | partial | `rtc-ice/src/agent/mod.rs:657-677`; `candidate_host.rs:22-36` | `mdns_name_test.rs::test_agent_resolves_only_uuid_names` | Host candidates: correct (dropped). A non-host candidate with a `.local` address, or any other FQDN, makes `unmarshal_candidate` fail with `ErrAddressParseFailed`, an error to the caller instead of an ignored candidate |
| MDNSICE-3.2.1-2 | 3.2.1 step 2 | proc | With ICE candidate policy `relay`, ignore the mDNS candidate | missing | `Agent::add_remote_candidate` has no policy check (`mod.rs:618-697`) | `agent_test.rs::test_candidate_type_filtering` asserts the opposite for remote candidates in general | A relay-only agent still sends mDNS queries for remote names and pairs the result |
| MDNSICE-3.2.1-3 | 3.2.1 step 3 | proc | Otherwise resolve the name with mDNS | tested | `mod.rs:689-692`, `agent_proto.rs:17-52` | `agent_test.rs::test_query_only_agent_queries_mdns_remote_candidate`, `test_published_mdns_host_candidates_resolve_at_the_peer`; env `testenv_mdns` | |
| MDNSICE-3.2.1-4 | 3.2.1 step 3 | SHOULD | Set the unicast-response (QU) bit in the query | missing | `rtc-mdns/src/proto/mod.rs:537-548` (class `DNSCLASS_INET`, bit clear) | — | Also no way to receive a unicast reply distinctly; see RFC6762-5.4-1 |
| MDNSICE-3.2.1-5 | 3.2.1 step 4 | proc | On resolution, replace the name with the IP and continue per RFC 8445 | tested | `agent_proto.rs:27-38`, `candidate/mod.rs:468` `set_ip` | `test_published_mdns_host_candidates_resolve_at_the_peer` | The candidate keeps the name in `address()`, the IP in `addr()` |
| MDNSICE-3.2.1-6 | 3.2.1 step 5 | proc | Otherwise ignore the candidate | untested | `agent_proto.rs:40-44`, `118-122` (query timeout drops it) | `rtc-mdns` `mdns_timeout_test.rs::test_query_respect_timeout` covers the timer only | No agent-level test that a timed-out name leaves no candidate. `AgentConfig::multicast_dns_query_timeout` defaults to `None`: a bare `rtc-ice` agent queries forever (the peer connection sets 10 s) |
| MDNSICE-3.2.2-1 | 3.2.2 | SHOULD | Ignore a candidate whose name resolves to more than one IP address | missing | `rtc-mdns/src/proto/mod.rs:776-789` (first matching record wins, query removed) | — | A response with two A records, or A and AAAA, resolves to whichever is first |
| MDNSICE-3.2.2-2 | 3.2.2 | MAY | Further restrict which candidates are resolved | tested | `rtc-ice/src/agent/remote_policy.rs`, `MAX_PENDING_MDNS_QUERIES` (`mod.rs:121`) | `remote_policy_test.rs::test_remote_address_filter_refuses_candidates`, `agent_test.rs::test_mdns_resolved_candidates_respect_the_remote_candidate_cap` | |
| MDNSICE-3.2.2-3 | 3.2.2 | SHOULD NOT | Do not resolve names not in the UUID format | tested | `rtc-ice/src/mdns/mod.rs:47-58` `is_ice_mdns_name` | `mdns_name_test.rs::test_ice_mdns_names_are_uuids`, `test_agent_resolves_only_uuid_names` | UUID version nibble not checked (documented) |
| MDNSICE-3.3.1-1 | 3.3.1 | MUST NOT | Candidate statistics do not contain the IP of a local or remote mDNS candidate | untested | `rtc-ice/src/agent/agent_stats.rs:257,276` (`ip: c.address()`), `src/peer_connection/transport/ice/candidate.rs:145`, `internal.rs:1762` | — | The name is what is stored; no test reads stats of an mDNS candidate |
| MDNSICE-3.3.1-2 | 3.3.1 | SHOULD | The mDNS name is used in statistics instead | untested | same | — | |
| MDNSICE-3.3.1-3 | 3.3.1 | SHOULD NOT | Statistics do not leak whether mDNS resolution succeeded | violated | `src/peer_connection/internal.rs:1789-1792` registers a remote candidate only when the agent returns `true`; a `.local` one returns `false` (`mod.rs:694`) and appears only once resolved and paired (`update_ice_agent_stats`) | — | A remote mDNS candidate is in the report if and only if it resolved |
| MDNSICE-3.3.1-4 | 3.3.1 | SHOULD | An `RTCIceCandidateStats` exists for every submitted remote mDNS candidate, ignored or not | missing | same | — | |
| MDNSICE-3.3.1-5 | 3.3.1 | MUST NOT | No peer-reflexive candidate IP in statistics unless that IP was already signalled | violated | `src/peer_connection/internal.rs:1854-1910` `update_ice_agent_stats` registers a prflx remote candidate with its address | — | The prflx candidate a check creates before the peer's `.local` name resolves (draft §6.2, §6.3) exposes the hidden host IP |
| MDNSICE-3.3.2-1 | 3.3.2 | MUST NOT | No candidate pair between a local relay candidate and a remote mDNS candidate | violated | `rtc-ice/src/candidate/mod.rs:449-461` `can_pair_with`, `agent/mod.rs:1181-1204` `add_pair`: no such rule | — | The resolved private address is sent to the TURN server in CreatePermission / Send |
| MDNSICE-3.3.2-2 | 3.3.2 | MAY | Pair local mDNS candidates with remote relay candidates | untested | no restriction | — | |
| MDNSICE-3.3.3-1 | 3.3.3 | SHOULD | Registered names are scoped to the web application origin | n/a | — | — | Browser concept; names are per agent |
| MDNSICE-3.3.3-2 | 3.3.3 | SHOULD | Registered names live no longer than the page | n/a | — | — | Per agent: gone at `close()` (without a goodbye, RFC6762-10.1-1) |
| MDNSICE-3.3.4-1 | 3.3.4 | SHOULD NOT | No names registered in third-party or private browsing contexts | n/a | — | — | Browser concept |
| MDNSICE-3.3.5-1 | 3.3.5 | proc | Limit the number of names exposed | tested | `rtc-mdns/src/proto/mod.rs:47` `MAX_LOCAL_NAMES` = 64 | `mdns_test.rs::test_add_local_name_refuses_duplicates_and_caps` | 64 is a memory bound, not "a small value" |
| MDNSICE-4-1 | 4 | proc | `.local` FQDN candidates may be generated and processed; other FQDNs stay ignored | partial | `candidate_host.rs:22-36`, `candidate_server_reflexive.rs:28-31` | `test_agent_resolves_only_uuid_names` | Other FQDNs are an error from `unmarshal_candidate`, not an ignored line (see 3.2.1-1) |
| MDNSICE-7.1-1 | 7.1 | MUST | An implementation-wide rate limit covers all mDNS queries and responses of gathering and processing | partial | caps only: `MAX_PENDING_MDNS_QUERIES` 32, `MAX_LOCAL_NAMES` 64, `MAX_REMOTE_CANDIDATES` 256 | `test_mdns_resolved_candidates_respect_the_remote_candidate_cap` | No rate limit: every pending query is resent each second, every received question is answered at once, and the caps are per agent, not per process |
| MDNSICE-7.1-2 | 7.1 | MAY | More specific (per-origin) rate limits | n/a | — | — | Browser concept |
| MDNSICE-7.1-3 | 7.1 | proc | Goodbye responses when names are removed | missing | `rtc-mdns/src/proto/mod.rs:1147-1155` `close` clears queues | — | See RFC6762-10.1-1 |

## Gaps, in order of importance

1. **Privacy leaks around hidden addresses (M).** MDNSICE-3.3.2-1 (relay × remote-mDNS pairs),
   MDNSICE-3.3.1-5 (peer-reflexive IP in stats), MDNSICE-3.1.2.2-2 (srflx raddr). Work: mark a
   remote candidate as "mDNS" (it already keeps its name in `address()`), refuse `add_pair` when
   the local candidate is a relay and the remote is mDNS; in stats, blank the address of a
   peer-reflexive remote candidate unless a signalled candidate has the same IP; in
   `QueryAndGather`, write raddr `0.0.0.0` / rport `9` on srflx/relay candidates whose base is a
   hidden address (and in `apply_nat_1to1`). Tests for each.
2. **Relay policy ignores remote mDNS candidates (S).** MDNSICE-3.2.1-2: drop `.local` remote
   candidates when `candidate_types == [Relay]`.
3. **Stats presence does not depend on resolution (S).** MDNSICE-3.3.1-3, -4, and tests for
   -1/-2: register an accumulator for every remote `.local` candidate at `add_ice_candidate`.
4. **Announce on registration, goodbye on close (M).** MDNSICE-3.1.1-2, MDNSICE-7.1-3; shared
   with RFC 6762 §8.3, §10.1, §10.2.
5. **QU bit and multi-address answers (S/M).** MDNSICE-3.2.1-4 (set the QU bit on the first
   query), MDNSICE-3.2.2-1 (collect the answers of a response and drop the candidate when a name
   has more than one address).
6. **Rate limit (M).** MDNSICE-7.1-1: a token bucket over everything `Mdns` queues, plus
   back-off of query retries (RFC6762-5.2-2).
7. **Ignore instead of fail (S).** MDNSICE-3.2.1-1, MDNSICE-4-1: non-host `.local` candidates
   and other FQDNs are dropped without an error.
8. **Tests for what holds by construction (S).** MDNSICE-3.1.1-3, -3.1.2.2-1, -3.1.2.4-2/-3,
   -3.2.1-6, -3.3.2-2.
9. **Optional exposure policy (M, MAY).** MDNSICE-3.1.2.2-4, -3.1.2.3-1.

## Bugs found

- **Local relay candidates pair with resolved mDNS candidates** (`rtc-ice/src/agent/mod.rs:1181`,
  `candidate/mod.rs:449`). Reproduce: agent with one local relay candidate (UDP4), add remote
  `<uuid>.local` host candidate, deliver an mDNS answer; assert `candidate_pairs` is empty. Today
  it holds one pair and checks go out through TURN to the hidden IP.
- **`nat_1to1_ips` (Srflx) with `QueryAndGather` signals the private IP as raddr**
  (`rtc-ice/src/agent/mod.rs:548-568`). Reproduce: `AgentConfig { nat_1to1_ips: ["203.0.113.7"],
  nat_1to1_ip_candidate_type: ServerReflexive, multicast_dns_mode: QueryAndGather }`, add host
  `10.0.1.5`; the second local candidate marshals `... typ srflx raddr 10.0.1.5 rport ...`.
- **Peer-reflexive remote address reaches `get_stats`** (`src/peer_connection/internal.rs:1854`).
  Reproduce: two peer connections, the answerer `QueryAndGather`; withhold its candidates from the
  offerer, let its checks create a prflx remote candidate, read the offerer's stats: the prflx
  candidate's `address` is the hidden IP.
- **A remote mDNS candidate's stats entry reveals whether it resolved**
  (`src/peer_connection/internal.rs:1789`). Reproduce: add a `.local` remote candidate, never
  answer the query, `get_stats`: no remote-candidate object; answer it and one appears.
- **Relay-only policy still resolves remote `.local` names** (`rtc-ice/src/agent/mod.rs:657`).
  Reproduce: `candidate_types: [Relay]`, add a `.local` remote candidate, `handle_timeout`,
  `poll_write` yields an mDNS query to 224.0.0.251:5353.
- **A `.local` remote candidate is filtered as UDP4 before it resolves**
  (`rtc-ice/src/candidate/candidate_host.rs:32-35`, `agent/mod.rs:633-643`). Reproduce:
  `network_types: [Udp6]`, add a remote `<uuid>.local` UDP candidate that would resolve to an
  IPv6 address: dropped as "network type Udp4", no query sent. Same for a `tcp` `.local`
  candidate with `network_types: [Tcp4]`.
