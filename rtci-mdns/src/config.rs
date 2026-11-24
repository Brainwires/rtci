//! `MdnsConfig`, the configuration for an mDNS connection.
//!
//! This module is private; the type is re-exported as [`crate::MdnsConfig`], where its
//! documentation and examples live so that rustdoc renders them and their doctests run.

use std::net::IpAddr;
use std::time::Duration;

use crate::proto::MdnsRateLimit;

/// Default interval between the first two queries of a series (1 second), which is also the
/// least RFC 6762 section 5.2 allows.
pub(crate) const DEFAULT_QUERY_INTERVAL: Duration = Duration::from_secs(1);

/// Default query timeout (30 seconds).
///
/// A query that is still unanswered then ends with
/// [`MdnsEvent::QueryTimeout`](crate::MdnsEvent::QueryTimeout). Change it with
/// [`MdnsConfig::with_query_timeout`], or remove it with
/// [`MdnsConfig::without_query_timeout`].
pub(crate) const DEFAULT_QUERY_TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));

/// TTL of the host-name records this crate publishes (RFC 6762 section 10: 120 seconds).
pub(crate) const RESPONSE_TTL: u32 = 120;

/// Default number of announcements of a new name (RFC 6762 section 8.3: at least two).
pub(crate) const DEFAULT_ANNOUNCE_COUNT: u8 = 2;

/// The most announcements RFC 6762 section 8.3 allows.
pub(crate) const MAX_ANNOUNCE_COUNT: u8 = 8;

/// Whether a name is probed for (RFC 6762 section 8.1) before it is announced and answered.
///
/// Probing asks the link three times, 250 ms apart, whether another host already uses the
/// name; a name somebody defends is given up
/// ([`MdnsEvent::LocalNameConflict`](crate::MdnsEvent::LocalNameConflict)). A name that cannot
/// already be in use skips the step (RFC 6762 section 8.1), which is what
/// draft-ietf-mmusic-mdns-ice-candidates section 3.1.1 asks for its random `<uuid>.local`
/// names.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MdnsProbePolicy {
    /// Probe, unless the name is `<uuid>.local` (a UUID in its textual form as the only label
    /// before `.local`).
    #[default]
    Auto,
    /// Probe for every name.
    Always,
    /// Never probe: every name is taken as unique.
    Never,
}

/// MdnsConfiguration for an mDNS connection.
///
/// Use the builder pattern to construct a configuration:
///
/// ```rust
/// use rtci_mdns::MdnsConfig;
/// use std::time::Duration;
///
/// let config = MdnsConfig::new()
///     .with_query_interval(Duration::from_secs(2))
///     .with_local_names(vec!["myhost.local".to_string()]);
/// ```
///
/// # Fields
///
/// - `query_interval`: The interval between the first two queries of a series; it doubles
///   after each retry (default and minimum: 1 second)
/// - `query_timeout`: Maximum time to wait for a query answer (default: 30 seconds)
/// - `local_names`: Names this connection will respond to (empty by default)
/// - `local_addr`: IP address to advertise in responses (required for server mode)
///
/// The other settings have builder methods only: [`with_first_query_delay`],
/// [`with_multi_question_delay`],
/// [`with_destination_reported`], [`with_unicast_response`], [`with_unicast_replies`],
/// [`with_multiple_addresses`],
/// [`with_probe_policy`], [`with_announce_count`], [`with_rate_limit`],
/// [`with_on_link_subnets`], [`with_jitter_seed`].
///
/// [`with_first_query_delay`]: MdnsConfig::with_first_query_delay
/// [`with_multi_question_delay`]: MdnsConfig::with_multi_question_delay
/// [`with_destination_reported`]: MdnsConfig::with_destination_reported
/// [`with_unicast_response`]: MdnsConfig::with_unicast_response
/// [`with_unicast_replies`]: MdnsConfig::with_unicast_replies
/// [`with_multiple_addresses`]: MdnsConfig::with_multiple_addresses
/// [`with_probe_policy`]: MdnsConfig::with_probe_policy
/// [`with_announce_count`]: MdnsConfig::with_announce_count
/// [`with_rate_limit`]: MdnsConfig::with_rate_limit
/// [`with_on_link_subnets`]: MdnsConfig::with_on_link_subnets
/// [`with_jitter_seed`]: MdnsConfig::with_jitter_seed
///
/// # Configuration scenarios
///
/// ## Client MdnsConfiguration
///
/// For a client that only sends queries:
///
/// ```rust
/// use rtci_mdns::MdnsConfig;
/// use std::time::Duration;
///
/// let config = MdnsConfig::default()
///     .with_query_interval(Duration::from_secs(2)); // Retry after 2 s, then 4 s, 8 s, ...
/// ```
///
/// ## Server MdnsConfiguration
///
/// For a server that responds to queries:
///
/// ```rust
/// use rtci_mdns::MdnsConfig;
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let config = MdnsConfig::default()
///     .with_local_names(vec![
///         "mydevice.local".to_string(),
///         "mydevice._http._tcp.local".to_string(),
///     ])
///     .with_local_ip(
///         IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
///     );
/// ```
///
/// ## Combined Client/Server
///
/// For a connection that both queries and responds:
///
/// ```rust
/// use rtci_mdns::MdnsConfig;
/// use std::net::{IpAddr, Ipv4Addr};
/// use std::time::Duration;
///
/// let config = MdnsConfig::default()
///     .with_query_interval(Duration::from_secs(1))
///     .with_local_names(vec!["myhost.local".to_string()])
///     .with_local_ip(
///         IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
///     );
/// ```
#[derive(Clone, Debug)]
pub struct MdnsConfig {
    /// The interval between the first two queries of a series.
    ///
    /// An unanswered query is sent again after this interval, then after twice it, four times
    /// it and so on, up to once an hour (RFC 6762 section 5.2), until an answer arrives, the
    /// query times out or it is cancelled. A value under one second is taken as one second,
    /// the least the RFC allows, and one over an hour as an hour; zero is taken as the
    /// default.
    ///
    /// Default: 1 second
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// // Retry after 2 s, 4 s, 8 s, ...
    /// let config = MdnsConfig::default()
    ///     .with_query_interval(Duration::from_secs(2));
    /// ```
    pub query_interval: Duration,

    /// Maximum time to wait for a query to be answered.
    ///
    /// When set, queries that haven't received an answer within this duration
    /// will emit [`MdnsEvent::QueryTimeout`](crate::MdnsEvent::QueryTimeout) and
    /// be automatically cancelled.
    ///
    /// When `None`, queries are retried, ever more slowly, until answered or
    /// manually cancelled.
    ///
    /// Default: 30 seconds
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// // Timeout queries after 5 seconds
    /// let config = MdnsConfig::default()
    ///     .with_query_timeout(Duration::from_secs(5));
    /// ```
    pub query_timeout: Option<Duration>,

    /// Local names that this connection will respond to.
    ///
    /// When an mDNS query arrives for any of these names, the connection
    /// will automatically generate a response with the configured `local_addr`.
    ///
    /// Names should be in `.local` format (e.g., `"myhost.local"`).
    /// Trailing dots are optional and will be normalized internally.
    ///
    /// Default: empty (no names to respond to)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    ///
    /// let config = MdnsConfig::default()
    ///     .with_local_names(vec![
    ///         "mydevice.local".to_string(),
    ///         "printer.local".to_string(),
    ///     ]);
    /// ```
    pub local_names: Vec<String>,

    /// Local address to advertise in mDNS responses.
    ///
    /// This IP address will be included in A record responses when
    /// queries for `local_names` are received.
    ///
    /// **Required** if `local_names` is non-empty, otherwise responses
    /// cannot be generated.
    ///
    /// Default: None
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    /// use std::net::{IpAddr, Ipv4Addr};
    ///
    /// let config = MdnsConfig::default()
    ///     .with_local_names(vec!["myhost.local".to_string()])
    ///     .with_local_ip(
    ///         IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
    ///     );
    /// ```
    pub local_ip: Option<IpAddr>,

    pub(crate) first_query_delay: bool,
    pub(crate) multi_question_delay: bool,
    pub(crate) unicast_response: bool,
    pub(crate) unicast_replies: bool,
    pub(crate) destination_reported: bool,
    pub(crate) multiple_addresses: bool,
    pub(crate) probe_policy: MdnsProbePolicy,
    pub(crate) announce_count: u8,
    pub(crate) rate_limit: Option<MdnsRateLimit>,
    pub(crate) on_link_subnets: Vec<(IpAddr, u8)>,
    pub(crate) jitter_seed: Option<u64>,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            query_interval: DEFAULT_QUERY_INTERVAL,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            local_names: Vec::new(),
            local_ip: None,
            first_query_delay: false,
            multi_question_delay: false,
            unicast_response: false,
            unicast_replies: true,
            destination_reported: false,
            multiple_addresses: false,
            probe_policy: MdnsProbePolicy::Auto,
            announce_count: DEFAULT_ANNOUNCE_COUNT,
            rate_limit: None,
            on_link_subnets: Vec::new(),
            jitter_seed: None,
        }
    }
}

impl MdnsConfig {
    /// Create a new configuration with default values.
    ///
    /// Equivalent to [`MdnsConfig::default()`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    ///
    /// let config = MdnsConfig::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interval between the first two queries of a series.
    ///
    /// The interval doubles after each retry (RFC 6762 section 5.2). A value under one second
    /// is taken as one second; zero is taken as the default (1 second).
    ///
    /// # Arguments
    ///
    /// * `interval` - Duration between the first query and its first retry
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// let config = MdnsConfig::default()
    ///     .with_query_interval(Duration::from_secs(2));
    /// ```
    pub fn with_query_interval(mut self, interval: Duration) -> Self {
        self.query_interval = interval;
        self
    }

    /// Set the query timeout.
    ///
    /// When set, queries that don't receive an answer within this duration
    /// will emit [`MdnsEvent::QueryTimeout`](crate::MdnsEvent::QueryTimeout)
    /// and be automatically removed from the pending list.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum duration to wait for a query answer
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// // Queries will timeout after 5 seconds
    /// let config = MdnsConfig::default()
    ///     .with_query_timeout(Duration::from_secs(5));
    ///
    /// // Combined with the retry interval: retry after 1 s and 3 s, give up after 5 s
    /// let config = MdnsConfig::default()
    ///     .with_query_interval(Duration::from_secs(1))
    ///     .with_query_timeout(Duration::from_secs(5));
    /// ```
    pub fn with_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = Some(timeout);
        self
    }

    /// Remove the query timeout: an unanswered query is retried, at intervals that double up
    /// to one hour, until it is answered or cancelled (the continuous querying of RFC 6762
    /// section 5.2).
    pub fn without_query_timeout(mut self) -> Self {
        self.query_timeout = None;
        self
    }

    /// Whether the first query of a series started with
    /// [`Mdns::schedule_query`](crate::Mdns::schedule_query) waits a random 20 to 120 ms
    /// (RFC 6762 section 5.2), so that hosts told of a name at the same moment (every
    /// participant of a call receiving the same ICE candidate, say) do not all ask at once.
    /// [`Mdns::query_now`](crate::Mdns::query_now) never waits.
    ///
    /// Default: `false`, a scheduled query goes out from the next `handle_timeout`. Turning it
    /// on is what the RFC recommends; a caller that does must keep driving
    /// [`poll_timeout`](sansio::Protocol::poll_timeout), since the query is no longer in
    /// `poll_write` right after the `handle_timeout` that started it.
    pub fn with_first_query_delay(mut self, delay: bool) -> Self {
        self.first_query_delay = delay;
        self
    }

    /// Whether the answers to a query of more than one question wait a random 20 to 120 ms
    /// even when every question is about a name of ours (RFC 6762 section 6.3: "for query
    /// messages containing more than one question, all (non-defensive) answers SHOULD be
    /// randomly delayed"). Off by default here: a message that asks only about our own
    /// unique names (an A and an AAAA question for one name, as browsers and this crate ask)
    /// is answered at once, as section 6 allows for unique records. `rtci-ice` turns it on.
    pub fn with_multi_question_delay(mut self, delay: bool) -> Self {
        self.multi_question_delay = delay;
        self
    }

    /// Declares that the caller gives every received datagram to
    /// [`handle_read`](sansio::Protocol::handle_read) with the datagram's destination address
    /// in `local_addr` (from `IP_PKTINFO` / `IPV6_PKTINFO`): `224.0.0.251` for one that
    /// arrived on the group, the host's own address for one sent to it by unicast.
    ///
    /// With that, a unicast arrival is held to the rules RFC 6762 has for it: a query is
    /// answered by unicast, and only when its source is on the link (section 5.5); a response
    /// is taken only when a question of ours asked for a unicast response in the last two
    /// seconds (section 6). Default: `false`, where `local_addr` is not looked at and every
    /// datagram is taken to have arrived on the group, since a socket's own bound address
    /// says nothing about how a datagram reached it.
    pub fn with_destination_reported(mut self, reported: bool) -> Self {
        self.destination_reported = reported;
        self
    }

    /// Whether the first query of a series asks for a unicast response (the "QU" bit,
    /// RFC 6762 section 5.4), as draft-ietf-mmusic-mdns-ice-candidates section 3.2.1 suggests.
    /// Retries never do. Default: `false`.
    ///
    /// Off by default because of RFC 6762 section 15.1: a unicast response reaches only one of
    /// the sockets bound to port 5353 on a host, so where a system responder (mDNSResponder,
    /// Avahi) shares the port the answer can go to it and the query waits for its first retry.
    /// Turn it on when the application's socket is the only one on port 5353, together with
    /// [`with_destination_reported`](Self::with_destination_reported) so that a unicast
    /// response nobody asked for is refused.
    pub fn with_unicast_response(mut self, unicast: bool) -> Self {
        self.unicast_response = unicast;
        self
    }

    /// Whether a question that asks for a unicast response, or a query known to have arrived
    /// by unicast ([`with_destination_reported`](Self::with_destination_reported)), is
    /// answered by unicast (RFC 6762 sections 5.4, 5.5). Default: `true`. With
    /// `false` every answer to a port 5353 querier is multicast, which the RFC also allows.
    pub fn with_unicast_replies(mut self, unicast: bool) -> Self {
        self.unicast_replies = unicast;
        self
    }

    /// Whether a name may resolve when a response gives it more than one address. Default:
    /// `false`: such a query ends with
    /// [`MdnsEvent::QueryTimeout`](crate::MdnsEvent::QueryTimeout), as
    /// draft-ietf-mmusic-mdns-ice-candidates section 3.2.2 asks of an ICE agent (an mDNS
    /// candidate names one address). With `true` the first address of the response answers.
    pub fn with_multiple_addresses(mut self, allow: bool) -> Self {
        self.multiple_addresses = allow;
        self
    }

    /// Set which names are probed for before they are used. Default:
    /// [`MdnsProbePolicy::Auto`].
    pub fn with_probe_policy(mut self, policy: MdnsProbePolicy) -> Self {
        self.probe_policy = policy;
        self
    }

    /// Set how many times a new name is announced: 2 (the default and the least RFC 6762
    /// section 8.3 allows) to 8, one second after the first and then at doubling intervals.
    /// Values outside the range are brought into it.
    pub fn with_announce_count(mut self, count: u8) -> Self {
        self.announce_count = count.clamp(DEFAULT_ANNOUNCE_COUNT, MAX_ANNOUNCE_COUNT);
        self
    }

    /// Set the limit on the messages sent. Give clones of one [`MdnsRateLimit`] to every
    /// connection of a process to bound them together. Default: a limit of its own per
    /// connection, 40 messages at once and 10 a second.
    pub fn with_rate_limit(mut self, limit: MdnsRateLimit) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Set the subnets of the link, as (address, prefix length) pairs: a sender is on the
    /// link when its address is in one of them (RFC 6762 section 11). Default: empty, and
    /// then a sender is judged by the scope of its address (private, shared, link-local and
    /// loopback IPv4; link-local, unique-local and loopback IPv6), which refuses an on-link
    /// host with a public IPv4 address.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    ///
    /// let config = MdnsConfig::default().with_on_link_subnets(vec![
    ///     ("203.0.113.0".parse().unwrap(), 24),
    ///     ("fe80::".parse().unwrap(), 10),
    /// ]);
    /// ```
    pub fn with_on_link_subnets(mut self, subnets: Vec<(IpAddr, u8)>) -> Self {
        self.on_link_subnets = subnets;
        self
    }

    /// Seed the random delays (first query, probe start, delayed responses), which makes a
    /// run reproducible. Default: a seed of the process's own.
    pub fn with_jitter_seed(mut self, seed: u64) -> Self {
        self.jitter_seed = Some(seed);
        self
    }

    /// Set the local names to respond to.
    ///
    /// When mDNS queries for these names are received, the connection
    /// will automatically generate responses with the configured `local_addr`.
    ///
    /// # Arguments
    ///
    /// * `names` - List of hostnames (e.g., `["myhost.local"]`)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    ///
    /// let config = MdnsConfig::default()
    ///     .with_local_names(vec!["server.local".to_string()]);
    /// ```
    pub fn with_local_names(mut self, names: Vec<String>) -> Self {
        self.local_names = names;
        self
    }

    /// Set the local address to advertise in responses.
    ///
    /// This address will be included in A record responses. The port
    /// is typically 5353 for mDNS.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address containing the IP to advertise
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtci_mdns::MdnsConfig;
    /// use std::net::{IpAddr, Ipv4Addr};
    ///
    /// let config = MdnsConfig::default()
    ///     .with_local_ip(
    ///         IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
    ///     );
    /// ```
    pub fn with_local_ip(mut self, local_ip: IpAddr) -> Self {
        self.local_ip = Some(local_ip);
        self
    }
}
