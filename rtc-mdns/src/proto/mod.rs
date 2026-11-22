//! The Sans-I/O mDNS connection.
//!
//! This module is private; [`Mdns`] is re-exported as [`crate::Mdns`], where its
//! documentation and examples live so that rustdoc renders them and their doctests run.
//!
//! The connection is a resolver (`resolver.rs`: query series, the address cache) and a
//! responder for unique host-name records (`responder.rs`: probing, announcing, answering,
//! goodbyes), over the message reader and writer of `wire.rs` and the message budget of
//! `rate.rs`. Every decision is made against the instant the caller supplied.

mod rate;
mod resolver;
mod responder;
pub(crate) mod wire;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use shared::{TaggedBytesMut, TransportContext, TransportMessage, TransportProtocol};

use crate::config::{DEFAULT_QUERY_INTERVAL, MdnsConfig};
use crate::message::RCode;
use rate::Jitter;
use resolver::{Cached, Query};
use responder::{Goodbye, LocalRecord};
use shared::error::{Error, Result};

pub use rate::MdnsRateLimit;

/// The mDNS multicast group address (224.0.0.251).
pub const MDNS_MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The standard mDNS port (5353).
pub const MDNS_PORT: u16 = 5353;

/// mDNS multicast destination address (224.0.0.251:5353).
///
/// All mDNS queries and multicast responses are sent to this address.
///
/// # Example
///
/// ```rust
/// use rtc_mdns::MDNS_DEST_ADDR;
///
/// assert_eq!(MDNS_DEST_ADDR.to_string(), "224.0.0.251:5353");
/// ```
pub const MDNS_DEST_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(MDNS_MULTICAST_IPV4), MDNS_PORT);

/// The most names [`Mdns::add_local_name`] registers: one per local address is the use, and a
/// host has a handful.
pub const MAX_LOCAL_NAMES: usize = 64;

/// The most addresses the resolver's cache holds. Any host on the link can offer records, so
/// the cache is bounded: when it is full, the entry nearest its expiry gives way to one that
/// lives longer.
pub const MAX_CACHED_ADDRESSES: usize = 256;

/// The longest a cached address is kept, whatever TTL it came with: 75 minutes, the TTL
/// RFC 6762 section 10 recommends for records that are not host names.
const CACHE_TTL_CAP: u32 = 75 * 60;

/// Query intervals double up to one hour (RFC 6762 section 5.2).
const MAX_QUERY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Packets waiting for `poll_write`. With this many unsent, nothing more is queued until the
/// caller drains them.
const MAX_QUEUED_PACKETS: usize = 256;

/// How long sending is put off when the write queue is full.
const QUEUE_FULL_RETRY: Duration = Duration::from_secs(1);

/// Unique identifier for tracking mDNS queries.
///
/// Each call to [`Mdns::query_now()`] returns a unique ID that can be used to:
/// - Track which query was answered in [`MdnsEvent::QueryAnswered`]
/// - Cancel a pending query with [`Mdns::cancel_query()`]
/// - Check if a query is still pending with [`Mdns::is_query_pending()`]
pub type QueryId = u64;

/// When something is to be done: at an instant, or as soon as the caller next gives the time
/// (what a method that takes no `now` leaves behind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum When {
    Asap,
    At(Instant),
}

impl When {
    fn due(self, now: Instant) -> bool {
        matches!(self, When::At(at) if at <= now)
    }
}

/// Events emitted by the mDNS connection.
///
/// Poll for events using [`poll_event()`](sansio::Protocol::poll_event) after
/// calling [`handle_read()`](sansio::Protocol::handle_read) or
/// [`handle_timeout()`](sansio::Protocol::handle_timeout).
///
/// # Example
///
/// ```rust,ignore
/// while let Some(event) = mdns.poll_event() {
///     match event {
///         MdnsEvent::QueryAnswered(query_id, addr) => {
///             println!("Query {} resolved to {}", query_id, addr);
///         }
///         MdnsEvent::QueryTimeout(query_id) => {
///             println!("Query {} timed out", query_id);
///         }
///         _ => {}
///     }
/// }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum MdnsEvent {
    /// A query was successfully answered.
    ///
    /// Contains the query ID and the resolved IP address.
    /// The query is automatically removed from the pending list.
    QueryAnswered(QueryId, IpAddr),

    /// A query ended without an address.
    ///
    /// Emitted when the query's timeout passed
    /// ([`MdnsConfig::query_timeout`](crate::MdnsConfig::query_timeout), 30 seconds unless
    /// changed), when a response gave the name more than one address and
    /// [`MdnsConfig::with_multiple_addresses`](crate::MdnsConfig::with_multiple_addresses) is
    /// off, or when the name's owner said it has no address record. The query is removed from
    /// the pending list when this event is emitted.
    ///
    /// ```rust
    /// use rtc_mdns::MdnsConfig;
    /// use std::time::Duration;
    ///
    /// let config = MdnsConfig::default()
    ///     .with_query_timeout(Duration::from_secs(5));
    /// ```
    QueryTimeout(QueryId),

    /// A name of ours is in use by another host and has been given up (RFC 6762 section 9):
    /// probing for it met a defender. The name is no longer answered; it is given as it was
    /// registered. Register another name in its place.
    LocalNameConflict(String),
}

/// Sans-I/O mDNS Connection.
///
/// This implements a sans-I/O mDNS resolver and host-name responder (RFC 6762, as far as
/// draft-ietf-mmusic-mdns-ice-candidates uses it):
///
/// - **Resolver**: a query asks for a name's A and AAAA records and is retried at doubling
///   intervals until it is answered or times out. Answers are cached for their TTL, so a name
///   seen in an announcement or resolved before answers at once.
/// - **Responder**: each local name owns one address record. A name is probed for unless it is
///   a random `<uuid>.local` name, announced twice, answered (by multicast at most once a
///   second per record, or by unicast where the querier asked), defended against probes, and
///   withdrawn with a goodbye when it is removed or the connection closes.
/// - Every message sent draws on one budget ([`MdnsRateLimit`]).
///
/// # Sans-I/O Pattern
///
/// This struct implements [`sansio::Protocol`], which means it doesn't perform
/// any I/O itself. Instead, the caller is responsible for:
///
/// 1. Calling [`handle_read()`](sansio::Protocol::handle_read) when packets arrive
/// 2. Sending packets from [`poll_write()`](sansio::Protocol::poll_write)
/// 3. Calling [`handle_timeout()`](sansio::Protocol::handle_timeout) on schedule
/// 4. Processing events from [`poll_event()`](sansio::Protocol::poll_event)
///
/// The socket is the application's: bound to port 5353, joined to 224.0.0.251
/// ([`MulticastSocket`](crate::MulticastSocket)). Give `handle_read` each datagram with its
/// source in `peer_addr`. Every datagram is taken to have arrived on the group, unless the
/// application reports destinations
/// ([`MdnsConfig::with_destination_reported`]): then `local_addr` is the datagram's
/// destination address, and one sent to the host by unicast is treated as RFC 6762 treats
/// unicast queries and responses.
///
/// # Example: Complete Event Loop
///
/// ```rust
/// use rtc_mdns::{MdnsConfig, Mdns, MdnsEvent};
/// use sansio::Protocol;
/// use std::time::{Duration, Instant};
///
/// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
///
/// // Start a query
/// let query_id = mdns.query_now(Instant::now(), "device.local");
///
/// // Simulate an event loop iteration
/// let now = Instant::now();
///
/// // 1. Send queued packets (would go to network in real code)
/// while let Some(packet) = mdns.poll_write() {
///     println!("Would send {} bytes to {}", packet.message.len(), packet.transport.peer_addr);
/// }
///
/// // 2. Handle timeout if due
/// if let Some(deadline) = mdns.poll_timeout() {
///     if deadline <= now {
///         mdns.handle_timeout(now).ok();
///     }
/// }
///
/// // 3. Process any events
/// while let Some(event) = mdns.poll_event() {
///     match event {
///         MdnsEvent::QueryAnswered(query_id, addr) => {
///             println!("Query {} answered: {}", query_id, addr);
///         }
///         MdnsEvent::QueryTimeout(id) => {
///             println!("Query {} timed out", id);
///         }
///         // MdnsEvent is #[non_exhaustive]: a wildcard arm is required.
///         _ => {}
///     }
/// }
/// ```
///
/// # Example: Multiple Concurrent Queries
///
/// ```rust
/// # use std::time::Instant;
/// use rtc_mdns::{MdnsConfig, Mdns};
/// use sansio::Protocol;
///
/// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
///
/// // Start multiple queries - each gets a unique ID
/// let id1 = mdns.query_now(Instant::now(), "printer.local");
/// let id2 = mdns.query_now(Instant::now(), "server.local");
/// let id3 = mdns.query_now(Instant::now(), "nas.local");
///
/// assert_eq!(mdns.pending_query_count(), 3);
/// assert!(mdns.is_query_pending(id1));
/// assert!(mdns.is_query_pending(id2));
/// assert!(mdns.is_query_pending(id3));
///
/// // Cancel one query
/// mdns.cancel_query(id2);
/// assert_eq!(mdns.pending_query_count(), 2);
/// assert!(!mdns.is_query_pending(id2));
/// ```
///
/// # Query Lifecycle
///
/// 1. Call [`Mdns::query_now()`] (sent at once) or [`Mdns::schedule_query()`] (sent from the
///    next `handle_timeout`; after a random 20 to 120 ms with
///    [`MdnsConfig::with_first_query_delay`]) with the hostname to resolve
/// 2. Retrieve the query packet from [`poll_write()`](sansio::Protocol::poll_write)
/// 3. Send the packet to the mDNS multicast address
/// 4. When responses arrive, pass them to [`handle_read()`](sansio::Protocol::handle_read)
/// 5. Check [`poll_event()`](sansio::Protocol::poll_event) for [`MdnsEvent::QueryAnswered`]
/// 6. Call [`handle_timeout()`](sansio::Protocol::handle_timeout) when
///    [`poll_timeout()`](sansio::Protocol::poll_timeout) says so: retries go out after 1, 2,
///    4, ... seconds, and the query ends with [`MdnsEvent::QueryTimeout`] at its timeout
///
/// # Name Lifecycle
///
/// A name given in [`MdnsConfig::with_local_names`] or to [`Mdns::add_local_name`] starts at
/// the next `handle_timeout`: three probes 250 ms apart unless the name is exempt
/// ([`MdnsProbePolicy`](crate::MdnsProbePolicy)), then two announcements one second apart. A
/// name that is not probed for is answered from the moment it is registered.
/// [`Mdns::remove_local_name`] and [`close()`](sansio::Protocol::close) send goodbyes;
/// [`Mdns::network_changed`] starts every name over.
pub struct Mdns {
    config: MdnsConfig,

    /// The configured local names with trailing dots, as given.
    local_names: Vec<String>,

    /// The records this connection owns: the configured names (when a local IP is configured)
    /// and those registered with [`Mdns::add_local_name`].
    records: Vec<LocalRecord>,

    /// Goodbyes still to send for removed names. At most [`MAX_LOCAL_NAMES`].
    goodbyes: Vec<Goodbye>,

    /// The times of the latest name conflicts, at most [`responder::CONFLICT_LIMIT`].
    conflicts: VecDeque<Instant>,

    /// Pending queries.
    queries: Vec<Query>,

    /// Addresses learned from responses. At most [`MAX_CACHED_ADDRESSES`].
    cache: Vec<Cached>,

    /// Next query ID to assign
    next_query_id: QueryId,

    /// The interval between the first two queries of a series.
    query_interval: Duration,

    /// Query timeout (None = no automatic timeout)
    query_timeout: Option<Duration>,

    limiter: MdnsRateLimit,
    jitter: Jitter,

    /// Set by a flush that could not send: when sending can go on.
    blocked_until: Option<Instant>,

    /// Outgoing packet queue
    write_outs: VecDeque<TaggedBytesMut>,

    /// Event queue
    event_outs: VecDeque<MdnsEvent>,

    /// The next instant anything is due.
    next_timeout: Option<Instant>,

    /// Whether anything waits for the caller to give the time.
    asap: bool,

    last_now: Instant,

    /// Whether the connection is closed
    closed: bool,
}

/// `name` with a trailing dot, and that in ASCII lower case: DNS names compare without regard
/// to ASCII case (RFC 1035 section 2.3.3).
fn normalize(name: &str) -> (String, String) {
    let name = if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    };
    let key = name.to_ascii_lowercase();
    (name, key)
}

impl Mdns {
    /// Create a new mDNS connection with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    /// * `config` - MdnsConfiguration for the connection
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use std::time::{Duration, Instant};
    ///
    /// // Client-only configuration
    /// let client = Mdns::new(Instant::now(), MdnsConfig::default());
    ///
    /// // Server configuration
    /// use std::net::{IpAddr, Ipv4Addr};
    /// let server = Mdns::new(
    ///     Instant::now(),
    ///     MdnsConfig::default()
    ///         .with_local_names(vec!["myhost.local".to_string()])
    ///         .with_local_ip(
    ///             IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
    ///         )
    /// );
    /// ```
    pub fn new(now: Instant, config: MdnsConfig) -> Self {
        let query_interval = if config.query_interval == Duration::ZERO {
            DEFAULT_QUERY_INTERVAL
        } else {
            // RFC 6762 section 5.2: at least one second between the first two queries, and
            // no need for more than an hour.
            config
                .query_interval
                .clamp(DEFAULT_QUERY_INTERVAL, MAX_QUERY_INTERVAL)
        };

        let mut mdns = Self {
            local_names: Vec::new(),
            records: Vec::new(),
            goodbyes: Vec::new(),
            conflicts: VecDeque::new(),
            queries: Vec::new(),
            cache: Vec::new(),
            next_query_id: 1,
            query_interval,
            query_timeout: config.query_timeout,
            limiter: config.rate_limit.clone().unwrap_or_default(),
            jitter: Jitter::new(config.jitter_seed),
            blocked_until: None,
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            next_timeout: None,
            asap: false,
            last_now: now,
            closed: false,
            config,
        };

        if !mdns.config.local_names.is_empty() && mdns.config.local_ip.is_none() {
            log::warn!("mDNS local names are configured without a local IP: they are not answered");
        }
        for name in mdns.config.local_names.clone() {
            let (name, key) = normalize(&name);
            mdns.local_names.push(name.clone());
            if let Some(ip) = mdns.config.local_ip
                && !mdns.records.iter().any(|r| r.key == key)
            {
                match mdns.new_record(name, key, ip, false) {
                    Some(record) => mdns.records.push(record),
                    None => log::warn!("mDNS cannot publish a configured name: not a DNS name"),
                }
            }
        }
        mdns.update_next_timeout();
        mdns
    }

    /// Answers queries for `name` with `ip` from now on: an A record for an IPv4 address, an
    /// AAAA record for an IPv6 one. Unlike [`MdnsConfig::with_local_names`], whose names all
    /// answer with the one [`MdnsConfig::local_ip`], each name registered here has its own
    /// address, so a host can publish one name per interface address (what WebRTC's mDNS host
    /// candidates do).
    ///
    /// The name is announced from the next
    /// [`handle_timeout`](sansio::Protocol::handle_timeout) (RFC 6762 section 8.3). A name that
    /// is not `<uuid>.local` is probed for first
    /// ([`MdnsProbePolicy`](crate::MdnsProbePolicy)) and answered only once probing has met no
    /// defender.
    ///
    /// Returns `false`, registering nothing, when `name` is already registered,
    /// [`MAX_LOCAL_NAMES`] are, or `name` is not a DNS name (an empty label, a label over 63
    /// bytes, over 255 bytes in all).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{Mdns, MdnsConfig};
    /// use std::net::IpAddr;
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    /// assert!(mdns.add_local_name("v4-name.local", "192.168.1.10".parse::<IpAddr>().unwrap()));
    /// assert!(mdns.add_local_name("v6-name.local", "2001:db8::10".parse::<IpAddr>().unwrap()));
    /// ```
    pub fn add_local_name(&mut self, name: &str, ip: IpAddr) -> bool {
        let (name, key) = normalize(name);
        if self.closed
            || self.records.iter().filter(|r| r.registered).count() >= MAX_LOCAL_NAMES
            || self.records.iter().any(|r| r.key == key)
        {
            return false;
        }
        let Some(record) = self.new_record(name, key, ip, true) else {
            return false;
        };
        // The name is back: the goodbye its removal left behind would withdraw it again.
        self.goodbyes
            .retain(|g| !(g.key == record.key && g.ip == record.ip));
        self.records.push(record);
        self.update_next_timeout();
        true
    }

    /// Stops answering for `name` and withdraws it: when the name was ever sent to the link,
    /// a goodbye (its record with TTL 0, RFC 6762 section 10.1) goes out from the next
    /// [`handle_timeout`](sansio::Protocol::handle_timeout), so that neighbours drop it from
    /// their caches.
    ///
    /// Returns `false` when `name` is not one of this connection's names.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{Mdns, MdnsConfig};
    /// use std::net::IpAddr;
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    /// let ip: IpAddr = "192.168.1.10".parse().unwrap();
    /// assert!(mdns.add_local_name("a-name.local", ip));
    /// assert!(mdns.remove_local_name("A-Name.local"));
    /// assert!(!mdns.remove_local_name("a-name.local"));
    /// ```
    pub fn remove_local_name(&mut self, name: &str) -> bool {
        let (_, key) = normalize(name);
        let Some(index) = self.records.iter().position(|r| r.key == key) else {
            return false;
        };
        let record = self.records.remove(index);
        self.withdraw(record);
        self.update_next_timeout();
        true
    }

    /// Tells the connection that the host's network may have changed: it woke from sleep, a
    /// link came up, an address changed.
    ///
    /// What was learned on the old link is dropped (the address cache, RFC 6762 section 10.3),
    /// and every local name starts over as a new one does, from the next
    /// [`handle_timeout`](sansio::Protocol::handle_timeout): probed for unless exempt, then
    /// announced (RFC 6762 sections 8, 10.2). Pending queries carry on.
    ///
    /// Announcements are sent only when a name is registered and when this is called: there
    /// are no periodic ones (RFC 6762 section 8.3).
    pub fn network_changed(&mut self) {
        if self.closed {
            return;
        }
        self.cache.clear();
        self.restart_records();
        self.update_next_timeout();
    }

    /// Start a new mDNS query for the given name, sending it at once.
    ///
    /// The query asks for the name's A and AAAA records. It is retried after the configured
    /// interval, then at doubling intervals (RFC 6762 section 5.2), until either:
    /// - An answer is received (emits [`MdnsEvent::QueryAnswered`])
    /// - The query times out (emits [`MdnsEvent::QueryTimeout`])
    /// - The query is cancelled with [`cancel_query()`](Self::cancel_query)
    /// - The connection is closed
    ///
    /// A name whose address is in the cache (answered before, or announced by its owner, and
    /// not past its TTL) is answered at once: the event is queued, no packet is, and the query
    /// is never pending.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    /// * `name` - The hostname to query (e.g., `"mydevice.local"`)
    ///
    /// # Returns
    ///
    /// A unique [`QueryId`] that can be used to track this query.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{MdnsConfig, Mdns, MdnsEvent};
    /// use sansio::Protocol;
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    ///
    /// // Start a query
    /// let query_id = mdns.query_now(Instant::now(), "printer.local");
    ///
    /// // The query packet is now queued
    /// let packet = mdns.poll_write().expect("query packet should be queued");
    /// assert_eq!(packet.transport.peer_addr.to_string(), "224.0.0.251:5353");
    ///
    /// // Track the query
    /// assert!(mdns.is_query_pending(query_id));
    /// ```
    pub fn query_now(&mut self, now: Instant, name: &str) -> QueryId {
        let id = self.new_query(name, When::At(now), Some(now));
        if !self.closed {
            self.last_now = now;
            self.answer_from_cache(now);
            self.flush(now);
            self.update_next_timeout();
        }
        id
    }

    /// Start a query for `name` from the next
    /// [`handle_timeout`](sansio::Protocol::handle_timeout): its first packet goes out in that
    /// call, or, with [`MdnsConfig::with_first_query_delay`], a random 20 to 120 ms after it
    /// (RFC 6762 section 5.2); not at all when the name's address is in the cache. Otherwise
    /// as [`query_now`](Self::query_now).
    pub fn schedule_query(&mut self, name: &str) -> QueryId {
        let id = self.new_query(name, When::Asap, None);
        self.update_next_timeout();
        id
    }

    /// Cancel a pending query.
    ///
    /// Removes the query from the pending list. No more retry packets will
    /// be sent and no events will be emitted for this query.
    ///
    /// # Arguments
    ///
    /// * `query_id` - The ID returned by [`query_now()`](Self::query_now)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{MdnsConfig, Mdns};
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    /// let query_id = mdns.query_now(Instant::now(), "device.local");
    ///
    /// assert!(mdns.is_query_pending(query_id));
    /// mdns.cancel_query(query_id);
    /// assert!(!mdns.is_query_pending(query_id));
    /// ```
    pub fn cancel_query(&mut self, query_id: QueryId) {
        self.queries.retain(|q| q.id != query_id);
        self.update_next_timeout();
    }

    /// Check if a query is still pending.
    ///
    /// A query is pending until it is answered, times out or is cancelled.
    ///
    /// # Arguments
    ///
    /// * `query_id` - The ID returned by [`query_now()`](Self::query_now)
    ///
    /// # Returns
    ///
    /// `true` if the query is still waiting for an answer, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{MdnsConfig, Mdns};
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    /// let query_id = mdns.query_now(Instant::now(), "device.local");
    ///
    /// // Query is pending until answered or cancelled
    /// assert!(mdns.is_query_pending(query_id));
    /// ```
    pub fn is_query_pending(&self, query_id: QueryId) -> bool {
        self.queries.iter().any(|q| q.id == query_id)
    }

    /// Get the number of pending queries.
    ///
    /// # Returns
    ///
    /// The count of queries that are still waiting for answers.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{MdnsConfig, Mdns};
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    /// assert_eq!(mdns.pending_query_count(), 0);
    ///
    /// mdns.query_now(Instant::now(), "device1.local");
    /// mdns.query_now(Instant::now(), "device2.local");
    /// assert_eq!(mdns.pending_query_count(), 2);
    /// ```
    pub fn pending_query_count(&self) -> usize {
        self.queries.len()
    }

    /// Whether `ip` may be on the local link (RFC 6762 section 11): in one of the configured
    /// subnets, or, with none configured, by the scope of the address.
    fn is_on_link(&self, ip: IpAddr) -> bool {
        if self.config.on_link_subnets.is_empty() {
            return is_on_link_source(ip);
        }
        let ip = ip.to_canonical();
        self.config
            .on_link_subnets
            .iter()
            .any(|&(net, prefix)| in_subnet(ip, net.to_canonical(), prefix))
    }

    /// Whether an answer naming `addr` is believed from `src`: see
    /// [`answer_is_from_its_owner`].
    fn trusts(&self, addr: IpAddr, src: IpAddr) -> bool {
        let (addr, src) = (addr.to_canonical(), src.to_canonical());
        match addr {
            IpAddr::V4(_) => addr == src && self.is_on_link(src),
            IpAddr::V6(_) => addr == src || self.is_on_link(src),
        }
    }

    /// Whether `ip` is an address this connection publishes: a datagram from it is our own,
    /// looped back, or another responder of this host.
    fn is_own_address(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.config.local_ip.map(|own| own.to_canonical()) == Some(ip)
            || self.records.iter().any(|r| r.ip.to_canonical() == ip)
    }

    /// Queues `bytes` for `to`, taking one message of the budget. `false`, queuing nothing,
    /// when the budget or the queue has no room; `blocked_until` then says when to try again.
    fn emit(&mut self, now: Instant, from: IpAddr, to: SocketAddr, bytes: &[u8]) -> bool {
        if self.write_outs.len() >= MAX_QUEUED_PACKETS {
            self.blocked_until = Some(now + QUEUE_FULL_RETRY);
            return false;
        }
        if !self.limiter.take(now) {
            self.blocked_until = Some(self.limiter.ready_at(now));
            return false;
        }
        self.push_packet(now, from, to, bytes);
        true
    }

    fn push_packet(&mut self, now: Instant, from: IpAddr, to: SocketAddr, bytes: &[u8]) {
        self.write_outs.push_back(TransportMessage {
            now,
            transport: TransportContext {
                local_addr: SocketAddr::new(from, MDNS_PORT),
                peer_addr: to,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(bytes),
        });
    }

    /// Sends everything that is due and allowed at `now`, in this order: probes, records
    /// (answers and announcements), goodbyes, queries. Stops at the first message the budget
    /// refuses; what was not sent stays due.
    fn flush(&mut self, now: Instant) {
        if self.closed {
            return;
        }
        self.blocked_until = None;
        let _ = self.flush_probes(now)
            && self.flush_records(now)
            && self.flush_goodbyes(now)
            && self.flush_queries(now);
    }

    fn update_next_timeout(&mut self) {
        let mut next: Option<Instant> = None;
        let mut asap = false;
        let mut consider = |when: When| match when {
            When::Asap => asap = true,
            When::At(at) => next = Some(next.map_or(at, |n: Instant| n.min(at))),
        };
        for record in &self.records {
            record.deadlines(&mut consider);
        }
        for goodbye in &self.goodbyes {
            consider(goodbye.due);
        }
        for query in &self.queries {
            consider(query.next);
            if let (Some(started), Some(timeout)) = (query.started, self.query_timeout)
                && let Some(at) = started.checked_add(timeout)
            {
                consider(When::At(at));
            }
        }
        // What is due but could not be sent waits for the budget.
        if let (Some(at), Some(blocked)) = (next, self.blocked_until) {
            next = Some(at.max(blocked));
        }
        self.next_timeout = next;
        self.asap = asap;
    }

    fn process_message(&mut self, msg: &TaggedBytesMut) {
        let Some(inbound) = wire::parse(&msg.message) else {
            log::debug!("mDNS ignores a datagram that is not a DNS message");
            return;
        };
        // RFC 6762 sections 18.3 and 18.11: a message with another OPCODE or a non-zero RCODE
        // is silently ignored.
        if inbound.header.op_code != 0 || inbound.header.rcode != RCode::Success {
            return;
        }
        let src = msg.transport.peer_addr;
        // The destination, where the caller reports it: a unicast arrival is held to stricter
        // rules (RFC 6762 sections 5.5, 6, 11).
        let dst = msg.transport.local_addr.ip();
        let unicast_arrival =
            self.config.destination_reported && !(dst.is_unspecified() || dst.is_multicast());

        if inbound.header.response {
            // RFC 6762 section 6: a response from another source port is silently ignored.
            // Its questions, if it has any, are too.
            if src.port() == MDNS_PORT {
                self.process_response(&inbound, src, unicast_arrival, msg.now);
            }
        } else {
            // The Answer section of a query is its sender's known answers: it resolves
            // nothing and is never cached (RFC 6762 section 7.1).
            self.process_query(&inbound, src, unicast_arrival, msg.now);
        }
    }
}

/// Whether `ip` is in the subnet `net`/`prefix`.
fn in_subnet(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    fn bits(ip: IpAddr) -> (u128, u32) {
        match ip {
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
            IpAddr::V6(v6) => (u128::from(v6), 128),
        }
    }
    let ((ip, width), (net, net_width)) = (bits(ip), bits(net));
    if width != net_width {
        return false;
    }
    let prefix = u32::from(prefix).min(width);
    if prefix == 0 {
        return true;
    }
    (ip ^ net) >> (width - prefix) == 0
}

/// Whether `src` may be on the local link (RFC 6762 §11: mDNS is link-local; responses from
/// elsewhere are not to be trusted). The receiver sees no TTL or interface here, so this is the
/// address's scope: private, shared, link-local and loopback IPv4; link-local, unique-local and
/// loopback IPv6.
pub(crate) fn is_on_link_source(src: IpAddr) -> bool {
    match src.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_link_local()
                || v4.is_loopback()
                // 100.64.0.0/10, shared address space (RFC 6598).
                || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            v6.is_unicast_link_local() || v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Whether an answer naming `addr` is believed from `src`: the sender must be on-link, and an
/// A record must name the sender's own address. A host answers for its IPv6 names over the IPv4
/// group too, so an AAAA record is not compared with an IPv4 source (an IPv6 source that names
/// itself is accepted whatever its scope).
pub(crate) fn answer_is_from_its_owner(addr: IpAddr, src: IpAddr) -> bool {
    let (addr, src) = (addr.to_canonical(), src.to_canonical());
    match addr {
        IpAddr::V4(_) => addr == src && is_on_link_source(src),
        IpAddr::V6(_) => addr == src || is_on_link_source(src),
    }
}

impl sansio::Protocol<TaggedBytesMut, (), ()> for Mdns {
    type Rout = ();
    type Wout = TaggedBytesMut;
    type Eout = MdnsEvent;
    type Error = Error;
    type Time = Instant;

    /// Process an incoming mDNS packet.
    ///
    /// Call this method when a UDP packet is received on the mDNS socket (port 5353, joined
    /// to 224.0.0.251).
    ///
    /// The connection will:
    /// - Parse the packet as an mDNS message; one with a non-zero OPCODE or RCODE, or over
    ///   9000 bytes, is ignored
    /// - For a query: answer the questions for its names (at once, or after the delay RFC 6762
    ///   section 6 asks for), by multicast, by unicast when asked, or as a conventional DNS
    ///   reply to a querier that is not on port 5353
    /// - For a response (taken only from source port 5353): resolve pending queries, cache
    ///   the addresses, and check its records against the names it owns (a conflicting record
    ///   sends the name back to probing)
    ///
    /// # Arguments
    ///
    /// * `msg` - The received packet with transport context: the sender in `peer_addr`, and,
    ///   with [`MdnsConfig::with_destination_reported`], the datagram's destination address
    ///   in `local_addr`
    ///
    /// # Errors
    ///
    /// Returns [`Error::ErrConnectionClosed`] if the connection has been closed.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bytes::BytesMut;
    /// use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
    /// use std::time::Instant;
    ///
    /// // When a packet arrives from the network:
    /// let msg = TaggedBytesMut {
    ///     now: Instant::now(),
    ///     transport: TransportContext {
    ///         local_addr: "224.0.0.251:5353".parse().unwrap(),
    ///         peer_addr: src_addr,
    ///         transport_protocol: TransportProtocol::UDP,
    ///         ecn: None,
    ///     },
    ///     message: BytesMut::from(&packet_data[..]),
    /// };
    /// mdns.handle_read(msg)?;
    ///
    /// // Check for events
    /// while let Some(event) = mdns.poll_event() {
    ///     // handle event
    /// }
    /// ```
    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<()> {
        if self.closed {
            return Err(Error::ErrConnectionClosed);
        }
        self.last_now = msg.now;
        self.process_message(&msg);
        self.flush(msg.now);
        self.update_next_timeout();
        Ok(())
    }

    /// mDNS doesn't produce read outputs.
    ///
    /// Answers to queries are delivered via `poll_event()`
    /// as [`MdnsEvent::QueryAnswered`] events instead.
    ///
    /// # Returns
    ///
    /// Always returns `None`.
    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }

    /// Handle write requests (not used).
    ///
    /// Queries are initiated via the [`query_now()`](Mdns::query_now) method instead
    /// of through this interface.
    fn handle_write(&mut self, _msg: ()) -> Result<()> {
        Ok(())
    }

    /// Get the next packet to send.
    ///
    /// Call this method repeatedly until it returns `None` to retrieve all
    /// queued packets. Packets should be sent via UDP, from port 5353, to the address
    /// specified in `packet.transport.peer_addr`: 224.0.0.251:5353, or a querier's own address
    /// for a unicast reply. Responses should leave with IP TTL 255 (RFC 6762 section 11;
    /// [`MulticastSocket`](crate::MulticastSocket) sets it).
    ///
    /// Packets are queued when:
    /// - A query is started with [`query_now()`](Mdns::query_now)
    /// - `handle_timeout()` reaches a query's first packet or retry, a probe, an
    ///   announcement, a delayed response or a goodbye
    /// - A response is generated for a matching question
    /// - The connection is closed while it has published names (their goodbyes)
    ///
    /// # Returns
    ///
    /// The next packet to send, or `None` if the queue is empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use sansio::Protocol;
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    /// mdns.query_now(Instant::now(), "device.local");
    ///
    /// // Send all queued packets
    /// while let Some(packet) = mdns.poll_write() {
    ///     // socket.send_to(&packet.message, packet.transport.peer_addr).await?;
    ///     println!("Send to {}", packet.transport.peer_addr);
    /// }
    /// ```
    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_outs.pop_front()
    }

    /// Handle external events (not used).
    ///
    /// mDNS does not use external events. This method does nothing.
    fn handle_event(&mut self, _evt: ()) -> Result<()> {
        Ok(())
    }

    /// Get the next event.
    ///
    /// Call this method repeatedly until it returns `None` to process all
    /// queued events. Events are generated when:
    /// - An mDNS answer matches a pending query ([`MdnsEvent::QueryAnswered`])
    /// - A query ends without an address ([`MdnsEvent::QueryTimeout`])
    /// - A local name is lost to another host ([`MdnsEvent::LocalNameConflict`])
    ///
    /// # Returns
    ///
    /// The next event, or `None` if the queue is empty.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// while let Some(event) = mdns.poll_event() {
    ///     match event {
    ///         MdnsEvent::QueryAnswered(query_id, addr) => {
    ///             println!("Query {} resolved to {}", query_id, addr);
    ///         }
    ///         MdnsEvent::QueryTimeout(id) => {
    ///             println!("Query {} timed out", id);
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// ```
    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.event_outs.pop_front()
    }

    /// Handle timeout: send what is due.
    ///
    /// Call this method when the deadline from `poll_timeout()`
    /// is reached. It starts what was registered or scheduled since the last call, ends the
    /// queries whose timeout has passed, and queues the packets that are due: query packets
    /// and retries, probes, announcements, delayed responses, goodbyes. They can be retrieved
    /// with `poll_write()`.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    ///
    /// # Errors
    ///
    /// Returns [`Error::ErrConnectionClosed`] if the connection has been closed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use sansio::Protocol;
    /// use std::time::{Duration, Instant};
    ///
    /// let start = Instant::now();
    /// let mut mdns = Mdns::new(start, MdnsConfig::default());
    /// mdns.query_now(start, "device.local");
    ///
    /// // Consume initial packet
    /// mdns.poll_write();
    ///
    /// // The first retry is due one second after the query
    /// assert_eq!(mdns.poll_timeout(), Some(start + Duration::from_secs(1)));
    /// mdns.handle_timeout(start + Duration::from_secs(1)).unwrap();
    ///
    /// // A retry packet should be queued
    /// assert!(mdns.poll_write().is_some());
    /// ```
    fn handle_timeout(&mut self, now: Self::Time) -> Result<()> {
        if self.closed {
            return Err(Error::ErrConnectionClosed);
        }
        self.last_now = now;

        self.start_records(now);
        self.start_queries(now);
        self.expire_queries(now);
        self.cache.retain(|cached| cached.expires > now);

        self.flush(now);
        self.update_next_timeout();
        Ok(())
    }

    /// Get the next timeout deadline.
    ///
    /// Returns the time at which `handle_timeout()` should
    /// be called next. Use this to schedule your event loop's sleep/wait.
    ///
    /// # Returns
    ///
    /// - `Some(instant)` when something is due then: a query's packet or timeout, a probe, an
    ///   announcement, a delayed response, a goodbye. An instant that is not in the future
    ///   means "call `handle_timeout` now".
    /// - `None` if nothing is pending
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use sansio::Protocol;
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    ///
    /// // No queries, no timeout
    /// assert!(mdns.poll_timeout().is_none());
    ///
    /// // Start a query
    /// mdns.query_now(Instant::now(), "device.local");
    ///
    /// // Now there's a timeout scheduled
    /// assert!(mdns.poll_timeout().is_some());
    /// ```
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        if self.closed {
            None
        } else if self.asap {
            // Something waits for the time: handle it at once.
            Some(self.last_now)
        } else {
            self.next_timeout
        }
    }

    /// Close the connection.
    ///
    /// This clears all pending queries and queued packets/events, then queues a goodbye (TTL
    /// 0, RFC 6762 section 10.1) for every name that was sent to the link: drain
    /// `poll_write()` once more after closing so that neighbours drop the names at once.
    /// After closing, `handle_read()` and
    /// `handle_timeout()` will return
    /// [`Error::ErrConnectionClosed`].
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Instant;
    /// use rtc_mdns::{MdnsConfig, Mdns};
    /// use sansio::Protocol;
    ///
    /// let mut mdns = Mdns::new(Instant::now(), MdnsConfig::default());
    /// mdns.query_now(Instant::now(), "device.local");
    ///
    /// assert_eq!(mdns.pending_query_count(), 1);
    ///
    /// mdns.close().unwrap();
    ///
    /// // All state is cleared
    /// assert_eq!(mdns.pending_query_count(), 0);
    /// assert!(mdns.poll_write().is_none());
    /// assert!(mdns.poll_timeout().is_none());
    /// ```
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.queries.clear();
        self.cache.clear();
        self.write_outs.clear();
        self.event_outs.clear();
        self.queue_closing_goodbyes();
        self.records.clear();
        self.goodbyes.clear();
        self.next_timeout = None;
        self.asap = false;
        Ok(())
    }
}

#[cfg(test)]
mod mdns_answer_trust_test;
#[cfg(test)]
mod mdns_resolver_test;
#[cfg(test)]
mod mdns_responder_test;
#[cfg(test)]
mod mdns_test;
#[cfg(test)]
mod mdns_timeout_test;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod wire_test;
