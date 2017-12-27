// Implemented by Vitaly "_Vi" Shukela in 2017; Licence = MIT or Apache 2.0
#![deny(missing_docs)]
//! Library part of DnsCache, allowing abstracting network and database (but not packet parsing) away from the actual code.


extern crate dns_parser;
#[macro_use]
extern crate compactmap;
#[macro_use]
extern crate serde_derive;
extern crate serde_bytes;
extern crate bytes;
extern crate multimap;
extern crate clamp;
#[macro_use]
extern crate log;


use std::collections::HashMap;
use compactmap::wrapped::CompactMap;
use multimap::MultiMap;

/// TTL values in seconds
/// Actual resource record TTL values are clamped between min_ttl and max_ttl
#[derive(Debug)]
pub struct Options {
    /// TTL in seconds for answer that returned no addresses
    pub neg_ttl: u64,
    /// Limit TTL from above (in seconds)
    pub max_ttl: u32,
    /// Limit TTL from below (in seconds)
    pub min_ttl: u32,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            neg_ttl: 30,
            max_ttl: 0xFFFF_FFFF,
            min_ttl: 0,
        }
    }
}


/// What [`Network::recv_from`] returns
pub enum ReceiveResult<C: Copy> {
    /// This is a packet from client
    FromClient(C),
    /// This is a packet from upstream DNS server
    FromUpstream,
}

/// Network abstraction
pub trait Network {
    /// What to use instead of SocketAddr
    type ClientId: Copy;
    /// Like UdpSocket::send_to to upstream
    fn send_to_client(&self, buf: &[u8], client: Self::ClientId) -> BoxResult<()>;
    /// Like UdpSocket::send_to
    fn send_to_upstream(&self, buf: &[u8]) -> BoxResult<()>;
    /// Like UdpSocket::recv_from
    fn recv_from(&self, buf: &mut [u8]) -> BoxResult<(usize, ReceiveResult<Self::ClientId>)>;
}


/// Database abstraction
pub trait Database {
    /// retrieve entry
    fn get(&mut self, dom: &str) -> BoxResult<Option<CacheEntry>>;
    /// create or replace entry
    fn put(&mut self, dom: &str, entry: &CacheEntry) -> BoxResult<()>;
    /// flush previous puts
    fn flush(&mut self) -> BoxResult<()>;
}

/// Main object. DNS proxy with forced caching.
pub struct DnsCache<DB: Database, N: Network> {
    db: DB,
    net: N,
    r2a: HashMap<u16, N::ClientId>,
    opts: Options,

    unreplied_requests: UnrepliedRequests<N::ClientId>,
    dom_update_subscriptions: DomUpdateSubstriptions,
}


/// Answer timestamp, seconds
pub type Time = u64;
/// Too lazy to do proper error handling
pub type BoxResult<T> = Result<T, Box<std::error::Error>>;
/// TTL of a resource record, seconds
pub type Ttl = u32;


/// Simplified record: some address with TTL
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
pub struct AddrTtl {
    /// Time to Live, seconds
    pub ttl: Ttl,

    /// IPv4 or IPv6 address. Must be appropriate length (4 / 16 bytes respectively)
    // FIXME: should be a static array in the better world
    #[serde(with = "serde_bytes")]
    pub ip: Vec<u8>,
}

/// Result of resolution of A or AAAA entries of some domain
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
pub struct CacheEntry2 {
    /// Answer time, UNIX timestamp, seconds
    pub t: Time,
    /// Answer result
    pub a: Vec<AddrTtl>,
}

/// Remembered status about some domain
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
pub struct CacheEntry {
    /// Information about A records, if any. None = unqueried yet
    pub a4: Option<CacheEntry2>,
    /// Information about AAAA records, if any. None = unqueried yet
    pub a6: Option<CacheEntry2>,
}






pub(crate) struct SimplifiedQuestion {
    dom: String,
    a4: bool,
    a6: bool,
}
pub(crate) struct SimplifiedRequest<C: Copy> {
    id: u16,
    clientid: C,
    q: Vec<SimplifiedQuestion>,
    inhibit_send: bool,
}

declare_compactmap_token!(UnrepliedRequestId);
type UnrepliedRequests<C> = CompactMap<UnrepliedRequestId, SimplifiedRequest<C>>;
type DomUpdateSubstriptions = MultiMap<String, UnrepliedRequestId>;


impl<DB: Database, N: Network> DnsCache<DB, N> {
    /// Create instance of DnsCache
    pub fn new(db: DB, net: N, opts: Options) -> Self {
        DnsCache {
            db,
            net,
            opts,
            r2a: HashMap::new(),
            unreplied_requests: CompactMap::new(),
            dom_update_subscriptions: MultiMap::new(),
        }
    }
    
    /// Receive and process one packet
    pub fn serve_one_packet(&mut self) -> BoxResult<()> {
        let mut buf = [0; 1600];
        self.serve1(&mut buf)
    }

    /// Receive and process forever in a loop
    // BoxResult<!> ?
    pub fn run_endlessly(&mut self) -> BoxResult<()> {
        let mut buf = [0; 1600];
        loop {
            self.serve1(&mut buf)?
        }
    }
}

mod details;
