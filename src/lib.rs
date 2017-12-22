// Implemented by Vitaly "_Vi" Shukela in 2017; Licence = MIT or Apache 2.0

extern crate dns_parser;
extern crate compactmap;
#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate serde_bytes;
extern crate bytes;
extern crate multimap;
extern crate clamp;

use dns_parser::Packet;
use dns_parser::QueryType::{A, AAAA, All as QTAll};
use dns_parser::QueryClass::{IN, Any as QCAny};
use dns_parser::RRData;
use std::collections::HashMap;
use compactmap::CompactMap;
use bytes::{BigEndian as BE};
#[allow(unused_imports)]
use bytes::BufMut;
use multimap::MultiMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Options {
    pub neg_ttl: u64,
    pub max_ttl: u32,
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


pub enum ReceiveResult<C:Copy> {
    FromClient(C),
    FromUpstream
}

/// Network abstraction
pub trait Network {
    type ClientId : Copy;
    fn send_to_client(&self, buf: &[u8], client: Self::ClientId) -> BoxResult<()>;
    fn send_to_upstream(&self, buf: &[u8]) -> BoxResult<()>;
    fn recv_from(&self, buf: &mut[u8]) -> BoxResult<(usize, ReceiveResult<Self::ClientId>)>;
}


/// Database abstraction
pub trait Database {
    fn get(&mut self, dom: &str) -> BoxResult<Option<CacheEntry>>;
    fn put(&mut self, dom: &str, entry: &CacheEntry) -> BoxResult<()>;
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



pub type Time = u64;
pub type BoxResult<T> = Result<T, Box<std::error::Error>>;
pub type Ttl = u32;


/// Simplified record: some address with TTL
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
pub struct AddrTtl {
    ttl: Ttl,

    // FIXME: should be a static array in the better world
    #[serde(with = "serde_bytes")]
    ip: Vec<u8>,
}

/// Result of resolution of A or AAAA entries of some domain
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
pub struct CacheEntry2 {
    t: Time,
    a: Vec<AddrTtl>,
}

/// Remembered status about some domain
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
pub struct CacheEntry {
    a4: Option<CacheEntry2>, // None - unqueried
    a6: Option<CacheEntry2>,
}






pub(crate) struct SimplifiedQuestion {
    dom: String,
    a4: bool,
    a6: bool,
}
pub(crate) struct SimplifiedRequest<C:Copy> {
    id: u16,
    clientid: C,
    q: Vec<SimplifiedQuestion>,
    inhibit_send: bool,
}

type UnrepliedRequests<C> = CompactMap<SimplifiedRequest<C>>;
type UnrepliedRequestId = usize;
type DomUpdateSubstriptions = MultiMap<String, UnrepliedRequestId>;


impl<DB: Database, N: Network> DnsCache<DB, N> {
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
    
    pub fn serve_one_packet(&mut self) -> BoxResult<()> {
        let mut buf = [0; 1600];
        self.serve1(&mut buf)
    }
    
    // BoxResult<!> ?
    pub fn run_endlessly(&mut self) -> BoxResult<()> {
        let mut buf = [0; 1600];
        loop {
            self.serve1(&mut buf)?
        }
    }
}

mod details;
