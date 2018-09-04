// Implemented by Vitaly "_Vi" Shukela in 2017; Licence = MIT or Apache 2.0

extern crate dnscache;
extern crate serde_cbor;
extern crate serde_bytes;
extern crate rusty_leveldb;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate println_logger;

use std::net::{UdpSocket, SocketAddr};
use rusty_leveldb::DB as LevelDB;
use serde_cbor::de::from_slice;
use serde_cbor::ser::to_vec;
use structopt::StructOpt;
use std::path::PathBuf;
use dnscache::{DnsCache, Options as CacheOptions, Network};
use dnscache::{Database, ReceiveResult, CacheEntry, BoxResult};


#[derive(StructOpt, Debug)]
#[structopt(name = "dnscache", about = "Simple DNS cacher.")]
struct Opt {
    #[structopt(help = "Listen address and port")]
    listen_addr: SocketAddr,

    #[structopt(help = "Upstream DNS server address and port")]
    upstream_addr: SocketAddr,

    #[structopt(help = "Path to LevelDB database directory", parse(from_os_str))]
    db: PathBuf,

    #[structopt(long = "neg-ttl", help = "Negative reply TTL, seconds", default_value = "30",
                parse(try_from_str))]
    neg_ttl: u64,

    #[structopt(long = "max-ttl", help = "Maximum TTL of A or AAAA entry, seconds",
                default_value = "4294967295", parse(try_from_str))]
    max_ttl: u32,

    #[structopt(long = "min-ttl", help = "Minimum TTL of A or AAAA entry, seconds",
                default_value = "0", parse(try_from_str))]
    min_ttl: u32,

    /// Delete information about this domain before startup
    #[structopt(long="delete",short="D")]
    delete_domains: Vec<String>,
}

struct MyNetwork {
    s: UdpSocket,
    upstream: SocketAddr,
}
struct MyDatabase(LevelDB);

impl Network for MyNetwork {
    type ClientId = SocketAddr;
    fn send_to_client(&self, buf: &[u8], client: Self::ClientId) -> BoxResult<()> {
        self.s.send_to(buf, &client)?;
        Ok(())
    }
    fn send_to_upstream(&self, buf: &[u8]) -> BoxResult<()> {
        self.s.send_to(buf, &self.upstream)?;
        Ok(())
    }
    fn recv_from(&self, buf: &mut [u8]) -> BoxResult<(usize, ReceiveResult<Self::ClientId>)> {
        let (amt, src) = self.s.recv_from(buf)?;
        if src == self.upstream {
            Ok((amt, ReceiveResult::FromUpstream))
        } else {
            Ok((amt, ReceiveResult::FromClient(src)))
        }
    }
}

impl Database for MyDatabase {
    fn get(&mut self, dom: &str) -> BoxResult<Option<CacheEntry>> {
        if let Some(ceb) = self.0.get(dom.as_bytes()) {
            let ce: CacheEntry = from_slice(&ceb[..])?;
            Ok(Some(ce))
        } else {
            Ok(None)
        }
    }
    fn put(&mut self, dom: &str, entry: &CacheEntry) -> BoxResult<()> {
        self.0.put(dom.as_bytes(), &to_vec(&entry)?[..])?;
        Ok(())
    }
    fn flush(&mut self) -> BoxResult<()> {
        self.0.flush()?;
        Ok(())
    }
}

fn run(opt: &Opt) -> BoxResult<()> {
    let dbopts: rusty_leveldb::Options = Default::default();
    let mut db = LevelDB::open(
        &opt.db,
        dbopts,
    )?;

    for deldm in &opt.delete_domains {
        db.delete(deldm.as_bytes())?;
    }

    let s = UdpSocket::bind(opt.listen_addr)?;
    let upstream = opt.upstream_addr;

    if opt.listen_addr.ip().is_loopback() && !opt.upstream_addr.ip().is_loopback() {
        eprintln!(
            "Warning: listening on localhost, but sending to non-localhost upstream server is not supported"
        );
    }

    let net = MyNetwork { s, upstream };

    let dnscache_opts = CacheOptions {
        neg_ttl: opt.neg_ttl,
        max_ttl: opt.max_ttl,
        min_ttl: opt.min_ttl,
    };

    let mut dnscache = DnsCache::new(MyDatabase(db), net, dnscache_opts);

    dnscache.run_endlessly()
}

fn main() {
    println_logger::init();
    let opt = Opt::from_args();
    if let Err(e) = run(&opt) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
