#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]
extern crate dns_parser;
extern crate compactmap;
#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate rusty_leveldb;
extern crate bytes;
extern crate multimap;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;

// TODO: handling multiple in-flight refreshes of the same domain

use std::net::{UdpSocket, SocketAddr, Ipv4Addr, Ipv6Addr};
use dns_parser::Packet;
use dns_parser::QueryType::{self, A,AAAA,All as QTAll};
use dns_parser::QueryClass::{IN,Any as QCAny};
use std::collections::HashMap;
use std::collections::HashSet;
use compactmap::CompactMap;
use rusty_leveldb::DB;
use std::time::Duration;
use std::io::Cursor;
use bytes::{BufMut,BigEndian as BE};
use serde_cbor::de::from_slice;
use serde_cbor::ser::to_vec;
use multimap::MultiMap;
use std::time::{SystemTime, UNIX_EPOCH};
use structopt::StructOpt;
use std::num::ParseIntError;
use std::path::PathBuf;

#[derive(StructOpt, Debug)]
#[structopt(name = "dnscache", about = "Simple DNS cacher.")]
struct Opt {
    #[structopt(help = "Listen address and port")]
    listen_addr: SocketAddr,
    
    #[structopt(help = "Upstream DNS server address and port")]
    upstream_addr: SocketAddr,

    #[structopt(help = "Path to LevelDB database directory", parse(from_os_str))]
    db: PathBuf,
    
    #[structopt(long = "neg-ttl", help = "Negative reply TTL, seconds", default_value = "30", parse(try_from_str))]
    neg_ttl: u64,
}


type CacheId = usize;
type Time = u64;

type BoxResult<T> = Result<T,Box<std::error::Error>>;
type Ttl = u32;

type Ipv4AddrB = [u8; 4];
type Ipv6AddrB = [u8; 16];

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
struct CacheEntry {
    a4: Option<Vec<(Ipv4AddrB,Ttl)>>, // None - unqueried
    a6: Option<Vec<(Ipv6AddrB,Ttl)>>,
    t : Time,
}

struct RequestToUs {
    entry: CacheId,
    reply_to: SocketAddr,
    id: u16,
}

struct SimplifiedQuestion {
    dom: String,
    a4: bool,
    a6: bool,
}
struct SimplifiedRequest {
    id : u16,
    sa : SocketAddr,
    q: Vec<SimplifiedQuestion>,
    t: Time,
    inhibit_send: bool,
}

fn send_dns_reply(
                s : &UdpSocket, 
                r: &SimplifiedRequest,
                ans_a:    &Vec<(String, Vec<(Ipv4AddrB, Ttl)>)>,
                ans_aaaa: &Vec<(String, Vec<(Ipv6AddrB, Ttl)>)>,
                ) -> BoxResult<()> {
    
    let mut num_answers = ans_a   .iter().fold(0, |a,x|a+x.1.len())
                        + ans_aaaa.iter().fold(0, |a,x|a+x.1.len());
    if num_answers > 65535 { num_answers=65535; } // XXX
    
    let mut reply_buf = Vec::with_capacity(600);
    reply_buf.put_u16::<BE>(r.id);
    reply_buf.put_u16::<BE>(0x8180); // response, recursion, recursion
    reply_buf.put_u16::<BE>(r.q.len() as u16); // q-s
    reply_buf.put_u16::<BE>(num_answers as u16); // a-s
    reply_buf.put_u16::<BE>(0); // auth-s
    reply_buf.put_u16::<BE>(0); // addit
    for q in &r.q {
        for l in q.dom.split(".") {
            reply_buf.put_u8(l.len() as u8); // XXX
            reply_buf.put(l);
        }
        reply_buf.put_u8(0x00); // end of name
        if q.a4 && q.a6 {
            reply_buf.put_u16::<BE>(0x00FF); // All
        } else if q.a4 {
            reply_buf.put_u16::<BE>(0x0001); // A
        } else if q.a6 {
            reply_buf.put_u16::<BE>(0x001C); // AAAA
        } else {
            println!("?");
            reply_buf.put_u16::<BE>(0x0000);
        }
        reply_buf.put_u16::<BE>(0x0001); // IN
    }
    for &(ref dom, ref a) in ans_a {
        for &(ip4, ttl) in a {
            for l in dom.split(".") {
                reply_buf.put_u8(l.len() as u8); // < 64
                reply_buf.put(l);
            }
            reply_buf.put_u8(0x00); // end of name
            reply_buf.put_u16::<BE>(0x0001); // A
            reply_buf.put_u16::<BE>(0x0001); // IN
            // FIXME: adjust TTL based on time it lived in the cache
            reply_buf.put_u32::<BE>(ttl); // TTL
            reply_buf.put_u16::<BE>(4); // data len
            reply_buf.put(&ip4[..]);
        }
    }
    for &(ref dom, ref aaaa) in ans_aaaa {
        for &(ip6, ttl) in aaaa {
            for l in dom.split(".") {
                reply_buf.put_u8(l.len() as u8); // < 64
                reply_buf.put(l);
            }
            reply_buf.put_u8(0x00); // end of name
            reply_buf.put_u16::<BE>(0x001C); // A
            reply_buf.put_u16::<BE>(0x0001); // IN
            // FIXME: adjust TTL based on time it lived in the cache
            reply_buf.put_u32::<BE>(ttl); // TTL
            reply_buf.put_u16::<BE>(16); // data len
            reply_buf.put(&ip6[..]);
        }
    }
    
    s.send_to(&reply_buf[..], &r.sa)?;
    Ok(())
}


enum TryAnswerRequestResult {
    Resolved(AdjustTtlResult),
    UnknownsRemain(usize),
}

#[derive(PartialEq)]
enum AdjustTtlResult {
    Ok,
    Expired,
    Negative(u64),
}

fn adjust_ttl<T:Copy+Clone>(v: &Vec<(T, Ttl)>, now: Time, then: Time) -> (AdjustTtlResult, Vec<(T, Ttl)>){
    let mut vv = Vec::with_capacity(v.len());
    let mut result = AdjustTtlResult::Ok;
    for &(x, ttl) in v {
        let newttl;
        if now.saturating_sub(then) >= ttl as u64 {
            newttl = 0;
            result = AdjustTtlResult::Expired;
        } else {
            newttl = ttl.saturating_sub(now.saturating_sub(then) as u32);
        }
        vv.push((x, newttl));
    }
    if v.len() == 0 {
        result = AdjustTtlResult::Negative(now.saturating_sub(then));
    }
    (result, vv)
}

fn try_answer_request(
                db : &mut DB,
                now : Time,
                s : &UdpSocket,
                r: &SimplifiedRequest
                ) -> BoxResult<TryAnswerRequestResult> {
    
    let mut num_unknowns = 0;
    
    let mut ans_a4 = Vec::with_capacity(4);
    let mut ans_a6 = Vec::with_capacity(4);
    
    let mut ttl_status = AdjustTtlResult::Ok;
    
    for q in &r.q {
        assert!(q.a4 || q.a6);
        if let Some(ceb) = db.get(q.dom.as_bytes()) {
            let ce : CacheEntry = from_slice(&ceb[..])?;
            let then = ce.t;
            if q.a4 {
                if let Some(a4) = ce.a4 {
                    let (tr,a4adj) = adjust_ttl(&a4, now, then);
                    if ttl_status == AdjustTtlResult::Ok { ttl_status = tr }
                    ans_a4.push((q.dom.clone(), a4adj));
                } else {
                    num_unknowns += 1;
                    continue;
                }
            }
            
            if q.a6 {
                if let Some(a6) = ce.a6 {
                    let (tr,a6adj) = adjust_ttl(&a6, now, then);
                    if ttl_status == AdjustTtlResult::Ok { ttl_status = tr }
                    ans_a6.push((q.dom.clone(), a6adj));
                } else {
                    num_unknowns += 1;
                    continue;
                }
            }

        } else {
            num_unknowns += 1;
        }
    }
    
    if num_unknowns > 0 { 
        return Ok(TryAnswerRequestResult::UnknownsRemain(num_unknowns));
    }
    send_dns_reply(s, r, &ans_a4, &ans_a6)?;
    Ok(TryAnswerRequestResult::Resolved(ttl_status))
}


type UnrepliedRequests = CompactMap<SimplifiedRequest>;
type UnrepliedRequestId = usize;
type DomUpdateSubstriptions = MultiMap<String, UnrepliedRequestId>;

struct ProgState {
    db : DB,
    s : UdpSocket,
    buf: [u8; 1600],
    amt: usize,
    r2a: HashMap<u16, SocketAddr>,
    upstream : SocketAddr,
    neg_ttl: u64,
    
    unreplied_requests: UnrepliedRequests,
    dom_update_subscriptions: DomUpdateSubstriptions,
}

impl ProgState {
    fn from_upstream(&mut self) -> BoxResult<()> {
        //println!("reply: {:?}", p);
        println!("  upstream");
        let buf = &self.buf[..self.amt];
        let p = Packet::parse(buf)?;
        
        // 1. handle direct replies
        
        if let Some(ca) = self.r2a.remove(&p.header.id) {
            println!("  direct reply");
            self.s.send_to(&buf, &ca)?;
            return Ok(());
        }
        
        // 2. check for cache poisoning
        // TODO: also check id
        
        for q in &p.questions {
            let dom = q.qname.to_string();
            if !self.dom_update_subscriptions.contains_key(&dom) {
                println!("  unsolicited reply for {}", dom);
                return Ok(())
            }
        }
        
        for ans in &p.answers {
            let dom = ans.name.to_string();
            if !self.dom_update_subscriptions.contains_key(&dom) {
                println!("  unsolicited reply for {}", dom);
                return Ok(())
            }
        }
        
        // now we are decided to save things and reply
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        // 3. build a list of new entries
        
        let mut tmp : HashMap<String, CacheEntry> = HashMap::new();
        
        for q in &p.questions {
            if q.qclass != IN { continue; }
            let dom = q.qname.to_string();
            
            let ce = tmp.entry(dom).or_insert(Default::default());
            ce.t = now;
            
            if q.qtype == A    || q.qtype == QTAll {
                ce.a4 = Some(Vec::new());
            }
            if q.qtype == AAAA || q.qtype == QTAll {
                ce.a6 = Some(Vec::new());
            }
        }
        
        for ans in &p.answers {
            let dom = ans.name.to_string();
            if ans.cls != dns_parser::Class::IN { continue; }
            
            let ce = tmp.entry(dom).or_insert(Default::default());
            ce.t = now;
            
            use dns_parser::RRData;
            match ans.data {
                RRData::A(ip4)    => {
                    if ce.a4 == None { ce.a4 = Some(Vec::new()); }
                    let v = ce.a4.as_mut().unwrap();
                    v.push((ip4.octets(), ans.ttl));
                }
                RRData::AAAA(ip6) => {
                    if ce.a6 == None { ce.a6 = Some(Vec::new()); }
                    let v = ce.a6.as_mut().unwrap();
                    v.push((ip6.octets(), ans.ttl));
                }
                _ => continue,
            }
        }
        
        // 4. save entries to the database, maybe merging with old entries
        
        for (dom, mut entry) in tmp.iter_mut() {
            
            let cached : CacheEntry;
            if let Some(ceb) = self.db.get(dom.as_bytes()) {
                cached = from_slice(&ceb[..])?;
            } else {
                cached = Default::default();
            }
            
            if entry.a4.is_none() && cached.a4.is_some() {
                entry.a4 = cached.a4;
            }
            if entry.a6.is_none() && cached.a6.is_some() {
                entry.a6 = cached.a6;
            }

            self.db.put(dom.as_bytes(), &to_vec(&entry)?[..])?;
            println!("  saved to database: {}", dom);
        }
        self.db.flush()?;
        
        // 5. Try replying to queued queries
        
        for (dom, _) in tmp {
            let subs = self.dom_update_subscriptions.remove(&dom).unwrap();
            let mut unhappy = Vec::new();
            let mut happy = Vec::new();
            for sub_id in subs {
                use TryAnswerRequestResult::*;
                if let Some(r) = self.unreplied_requests.get(sub_id) {
                    if r.inhibit_send {
                        println!("  refreshed");
                        happy.push(sub_id);
                        continue;
                    }
                    let result = try_answer_request(
                                &mut self.db,
                                now,
                                &self.s,
                                r)?;
                    match result {
                        Resolved(AdjustTtlResult::Ok) => {
                            println!("  replied.");
                            happy.push(sub_id);
                        }
                        Resolved(AdjustTtlResult::Expired) => {
                            println!("  replied?");
                            happy.push(sub_id);
                        }
                        Resolved(AdjustTtlResult::Negative(_)) => {
                            println!("  replied...");
                            happy.push(sub_id);
                        }
                        UnknownsRemain(_) => {
                            unhappy.push(sub_id);
                        }
                    }
                } else {
                    // request got replied in previous iteration
                }
            }
            for id in happy {
                let _ = self.unreplied_requests.remove(id);
            }
            if unhappy.len() > 0 {
                self.dom_update_subscriptions.entry(dom).or_insert_vec(unhappy);
            }
        }
        
        Ok(())
    }
    
    fn from_client(&mut self, src: SocketAddr) -> BoxResult<()> {
        let buf = &self.buf[..self.amt];
        let p = Packet::parse(buf)?;
        //println!("request {:?}", p);
        let mut weird_querty = false;
        
        let mut simplified_questions = Vec::with_capacity(1);
        
        if p.questions.len() > 1 {
            println!("A query with {} questions:", p.questions.len());
        } 
        
        for q in &p.questions {
            match q.qclass {
                IN  |
                QCAny => {}
                _ => { weird_querty = true; }
            }
            match q.qtype {
                /*|*/ A
                  |   AAAA
                // | All // those are buggy: work only if both A and AAAA in reply
                    => {}
                _   => { weird_querty = true; }
            }
            
            let dom = q.qname.to_string();
            print!("{:?}\t{}", q.qtype, dom);
            let sq = SimplifiedQuestion {
                dom,
                a4: q.qtype == A    || q.qtype == QTAll,
                a6: q.qtype == AAAA || q.qtype == QTAll,
            };
            simplified_questions.push(sq);
        }
        
        if weird_querty {
            println!("  direct");
            //println!("Weird requestnow >= then && now - then {:?}",p);
            self.r2a.insert(p.header.id, src);
            self.s.send_to(&buf, &self.upstream)?;
            return Ok(());
        }
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        let mut r = SimplifiedRequest {
            id : p.header.id,
            q : simplified_questions,
            sa: src,
            t: now,
            inhibit_send: false,
        };
        
        use TryAnswerRequestResult::*;
        let result = try_answer_request(&mut self.db, now, &self.s, &r)?;
        
        match result {
            Resolved(AdjustTtlResult::Ok) => {
                println!("  cached");
                return Ok(());
            }
            Resolved(AdjustTtlResult::Expired) => {
                println!("  cached, but refreshing");
                r.inhibit_send = true;
            }
            Resolved(AdjustTtlResult::Negative(x)) => {
                if x >= self.neg_ttl {
                    println!("  cached, negative {}, refreshing", x);
                    r.inhibit_send = true;
                } else {
                    println!("  cached, negative {}.", x);
                    return Ok(());
                }
            }
            UnknownsRemain(_) => {
                println!("  queued");
            }
        }
        
        let id = self.unreplied_requests.insert(r);
        let r = self.unreplied_requests.get(id).unwrap();
        
        for ref q in &r.q {
            self.dom_update_subscriptions.insert(q.dom.clone(), id);
        }
        // Send to upstream as is.
        self.s.send_to(&buf, &self.upstream)?;
        Ok(())
    }

    fn serve1(&mut self) -> BoxResult<()> {
        let (amt, src) = self.s.recv_from(&mut self.buf)?;
        self.amt = amt;
        if src == self.upstream {
            self.from_upstream()?;
        } else {
            self.from_client(src)?;
        }
        Ok(())
    }
}

fn run(opt: Opt) -> BoxResult<()> {
    let dbopts : rusty_leveldb::Options = Default::default();
    let db = DB::open(opt.db.to_str().expect("rusty-leveldb opens only UTF-8 paths"), dbopts)?;

    let s = UdpSocket::bind(opt.listen_addr)?;
    let upstream = opt.upstream_addr;
    
    let mut r2a : HashMap<u16, SocketAddr> = HashMap::new();
    
    let mut buf = [0; 1600];
    
    let mut ps = ProgState {
        db,
        s,
        upstream,
        r2a,
        buf,
        amt: 0,
        unreplied_requests: CompactMap::new(),
        dom_update_subscriptions: MultiMap::new(),
        neg_ttl: opt.neg_ttl,
    };
    
    loop {
        if let Err(e) = ps.serve1() {
            eprintln!("Error: {:?}", e);
        }
    }
}

fn main() {
    let opt = Opt::from_args();
    if let Err(e) = run(opt) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
