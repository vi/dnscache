extern crate dns_parser;
extern crate compactmap;
#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;
extern crate serde_bytes;
extern crate rusty_leveldb;
extern crate bytes;
extern crate multimap;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate clamp;

use std::net::{UdpSocket, SocketAddr};
use dns_parser::Packet;
use dns_parser::QueryType::{A, AAAA, All as QTAll};
use dns_parser::QueryClass::{IN, Any as QCAny};
use dns_parser::RRData;
use std::collections::HashMap;
use compactmap::CompactMap;
use rusty_leveldb::DB;
use bytes::{BufMut, BigEndian as BE};
use serde_cbor::de::from_slice;
use serde_cbor::ser::to_vec;
use multimap::MultiMap;
use std::time::{SystemTime, UNIX_EPOCH};
use structopt::StructOpt;
use std::path::PathBuf;

// Implemented by Vitaly "_Vi" Shukela in 2017; Licence = MIT or Apache 2.0

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
}


type Time = u64;

type BoxResult<T> = Result<T, Box<std::error::Error>>;
type Ttl = u32;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
struct AddrTtl {
    ttl: Ttl,

    // FIXME: should be a static array in the better world
    #[serde(with = "serde_bytes")]
    ip: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
struct CacheEntry2 {
    t: Time,
    a: Vec<AddrTtl>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Default)]
struct CacheEntry {
    a4: Option<CacheEntry2>, // None - unqueried
    a6: Option<CacheEntry2>,
}

struct SimplifiedQuestion {
    dom: String,
    a4: bool,
    a6: bool,
}
struct SimplifiedRequest {
    id: u16,
    sa: SocketAddr,
    q: Vec<SimplifiedQuestion>,
    inhibit_send: bool,
}

fn send_dns_reply(
    s: &UdpSocket,
    r: &SimplifiedRequest,
    ans_a: &[(String, Vec<AddrTtl>)],
    ans_aaaa: &[(String, Vec<AddrTtl>)],
) -> BoxResult<()> {

    let mut num_answers = ans_a.iter().fold(0, |a, x| a + x.1.len()) +
        ans_aaaa.iter().fold(0, |a, x| a + x.1.len());
    if num_answers > 0xFFFF {
        num_answers = 0xFFFF;
    } // XXX

    let mut reply_buf = Vec::with_capacity(600);
    reply_buf.put_u16::<BE>(r.id);
    reply_buf.put_u16::<BE>(0x8180); // response, recursion, recursion
    reply_buf.put_u16::<BE>(r.q.len() as u16); // q-s
    reply_buf.put_u16::<BE>(num_answers as u16); // a-s
    reply_buf.put_u16::<BE>(0); // auth-s
    reply_buf.put_u16::<BE>(0); // addit

    fn putname(reply_buf: &mut Vec<u8>, dom: &str) {
        for l in dom.split('.') {
            reply_buf.put_u8(l.len() as u8);
            reply_buf.put(l);
        }
        reply_buf.put_u8(0x00);
    }

    for q in &r.q {
        putname(&mut reply_buf, q.dom.as_str());
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
        for &AddrTtl { ref ip, ttl } in a {
            putname(&mut reply_buf, dom);
            reply_buf.put_u16::<BE>(0x0001); // A
            reply_buf.put_u16::<BE>(0x0001); // IN
            reply_buf.put_u32::<BE>(ttl); // TTL
            reply_buf.put_u16::<BE>(4); // data len
            if ip.len() != 4 {
                return Err("non 4-byte IPv4")?;
            }
            reply_buf.put(&ip[..]);
        }
    }
    for &(ref dom, ref aaaa) in ans_aaaa {
        for &AddrTtl { ref ip, ttl } in aaaa {
            putname(&mut reply_buf, dom.as_str());
            reply_buf.put_u16::<BE>(0x001C); // A
            reply_buf.put_u16::<BE>(0x0001); // IN
            reply_buf.put_u32::<BE>(ttl); // TTL
            reply_buf.put_u16::<BE>(16); // data len
            if ip.len() != 16 {
                return Err("non 16-byte IPv6")?;
            }
            reply_buf.put(&ip[..]);
        }
    }

    s.send_to(&reply_buf[..], &r.sa)?;
    Ok(())
}


enum TryAnswerRequestResult {
    Resolved(AdjustTtlResult),
    UnknownsRemain(usize),
}

#[derive(PartialEq, Debug)]
enum AdjustTtlResult {
    Ok,
    Expired,
    Negative(u64),
}

fn adjust_ttl(
    v: &[AddrTtl],
    now: Time,
    then: Time,
    max_ttl: u32,
    min_ttl: u32,
) -> (AdjustTtlResult, Vec<AddrTtl>) {
    let mut vv = Vec::with_capacity(v.len());
    let mut result = AdjustTtlResult::Ok;
    for &AddrTtl { ref ip, ttl } in v {
        let ttl = clamp::clamp(min_ttl, ttl, max_ttl);
        let newttl;
        if now.saturating_sub(then) >= u64::from(ttl) {
            newttl = 0;
            result = AdjustTtlResult::Expired;
        } else {
            newttl = ttl.saturating_sub(now.saturating_sub(then) as u32);
        }
        vv.push(AddrTtl {
            ip: ip.clone(),
            ttl: newttl,
        });
    }
    if v.is_empty() {
        result = AdjustTtlResult::Negative(now.saturating_sub(then));
    }
    (result, vv)
}

fn try_answer_request(
    db: &mut DB,
    now: Time,
    s: &UdpSocket,
    r: &SimplifiedRequest,
    max_ttl: u32,
    min_ttl: u32,
) -> BoxResult<TryAnswerRequestResult> {

    let mut num_unknowns = 0;

    let mut ans_a4 = Vec::with_capacity(4);
    let mut ans_a6 = Vec::with_capacity(4);

    let mut ttl_status = AdjustTtlResult::Ok;

    for q in &r.q {
        assert!(q.a4 || q.a6);
        if let Some(ceb) = db.get(q.dom.as_bytes()) {
            let ce: CacheEntry = from_slice(&ceb[..])?;
            if q.a4 {
                if let Some(a4) = ce.a4 {
                    let (tr, a4adj) = adjust_ttl(&a4.a, now, a4.t, max_ttl, min_ttl);
                    if ttl_status == AdjustTtlResult::Ok {
                        ttl_status = tr
                    }
                    ans_a4.push((q.dom.clone(), a4adj));
                } else {
                    num_unknowns += 1;
                    continue;
                }
            }

            if q.a6 {
                if let Some(a6) = ce.a6 {
                    let (tr, a6adj) = adjust_ttl(&a6.a, now, a6.t, max_ttl, min_ttl);
                    if ttl_status == AdjustTtlResult::Ok {
                        ttl_status = tr
                    }
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
    if !r.inhibit_send {
        send_dns_reply(s, r, &ans_a4, &ans_a6)?;
    }
    Ok(TryAnswerRequestResult::Resolved(ttl_status))
}


type UnrepliedRequests = CompactMap<SimplifiedRequest>;
type UnrepliedRequestId = usize;
type DomUpdateSubstriptions = MultiMap<String, UnrepliedRequestId>;

struct ProgState {
    db: DB,
    s: UdpSocket,
    r2a: HashMap<u16, SocketAddr>,
    upstream: SocketAddr,
    neg_ttl: u64,
    max_ttl: u32,
    min_ttl: u32,

    unreplied_requests: UnrepliedRequests,
    dom_update_subscriptions: DomUpdateSubstriptions,
}


#[derive(PartialEq)]
enum StepResult {
    GoOn,
    EarlyReturn,
}
use StepResult::*;

macro_rules! may_return_early {
    [
        $(
            $func:ident(
                $($e:expr),*
            )?
        );*;
    ] => {
        $(
            if $func($($e),*)? == StepResult::EarlyReturn {
                return Ok(());
            }
        )* 
    }
}

impl ProgState {
    fn packet_from_upstream(&mut self, buf: &[u8]) -> BoxResult<()> {
        //println!("reply: {:?}", p);
        println!("  upstream");
        let p = Packet::parse(buf)?;

        // Recipe:

        may_return_early!{
            handle_direct_replies(self, buf, &p)?;
            check_questions(self, &p)?;
        };

        let mut cnames = HashMap::new();
        let mut actual_answers = vec![];

        may_return_early! {
            get_cname_redirs(&p, &mut cnames)?;
            make_list_of_ips(&p, &cnames, &mut actual_answers)?;
            check_answers(self, &p, &actual_answers)?;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut tmp: HashMap<String, CacheEntry> = HashMap::new();

        may_return_early! {
            build_new_entries(&p, actual_answers, &mut tmp, now)?;
            save_entries_to_database(self, &mut tmp)?;
            reply_to_client(self, tmp, now)?;
        }

        return Ok(());


        // Implementation:

        // 1. Handle direct requests

        fn handle_direct_replies(
            this: &mut ProgState,
            buf: &[u8],
            p: &Packet,
        ) -> BoxResult<StepResult> {
            if let Some(ca) = this.r2a.remove(&p.header.id) {
                println!("  direct reply");
                this.s.send_to(buf, &ca)?;
                Ok(EarlyReturn)
            } else {
                Ok(GoOn)
            }
        }

        fn check_dom(this: &ProgState, dom: &str, id: u16) -> bool {
            if let Some(rqs) = this.dom_update_subscriptions.get_vec(dom) {
                let mut good = false;
                for i in rqs {
                    if let Some(rq) = this.unreplied_requests.get(*i) {
                        if rq.id == id {
                            good = true;
                        }
                    } else {
                        eprintln!("  assertion failed 1");
                        return false;
                    }
                }
                if !good {
                    println!("  ID mismatch");
                    return false;
                } else {
                    return true;
                }
            } else {
                println!("  unsolicited reply for {}", dom);
                return false;
            }
        }

        // 2. Check if questin list cache poisoning attempt

        fn check_questions(this: &ProgState, p: &Packet) -> BoxResult<StepResult> {
            for q in &p.questions {
                let dom = q.qname.to_string();
                if !check_dom(this, dom.as_str(), p.header.id) {
                    return Ok(EarlyReturn);
                }
            }
            Ok(GoOn)
        }

        // 3. Make a map of CNAME redirections for later use
        fn get_cname_redirs(
            p: &Packet,
            cnames: &mut HashMap<String, String>,
        ) -> BoxResult<StepResult> {
            for ans in &p.answers {
                if let RRData::CNAME(x) = ans.data {
                    let from = ans.name.to_string();
                    let to = x.to_string();
                    println!("  {} -> {}", &from, &to);
                    cnames.insert(to, from);
                }
            }
            Ok(GoOn)
        }

        // 4. Make list of IP addresses of domains, following CNAMEs

        fn make_list_of_ips<'a>(
            p: &'a Packet,
            cnames: &HashMap<String, String>,
            actual_answers: &mut Vec<(String, &RRData<'a>, Ttl)>,
        ) -> BoxResult<StepResult> {
            for ans in &p.answers {
                if ans.cls != dns_parser::Class::IN {
                    continue;
                }
                match ans.data {
                    RRData::A(_) | RRData::AAAA(_) => {}
                    _ => continue,
                }

                let mut dom = ans.name.to_string();
                let mut recursion_limit = 10;
                loop {
                    if let Some(x) = cnames.get(&dom) {
                        dom = x.clone();
                        recursion_limit -= 1;
                        if recursion_limit == 0 {
                            println!("  Too many CNAMEs");
                            return Ok(EarlyReturn);
                        }
                        continue;
                    }
                    break;
                }
                actual_answers.push((dom, &ans.data, ans.ttl));
            }
            Ok(GoOn)
        }

        // 5. Check after-CNAME-redirection answers for cache poisoning
        fn check_answers(
            this: &ProgState,
            p: &Packet,
            actual_answers: &[(String, &RRData, Ttl)],
        ) -> BoxResult<StepResult> {

            for &(ref dom, data, _) in actual_answers {
                if !check_dom(this, dom.as_str(), p.header.id) {
                    println!("  offending entry: {:?}", data);
                    return Ok(EarlyReturn);
                }
            }
            Ok(GoOn)
        }

        // now we are decided to save things and reply

        // 6. build a list of new entries

        fn build_new_entries(
            p: &Packet,
            actual_answers: Vec<(String, &RRData, Ttl)>,
            tmp: &mut HashMap<String, CacheEntry>,
            now: Time,
        ) -> BoxResult<StepResult> {


            for q in &p.questions {
                if q.qclass != IN {
                    continue;
                }
                let dom = q.qname.to_string();

                let ce = tmp.entry(dom).or_insert_with(Default::default);

                if q.qtype == A || q.qtype == QTAll {
                    ce.a4 = Some(CacheEntry2 {
                        t: now,
                        a: Vec::new(),
                    });
                }
                if q.qtype == AAAA || q.qtype == QTAll {
                    ce.a6 = Some(CacheEntry2 {
                        t: now,
                        a: Vec::new(),
                    });
                }
            }

            for (dom, data, ttl) in actual_answers {
                let ce = tmp.entry(dom).or_insert_with(Default::default);

                match *data {
                    RRData::A(ip4) => {
                        if ce.a4 == None {
                            ce.a4 = Some(CacheEntry2 {
                                t: now,
                                a: Vec::new(),
                            });
                        }
                        let v = ce.a4.as_mut().unwrap();
                        v.a.push(AddrTtl {
                            ip: ip4.octets().to_vec(),
                            ttl,
                        });
                    }
                    RRData::AAAA(ip6) => {
                        if ce.a6 == None {
                            ce.a6 = Some(CacheEntry2 {
                                t: now,
                                a: Vec::new(),
                            });
                        }
                        let v = ce.a6.as_mut().unwrap();
                        v.a.push(AddrTtl {
                            ip: ip6.octets().to_vec(),
                            ttl,
                        });
                    }
                    _ => {
                        println!("  assertion failed 2");
                        continue;
                    }
                }
            }
            Ok(GoOn)
        }

        // 7. save entries to the database, maybe merging with old entries
        fn save_entries_to_database(
            this: &mut ProgState,
            tmp: &mut HashMap<String, CacheEntry>,
        ) -> BoxResult<StepResult> {

            for (dom, mut entry) in tmp {

                let cached: CacheEntry;
                if let Some(ceb) = this.db.get(dom.as_bytes()) {
                    cached = from_slice(&ceb[..])?;
                } else {
                    cached = Default::default();
                }

                // FIXME: DRY between A and AAAA cases

                let mut use_cached_a4 = false;
                let mut use_cached_a6 = false;

                if entry.a4.is_none() && cached.a4.is_some() {
                    use_cached_a4 = true;
                }
                if entry.a6.is_none() && cached.a6.is_some() {
                    use_cached_a6 = true;
                }

                if let Some(CacheEntry2 { a: ref new_a4, .. }) = entry.a4 {
                    if let Some(CacheEntry2 { a: ref cached_a4, .. }) = cached.a4 {
                        if new_a4.is_empty() && !cached_a4.is_empty() {
                            println!("  refusing to forget A entries");
                            use_cached_a4 = true;
                        }
                    }
                }
                if let Some(CacheEntry2 { a: ref new_a6, .. }) = entry.a6 {
                    if let Some(CacheEntry2 { a: ref cached_a6, .. }) = cached.a6 {
                        if new_a6.is_empty() && !cached_a6.is_empty() {
                            println!("  refusing to forget AAAA entries");
                            use_cached_a6 = true;
                        }
                    }
                }

                if use_cached_a4 {
                    entry.a4 = cached.a4;
                }
                if use_cached_a6 {
                    entry.a6 = cached.a6;
                }

                this.db.put(dom.as_bytes(), &to_vec(&entry)?[..])?;
                println!("  saved to database: {}", dom);
            }
            this.db.flush()?;
            Ok(GoOn)
        }

        // 8. Try replying to queued queries

        fn reply_to_client(
            this: &mut ProgState,
            tmp: HashMap<String, CacheEntry>,
            now: Time,
        ) -> BoxResult<StepResult> {

            for (dom, _) in tmp {
                let subs = this.dom_update_subscriptions.remove(&dom).unwrap();
                let mut unhappy = Vec::new();
                let mut happy = Vec::new();
                for sub_id in subs {
                    use TryAnswerRequestResult::*;
                    if let Some(r) = this.unreplied_requests.get(sub_id) {
                        let dummy_request = r.inhibit_send;
                        let result = try_answer_request(
                            &mut this.db,
                            now,
                            &this.s,
                            r,
                            this.max_ttl,
                            this.min_ttl,
                        )?;
                        match result {
                            Resolved(AdjustTtlResult::Ok) => {
                                if !dummy_request {
                                    println!("  replied.");
                                } else {
                                    println!("  refreshed.");
                                }
                                happy.push(sub_id);
                            }
                            Resolved(AdjustTtlResult::Expired) => {
                                if !dummy_request {
                                    println!("  replied?");
                                    happy.push(sub_id);
                                } else {
                                    unhappy.push(sub_id);
                                }
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
                    let _ = this.unreplied_requests.remove(id);
                }
                if !unhappy.is_empty() {
                    this.dom_update_subscriptions.entry(dom).or_insert_vec(
                        unhappy,
                    );
                }
            }
            Ok(GoOn)
        }
    }





    fn packet_from_client(&mut self, src: SocketAddr, buf: &[u8]) -> BoxResult<()> {
        let p = Packet::parse(buf)?;
        //println!("request {:?}", p);
        let mut weird_querty = false;

        let mut simplified_questions = Vec::with_capacity(1);

        if p.questions.len() > 1 {
            println!("A query with {} questions:", p.questions.len());
        }

        for q in &p.questions {
            match q.qclass {
                IN | QCAny => {}
                _ => {
                    weird_querty = true;
                }
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
                a4: q.qtype == A || q.qtype == QTAll,
                a6: q.qtype == AAAA || q.qtype == QTAll,
            };
            simplified_questions.push(sq);
        }

        if weird_querty {
            println!("  direct");
            //println!("Weird requestnow >= then && now - then {:?}",p);
            self.r2a.insert(p.header.id, src);
            self.s.send_to(buf, &self.upstream)?;
            return Ok(());
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut r = SimplifiedRequest {
            id: p.header.id,
            q: simplified_questions,
            sa: src,
            inhibit_send: false,
        };

        use TryAnswerRequestResult::*;
        let result =
            try_answer_request(&mut self.db, now, &self.s, &r, self.max_ttl, self.min_ttl)?;

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

        for q in &r.q {
            self.dom_update_subscriptions.insert(q.dom.clone(), id);
        }
        // Send to upstream as is.
        self.s.send_to(buf, &self.upstream)?;
        Ok(())
    }

    fn serve1(&mut self, buf: &mut [u8]) -> BoxResult<()> {
        let (amt, src) = self.s.recv_from(buf)?;
        let buf = &buf[..amt];
        if src == self.upstream {
            self.packet_from_upstream(buf)?;
        } else {
            self.packet_from_client(src, buf)?;
        }
        Ok(())
    }
}

fn run(opt: &Opt) -> BoxResult<()> {
    let dbopts: rusty_leveldb::Options = Default::default();
    let db = DB::open(
        opt.db.to_str().expect(
            "rusty-leveldb opens only UTF-8 paths",
        ),
        dbopts,
    )?;

    let s = UdpSocket::bind(opt.listen_addr)?;
    let upstream = opt.upstream_addr;

    let r2a: HashMap<u16, SocketAddr> = HashMap::new();

    let mut buf = [0; 1600];

    if opt.listen_addr.ip().is_loopback() && !opt.upstream_addr.ip().is_loopback() {
        eprintln!(
            "Warning: listening on localhost, but sending to non-localhost upstream server is not supported"
        );
    }

    let mut ps = ProgState {
        db,
        s,
        upstream,
        r2a,
        unreplied_requests: CompactMap::new(),
        dom_update_subscriptions: MultiMap::new(),
        neg_ttl: opt.neg_ttl,
        max_ttl: opt.max_ttl,
        min_ttl: opt.min_ttl,
    };

    loop {
        if let Err(e) = ps.serve1(&mut buf) {
            eprintln!("Error: {:?}", e);
        }
    }
}

fn main() {
    let opt = Opt::from_args();
    if let Err(e) = run(&opt) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
