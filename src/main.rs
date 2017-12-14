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

use std::net::{UdpSocket, SocketAddr, Ipv4Addr, Ipv6Addr};
use dns_parser::Packet;
use dns_parser::QueryType::{self, A,AAAA,All as QTAll};
use dns_parser::QueryClass::{IN,Any as QCAny};
use std::collections::HashMap;
use compactmap::CompactMap;
use rusty_leveldb::DB;
use std::time::Duration;
use std::io::Cursor;
use bytes::{BufMut,BigEndian as BE};
use serde_cbor::de::from_slice;
use serde_cbor::ser::to_vec;

type CacheId = usize;
type Time = u64;

type BoxResult<T> = Result<T,Box<std::error::Error>>;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
struct CacheEntry {
    a: Option<Vec<Ipv4Addr>>, // None - unqueried
    aaaa: Option<Vec<Ipv6Addr>>,
    obtained : Time,
    ttl: u32,
}

type Cache = CompactMap<CacheEntry>;
struct RequestToUs {
    entry: CacheId,
    reply_to: SocketAddr,
    id: u16,
}

struct SimplifiedQuestion {
    dom: String,
    a: bool,
    aaaa: bool,
}
struct SimplifiedRequest {
    id : u16,
    sa : SocketAddr,
    q: Vec<SimplifiedQuestion>,
    unknowns_remain: usize,
}


struct ScratchSpace {
    reply_buf: Vec<u8>,
    ans_a:    Vec<(String, Vec<Ipv4Addr>)>,
    ans_aaaa: Vec<(String, Vec<Ipv6Addr>)>,
}

fn send_dns_reply(
                s : &UdpSocket, 
                reply_buf:&mut Vec<u8>, 
                r: &SimplifiedRequest,
                ans_a:    &Vec<(String, Vec<Ipv4Addr>)>,
                ans_aaaa: &Vec<(String, Vec<Ipv6Addr>)>,
                ) -> BoxResult<()> {
    
    let mut num_answers = ans_a.len() + ans_aaaa.len();
    if num_answers > 65535 { num_answers=65535; } // XXX
    
    reply_buf.clear();
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
        if q.a && q.aaaa {
            reply_buf.put_u16::<BE>(0x00FF); // All
        } else if q.a {
            reply_buf.put_u16::<BE>(0x0001); // A
        } else if q.aaaa {
            reply_buf.put_u16::<BE>(0x001C); // AAAA
        } else {
            println!("?");
            reply_buf.put_u16::<BE>(0x0000);
        }
        reply_buf.put_u16::<BE>(0x0001); // IN
    }
    for &(ref dom, ref a) in ans_a {
        for ip in a {
            for l in dom.split(".") {
                reply_buf.put_u8(l.len() as u8); // < 64
                reply_buf.put(l);
            }
            reply_buf.put_u8(0x00); // end of name
            reply_buf.put_u16::<BE>(0x0001); // A
            reply_buf.put_u16::<BE>(0x0001); // IN
            reply_buf.put_u32::<BE>(3600); // TTL
            reply_buf.put_u16::<BE>(4); // data len
            reply_buf.put(&ip.octets()[..]);
        }
    }
    for &(ref dom, ref aaaa) in ans_aaaa {
        for ip6 in aaaa {
            for l in dom.split(".") {
                reply_buf.put_u8(l.len() as u8); // < 64
                reply_buf.put(l);
            }
            reply_buf.put_u8(0x00); // end of name
            reply_buf.put_u16::<BE>(0x001C); // A
            reply_buf.put_u16::<BE>(0x0001); // IN
            reply_buf.put_u32::<BE>(3600); // TTL
            reply_buf.put_u16::<BE>(16); // data len
            reply_buf.put(&ip6.octets()[..]);
        }
    }
    
    s.send_to(&reply_buf[..], &r.sa)?;
    Ok(())
}


enum TryAnswerRequestResult {
    Resolved,
    UnknownsRemain(usize),
}
fn try_answer_request(
                db : &mut DB,
                s : &UdpSocket,
                tmp: &mut ScratchSpace,
                r: &SimplifiedRequest
                ) -> BoxResult<TryAnswerRequestResult> {
    
    let mut num_unknowns = 0;
    
    let mut ans_a = &mut tmp.ans_a;
    let mut ans_aaaa = &mut tmp.ans_aaaa;
    ans_a.clear();
    ans_aaaa.clear();
    
    for q in &r.q {
        assert!(q.a || q.aaaa);
        if let Some(ceb) = db.get(q.dom.as_bytes()) {
            let ce : CacheEntry = from_slice(&ceb[..])?;
            if q.a {
                if let Some(a) = ce.a {
                    ans_a.push((q.dom.clone(), a));
                } else {
                    num_unknowns += 1;
                    continue;
                }
            }
            
            if q.aaaa {
                if let Some(aaaa) = ce.aaaa {
                    ans_aaaa.push((q.dom.clone(), aaaa));
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
    send_dns_reply(s, &mut tmp.reply_buf, r, &ans_a, &ans_aaaa)?;
    Ok(TryAnswerRequestResult::Resolved)
}

struct ProgState {
    db : DB,
    s : UdpSocket,
    buf: [u8; 1600],
    amt: usize,
    tmp: ScratchSpace,
    r2a: HashMap<u16, SocketAddr>,
    upstream : SocketAddr,
}

impl ProgState {
    fn from_upstream(&mut self) -> BoxResult<()> {
        //println!("reply: {:?}", p);
        println!("reply from upstream");
        
        let buf = &self.buf[..self.amt];
        let p = Packet::parse(buf)?;
        
        if let Some(ca) = self.r2a.remove(&p.header.id) {
            self.s.send_to(&buf, &ca)?;
        }
        Ok(())
    }
    
    fn from_client(&mut self, src: SocketAddr) -> BoxResult<()> {
        let buf = &self.buf[..self.amt];
        let p = Packet::parse(buf)?;
        //println!("request {:?}", p);
        let mut weird_querty = false;
        
        let mut simplified_questions = Vec::with_capacity(1);
        
        for q in &p.questions {
            match q.qclass {
                IN  |
                QCAny => {}
                _ => { weird_querty = true; }
            }
            match q.qtype {
                A |
                AAAA |
                QTAll => {}
                _ => { weird_querty = true; }
            }
            
            let dom = q.qname.to_string();
            println!("{:?}\t{}", q.qtype, dom);
            let sq = SimplifiedQuestion {
                dom,
                a:    q.qtype == A    || q.qtype == QTAll,
                aaaa: q.qtype == AAAA || q.qtype == QTAll,
            };
            simplified_questions.push(sq);
        }
        
        if weird_querty {
            println!("Weird request {:?}",p);
            self.r2a.insert(p.header.id, src);
            self.s.send_to(&buf, &self.upstream)?;
        }
        
        let r = SimplifiedRequest {
            id : p.header.id,
            q : simplified_questions,
            sa: src,
            unknowns_remain: 0,
        };
        
        for q in &r.q {
            if let None = self.db.get(q.dom.as_bytes()) {
                let ce = CacheEntry {
                    a:    Some(vec!["127.1.2.3".parse()?]),
                    aaaa: Some(vec!["23::44".parse()?]),
                    obtained: 123,
                    ttl: Default::default(),
                };
                self.db.put(q.dom.as_bytes(), &to_vec(&ce)?[..])?;
                self.db.flush()?;
                println!("Saved to database: {}", q.dom);
            }
        }
        
        use TryAnswerRequestResult::UnknownsRemain;
        if let UnknownsRemain(x) = try_answer_request(
                                        &mut self.db,
                                        &self.s, 
                                        &mut self.tmp, 
                                        &r
                        )? {
            println!("Unknowns remain: {}", x);
        }
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

fn run() -> BoxResult<()> {

    let dbopts : rusty_leveldb::Options = Default::default();
    let db = DB::open("./db", dbopts)?;

    let s = UdpSocket::bind("0.0.0.0:3553")?;
    let upstream : SocketAddr = "8.8.8.8:53".parse()?;
    
    let mut r2a : HashMap<u16, SocketAddr> = HashMap::new();
    
    let mut buf = [0; 1600];
    
    let mut tmp = ScratchSpace {
        reply_buf: Vec::with_capacity(1600),
        ans_a: Vec::with_capacity(20),
        ans_aaaa: Vec::with_capacity(20),
    };
    
    let mut ps = ProgState {
        db,
        s,
        upstream,
        r2a,
        buf,
        tmp,
        amt: 0,
    };
    
    loop {
        if let Err(e) = ps.serve1() {
            eprintln!("Error: {:?}", e);
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
