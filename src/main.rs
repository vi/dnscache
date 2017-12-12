#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]
extern crate dns_parser;
extern crate compactmap;
#[macro_use]
extern crate serde_derive;
extern crate rustbreak;
extern crate bytes;

use std::net::{UdpSocket, SocketAddr, Ipv4Addr, Ipv6Addr};
use dns_parser::Packet;
use dns_parser::QueryType::{self, A,AAAA,All as QTAll};
use dns_parser::QueryClass::{IN,Any as QCAny};
use std::collections::HashMap;
use compactmap::CompactMap;
use rustbreak::Database;
use std::time::Duration;
use std::io::Cursor;
use bytes::{BufMut,BigEndian as BE};

type CacheId = usize;
type Time = u64;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
struct CacheEntry {
    a: Option<Vec<Ipv4Addr>>, // None - unqueried
    aaaa: Option<Vec<Ipv6Addr>>,
    obtained : Time,
    ttl: Duration,
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
}


fn run() -> Result<(),Box<std::error::Error>> {

    let db : Database<CacheEntry> = Database::open("./db")?;

    let s = UdpSocket::bind("0.0.0.0:3553")?;
    let upstream : SocketAddr = "8.8.8.8:53".parse()?;
    
    let mut r2a : HashMap<u16, SocketAddr> = HashMap::new();
    
    let mut buf = [0; 1600];
    let mut reply_buf = Vec::with_capacity(1600);
    loop {
        let (amt, src) = s.recv_from(&mut buf)?;
        let buf = &mut buf[..amt];
        let p = Packet::parse(buf)?;
        
        if src == upstream {
            println!("reply: {:?}", p);
            
            if let Some(ca) = r2a.remove(&p.header.id) {
                s.send_to(&buf, &ca)?;
            }
            
        } else {
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
                println!("{:?} {}", q.qtype, dom);
                let sq = SimplifiedQuestion {
                    dom,
                    a:    q.qtype == A    || q.qtype == QTAll,
                    aaaa: q.qtype == AAAA || q.qtype == QTAll,
                };
                simplified_questions.push(sq);
            }
            
            if weird_querty {
                println!("Weird request {:?}",p);
                r2a.insert(p.header.id, src);
                s.send_to(&buf, &upstream)?;
            }
            
            let r = SimplifiedRequest {
                id : p.header.id,
                q : simplified_questions,
                sa: src,
            };
            
            reply_buf.clear();
            reply_buf.put_u16::<BE>(r.id);
            reply_buf.put_u16::<BE>(0x8180); // response, recursion
            reply_buf.put_u16::<BE>(r.q.len() as u16); // q-s
            reply_buf.put_u16::<BE>(r.q.len() as u16); // a-s
            reply_buf.put_u16::<BE>(0); // auth-s
            reply_buf.put_u16::<BE>(0); // addit
            for q in &r.q {
                for l in q.dom.split(".") {
                    reply_buf.put_u8(l.len() as u8);
                    reply_buf.put(l);
                }
                reply_buf.put_u8(0x00); // end of name
                reply_buf.put_u16::<BE>(0x0001); // A
                reply_buf.put_u16::<BE>(0x0001); // IN
            }
            for q in &r.q {
                for l in q.dom.split(".") {
                    reply_buf.put_u8(l.len() as u8); // < 64
                    reply_buf.put(l);
                }
                reply_buf.put_u8(0x00); // end of name
                reply_buf.put_u16::<BE>(0x0001); // A
                reply_buf.put_u16::<BE>(0x0001); // IN
                reply_buf.put_u32::<BE>(3600); // TTL
                reply_buf.put_u16::<BE>(4); // data len
                reply_buf.put_u32::<BE>(0x7F000506); // IP
            }
            
            s.send_to(&reply_buf[..], &src)?;
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
