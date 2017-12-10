#![allow(unused_mut)]
#![allow(unused_variables)]
extern crate dns_parser;

use std::net::{UdpSocket, SocketAddr};
use dns_parser::Packet;
use std::collections::HashMap;

fn run() -> Result<(),Box<std::error::Error>> {

    let s = UdpSocket::bind("0.0.0.0:3553")?;
    let upstream : SocketAddr = "8.8.8.8:53".parse()?;
    
    let mut r2a : HashMap<u16, SocketAddr> = HashMap::new();
    
    let mut buf = [0; 1600];
    loop {
        let (amt, src) = s.recv_from(&mut buf)?;
        let buf = &mut buf[..amt];
        let p = Packet::parse(buf)?;
        
        if src == upstream {
            println!("reply: {:?}", p);
            
            if let Some(ca) = r2a.get(&p.header.id) {
                s.send_to(&buf, &ca)?;
            }
            
        } else {
            println!("request {:?}", p);
            
            r2a.insert(p.header.id, src);
            
            s.send_to(&buf, &upstream)?;
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
