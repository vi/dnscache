extern crate dns_parser;

use std::net::UdpSocket;

fn run() -> std::io::Result<()> {
    let s = UdpSocket::bind("127.0.0.1:3553")?;
    
    let mut buf = [0; 1600];
    loop {
        let (amt, src) = s.recv_from(&mut buf)?;
        let buf = &mut buf[..amt];
        s.send_to(&buf, &src)?;
    }
}

fn main() {
    run().unwrap()
}
