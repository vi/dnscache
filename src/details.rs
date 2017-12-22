// Implemented by Vitaly "_Vi" Shukela in 2017; Licence = MIT or Apache 2.0

use super::*;

use dns_parser::Packet;
use dns_parser::QueryType::{A, AAAA, All as QTAll};
use dns_parser::QueryClass::{IN, Any as QCAny};
use dns_parser::RRData;
use bytes::{BufMut, BigEndian as BE};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn send_dns_reply<N:Network>(
    net: &N,
    r: &SimplifiedRequest<N::ClientId>,
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

    net.send_to_client(&reply_buf[..], r.clientid)?;
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

fn try_answer_request<DB:Database, N:Network>(
    db: &mut DB,
    now: Time,
    net: &N,
    r: &SimplifiedRequest<N::ClientId>,
    max_ttl: u32,
    min_ttl: u32,
) -> BoxResult<TryAnswerRequestResult> {

    let mut num_unknowns = 0;

    let mut ans_a4 = Vec::with_capacity(4);
    let mut ans_a6 = Vec::with_capacity(4);

    let mut ttl_status = AdjustTtlResult::Ok;

    for q in &r.q {
        assert!(q.a4 || q.a6);
        if let Some(ce) = db.get(q.dom.as_str())? {
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
        send_dns_reply(net, r, &ans_a4, &ans_a6)?;
    }
    Ok(TryAnswerRequestResult::Resolved(ttl_status))
}


#[derive(PartialEq)]
enum StepResult {
    GoOn,
    EarlyReturn,
}
use self::StepResult::*;

macro_rules! may_return_early {
    [
        $(
            $func:ident(
                $($e:expr),*
            )?
        );*;
    ] => {
        $(
            if DnsCache::<DB,N>::$func($($e),*)? == StepResult::EarlyReturn {
                return Ok(());
            }
        )* 
    }
}

impl<DB: Database, N: Network> DnsCache<DB, N> {
    fn packet_from_upstream(&mut self, buf: &[u8]) -> BoxResult<()> {
        //println!("reply: {:?}", p);
        println!("  upstream");
        let p = Packet::parse(buf)?;

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

        Ok(())
    }

    // Implementation:

    // 1. Handle direct requests

    fn handle_direct_replies(
        &mut self,
        buf: &[u8],
        p: &Packet,
    ) -> BoxResult<StepResult> {
        if let Some(ca) = self.r2a.remove(&p.header.id) {
            println!("  direct reply");
            self.net.send_to_client(buf, ca)?;
            Ok(EarlyReturn)
        } else {
            Ok(GoOn)
        }
    }

    fn check_dom(&self, dom: &str, id: u16) -> bool {
        if let Some(rqs) = self.dom_update_subscriptions.get_vec(dom) {
            let mut good = false;
            for i in rqs {
                if let Some(rq) = self.unreplied_requests.get(*i) {
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

    fn check_questions(&self, p: &Packet) -> BoxResult<StepResult> {
        for q in &p.questions {
            let dom = q.qname.to_string();
            if !self.check_dom(dom.as_str(), p.header.id) {
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
        &self,
        p: &Packet,
        actual_answers: &[(String, &RRData, Ttl)],
    ) -> BoxResult<StepResult> {

        for &(ref dom, data, _) in actual_answers {
            if !self.check_dom(dom.as_str(), p.header.id) {
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
        &mut self,
        tmp: &mut HashMap<String, CacheEntry>,
    ) -> BoxResult<StepResult> {

        for (dom, mut entry) in tmp {
            
            let cached: CacheEntry;
            if let Some(ce) = self.db.get(dom)? {
                cached = ce;
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

            self.db.put(dom.as_str(), entry)?;
            println!("  saved to database: {}", dom);
        }
        self.db.flush()?;
        Ok(GoOn)
    }

    // 8. Try replying to queued queries

    fn reply_to_client(
        &mut self,
        tmp: HashMap<String, CacheEntry>,
        now: Time,
    ) -> BoxResult<StepResult> {

        for (dom, _) in tmp {
            let subs = self.dom_update_subscriptions.remove(&dom).unwrap();
            let mut unhappy = Vec::new();
            let mut happy = Vec::new();
            for sub_id in subs {
                use self::TryAnswerRequestResult::*;
                if let Some(r) = self.unreplied_requests.get(sub_id) {
                    let dummy_request = r.inhibit_send;
                    let result = try_answer_request(
                        &mut self.db,
                        now,
                        &self.net,
                        r,
                        self.opts.max_ttl,
                        self.opts.min_ttl,
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
                let _ = self.unreplied_requests.remove(id);
            }
            if !unhappy.is_empty() {
                self.dom_update_subscriptions.entry(dom).or_insert_vec(
                    unhappy,
                );
            }
        }
        Ok(GoOn)
    }
    
    
    
    
    
    fn packet_from_client(&mut self, src: N::ClientId, buf: &[u8]) -> BoxResult<()> {
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
            self.net.send_to_upstream(buf)?;
            return Ok(());
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut r = SimplifiedRequest {
            id: p.header.id,
            q: simplified_questions,
            clientid: src,
            inhibit_send: false,
        };

        use self::TryAnswerRequestResult::*;
        let result =
            try_answer_request(&mut self.db, now, &self.net, &r, self.opts.max_ttl, self.opts.min_ttl)?;

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
                if x >= self.opts.neg_ttl {
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
        self.net.send_to_upstream(buf)?;
        Ok(())
    }

    pub(crate) fn serve1(&mut self, buf: &mut [u8]) -> BoxResult<()> {
        let (amt, src) = self.net.recv_from(buf)?;
        let buf = &buf[..amt];
        match src {
            ReceiveResult::FromUpstream => self.packet_from_upstream(buf)?,
            ReceiveResult::FromClient(src) => self.packet_from_client(src, buf)?,
        }
        Ok(())
    }
}
