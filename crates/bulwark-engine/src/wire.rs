//! DNS wire parsing and cache-response patching.

/// OPT fields at the TTL offset must not be patched.
const TYPE_OPT: u16 = 41;

/// Returns the offset after a DNS name without following pointers.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let b = *buf.get(pos)?;
        match b & 0xC0 {
            0x00 if b == 0 => return Some(pos + 1),
            0x00 => pos = pos.checked_add(1 + b as usize)?,
            0xC0 => return pos.checked_add(2),
            _ => return None,
        }
    }
}

/// Finds resource-record TTL offsets, excluding OPT.
pub fn scan_ttl_offsets(buf: &[u8]) -> Option<Vec<u32>> {
    if buf.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4)?;
        if pos > buf.len() {
            return None;
        }
    }

    let rr_count = an.checked_add(ns)?.checked_add(ar)?;
    let mut offsets = Vec::with_capacity(rr_count);
    for _ in 0..rr_count {
        pos = skip_name(buf, pos)?;
        if pos.checked_add(10)? > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl_off = pos + 4;
        if rtype != TYPE_OPT {
            offsets.push(ttl_off as u32);
        }
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos = pos.checked_add(10 + rdlen)?;
        if pos > buf.len() {
            return None;
        }
    }
    Some(offsets)
}

/// Patches a response transaction id and TTLs.
pub fn patch(buf: &mut [u8], id: u16, ttl: u32, ttl_offsets: &[u32]) {
    if buf.len() >= 2 {
        buf[0..2].copy_from_slice(&id.to_be_bytes());
    }
    let t = ttl.to_be_bytes();
    for &off in ttl_offsets {
        let o = off as usize;
        if let Some(slot) = buf.get_mut(o..o + 4) {
            slot.copy_from_slice(&t);
        }
    }
}

/// Query fields parsed without allocating a `Message`.
#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub id: u16,
    pub recursion_desired: bool,
    pub checking_disabled: bool,
    pub opcode: u8,
    /// Dot-terminated question name in its wire case.
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Advertised EDNS UDP payload size, if the query carries an OPT record.
    pub edns_payload: Option<u16>,
    /// EDNS DO (DNSSEC OK) bit.
    pub dnssec_ok: bool,
}

/// Reads a question name when it can match hickory's ASCII representation.
fn read_question_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    loop {
        let b = *buf.get(pos)?;
        match b & 0xC0 {
            0x00 if b == 0 => {
                if pos + 1 - start > 255 {
                    return None;
                }
                if name.is_empty() {
                    name.push('.');
                }
                return Some((name, pos + 1));
            }
            0x00 => {
                let lstart = pos + 1;
                let lend = lstart.checked_add(b as usize)?;
                for (j, &c) in buf.get(lstart..lend)?.iter().enumerate() {
                    // Accept only bytes hickory emits without escaping.
                    let is_first = j == 0;
                    let safe = c.is_ascii_alphanumeric()
                        || c == b'_'
                        || (c == b'-' && !is_first)
                        || (c == b'*' && is_first);
                    if !safe {
                        return None;
                    }
                    name.push(c as char);
                }
                name.push('.');
                pos = lend;
            }
            _ => return None,
        }
    }
}

/// Parses a strict subset of DNS queries for the hot path.
pub fn parse_query(buf: &[u8]) -> Option<ParsedQuery> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    // Header flag bytes: b2 = QR|Opcode(4)|AA|TC|RD, b3 = RA|Z|AD|CD|RCODE(4).
    let b2 = buf[2];
    let recursion_desired = b2 & 0x01 != 0;
    let opcode = (b2 >> 3) & 0x0F;
    let checking_disabled = buf[3] & 0x10 != 0;
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;
    if qd != 1 {
        return None;
    }

    let (qname, mut pos) = read_question_name(buf, 12)?;
    if pos.checked_add(4)? > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    pos += 4;

    // Match hickory's single-additional-OPT constraint.
    let mut edns_payload = None;
    let mut dnssec_ok = false;
    let additional_start = an.checked_add(ns)?;
    let total = additional_start.checked_add(ar)?;
    for idx in 0..total {
        pos = skip_name(buf, pos)?;
        if pos.checked_add(10)? > buf.len() {
            return None;
        }
        if u16::from_be_bytes([buf[pos], buf[pos + 1]]) == TYPE_OPT {
            if idx < additional_start || edns_payload.is_some() {
                return None;
            }
            edns_payload = Some(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
            dnssec_ok = buf[pos + 6] & 0x80 != 0;
        }
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos = pos.checked_add(10 + rdlen)?;
        if pos > buf.len() {
            return None;
        }
    }

    Some(ParsedQuery {
        id,
        recursion_desired,
        checking_disabled,
        opcode,
        qname,
        qtype,
        qclass,
        edns_payload,
        dnssec_ok,
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

    use super::*;

    fn response_with(answers: &[(u32, RData)], edns: bool) -> Message {
        let mut m = Message::new(0xABCD, MessageType::Response, OpCode::Query);
        m.metadata.response_code = ResponseCode::NoError;
        let mut q = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
        q.set_query_class(DNSClass::IN);
        m.queries.push(q);
        for (ttl, data) in answers {
            m.answers.push(Record::from_rdata(
                Name::from_str("example.com.").unwrap(),
                *ttl,
                data.clone(),
            ));
        }
        if edns {
            m.edns = Some(Default::default());
        }
        m
    }
    #[test]
    fn patches_all_answer_ttls() {
        let msg = response_with(
            &[
                (300, RData::A(A::new(1, 2, 3, 4))),
                (600, RData::A(A::new(5, 6, 7, 8))),
                (900, RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1))),
            ],
            false,
        );
        let mut wire = msg.to_vec().unwrap();
        let offsets = scan_ttl_offsets(&wire).expect("scan");
        assert_eq!(offsets.len(), 3);

        patch(&mut wire, 0x1234, 42, &offsets);
        let back = Message::from_vec(&wire).unwrap();
        assert_eq!(back.metadata.id, 0x1234);
        assert_eq!(back.answers.len(), 3);
        for r in &back.answers {
            assert_eq!(r.ttl, 42, "every answer TTL should be rewritten");
        }
    }
    #[test]
    fn does_not_patch_opt_record() {
        let msg = response_with(&[(300, RData::A(A::new(1, 2, 3, 4)))], true);
        let mut wire = msg.to_vec().unwrap();
        let offsets = scan_ttl_offsets(&wire).expect("scan");
        assert_eq!(offsets.len(), 1, "OPT must be excluded");

        patch(&mut wire, 0x1111, 10, &offsets);
        let back = Message::from_vec(&wire).unwrap();
        assert_eq!(back.answers[0].ttl, 10);
        assert!(back.edns.is_some());
    }
    #[test]
    fn patches_authority_soa() {
        use hickory_proto::rr::rdata::SOA;
        let mut m = Message::new(7, MessageType::Response, OpCode::Query);
        m.metadata.response_code = ResponseCode::NXDomain;
        let mut q = Query::query(Name::from_str("nope.example.com.").unwrap(), RecordType::A);
        q.set_query_class(DNSClass::IN);
        m.queries.push(q);
        m.authorities.push(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            3600,
            RData::SOA(SOA::new(
                Name::from_str("ns.example.com.").unwrap(),
                Name::from_str("hostmaster.example.com.").unwrap(),
                1,
                7200,
                3600,
                1209600,
                300,
            )),
        ));
        let mut wire = m.to_vec().unwrap();
        let offsets = scan_ttl_offsets(&wire).expect("scan");
        assert_eq!(offsets.len(), 1);
        patch(&mut wire, 9, 5, &offsets);
        let back = Message::from_vec(&wire).unwrap();
        assert_eq!(back.authorities[0].ttl, 5);
    }
    #[test]
    fn empty_answers_ok() {
        let msg = response_with(&[], false);
        let mut wire = msg.to_vec().unwrap();
        let offsets = scan_ttl_offsets(&wire).expect("scan");
        assert!(offsets.is_empty());
        patch(&mut wire, 0x2222, 1, &offsets);
        assert_eq!(Message::from_vec(&wire).unwrap().metadata.id, 0x2222);
    }
    #[test]
    fn malformed_returns_none() {
        assert!(scan_ttl_offsets(&[]).is_none());
        assert!(scan_ttl_offsets(&[0u8; 5]).is_none());
        let mut buf = vec![0u8; 12];
        buf[6] = 0; // ANCOUNT hi
        buf[7] = 1; // ANCOUNT lo
        assert!(scan_ttl_offsets(&buf).is_none());
    }
    fn query_msg(name: &str, rtype: RecordType, edns: Option<(u16, bool)>) -> Message {
        let mut m = Message::new(0x1234, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        let mut q = Query::query(Name::from_str(name).unwrap(), rtype);
        q.set_query_class(DNSClass::IN);
        m.queries.push(q);
        if let Some((payload, dnssec_ok)) = edns {
            let mut e = Edns::new();
            e.set_max_payload(payload);
            e.set_dnssec_ok(dnssec_ok);
            m.set_edns(e);
        }
        m
    }
    #[test]
    fn parse_query_matches_hickory() {
        let mut cases = vec![
            query_msg("example.com.", RecordType::A, None),
            query_msg(
                "a.b.c.deep-name.example.",
                RecordType::AAAA,
                Some((1232, true)),
            ),
            query_msg("EDNS-no-do.test.", RecordType::HTTPS, Some((4096, false))),
            query_msg(".", RecordType::NS, None), // root
        ];
        let mut cd = query_msg("cd.example.", RecordType::A, None);
        cd.metadata.recursion_desired = false;
        cd.metadata.checking_disabled = true;
        cases.push(cd);

        for m in &cases {
            let raw = m.to_vec().unwrap();
            let p = parse_query(&raw).expect("parse_query should succeed");
            let q = m.queries.first().unwrap();
            assert_eq!(p.id, m.metadata.id);
            assert_eq!(p.qname, q.name().to_ascii());
            assert_eq!(p.qtype, u16::from(q.query_type()));
            assert_eq!(p.qclass, u16::from(q.query_class()));
            assert_eq!(p.recursion_desired, m.metadata.recursion_desired);
            assert_eq!(p.checking_disabled, m.metadata.checking_disabled);
            assert_eq!(
                p.dnssec_ok,
                m.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
            );
            assert_eq!(p.edns_payload, m.edns.as_ref().map(|e| e.max_payload()));
        }
    }
    #[test]
    fn parse_query_preserves_case() {
        let mut m = Message::new(0x1234, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        let mut q = Query::query(
            Name::from_ascii("MixedCase.Example.COM.").unwrap(),
            RecordType::A,
        );
        q.set_query_class(DNSClass::IN);
        m.queries.push(q);
        let raw = m.to_vec().unwrap();
        let p = parse_query(&raw).unwrap();
        assert_eq!(p.qname, "MixedCase.Example.COM.");
        assert_eq!(p.qname, m.queries[0].name().to_ascii());
    }
    #[test]
    fn parse_query_rejects_malformed() {
        assert!(parse_query(&[]).is_none());
        assert!(parse_query(&[0u8; 8]).is_none());
        let mut buf = vec![0u8; 12];
        assert!(parse_query(&buf).is_none());
        buf[5] = 1;
        assert!(parse_query(&buf).is_none());
    }
    fn raw_query(name: Name) -> Option<Vec<u8>> {
        let mut m = Message::new(0x1234, MessageType::Query, OpCode::Query);
        let mut q = Query::query(name, RecordType::A);
        q.set_query_class(DNSClass::IN);
        m.queries.push(q);
        m.to_vec().ok()
    }

    fn raw_with_labels(labels: &[&[u8]]) -> Option<Vec<u8>> {
        let name = Name::from_labels(labels.iter().map(|l| l.to_vec()).collect::<Vec<_>>()).ok()?;
        raw_query(name)
    }
    #[test]
    fn parse_query_qname_never_diverges_from_to_ascii() {
        for b in 0u16..=255 {
            let b = b as u8;
            let cases: [Vec<Vec<u8>>; 3] = [
                vec![vec![b'a', b, b'z'], b"test".to_vec()],
                vec![vec![b, b'z'], b"test".to_vec()],
                vec![vec![b'z', b], b"test".to_vec()],
            ];
            for labels in cases {
                let Ok(name) = Name::from_labels(labels) else {
                    continue;
                };
                let Some(raw) = raw_query(name) else { continue };
                let Ok(hp) = Message::from_vec(&raw) else {
                    continue;
                };
                let expected = hp.queries[0].name().to_ascii();
                if let Some(p) = parse_query(&raw) {
                    assert_eq!(p.qname, expected, "byte {b:#04x} diverged from to_ascii");
                }
            }
        }
    }
    #[test]
    fn parse_query_bails_on_escaped_labels() {
        let raw = raw_with_labels(&[b"a!b", b"example"]).unwrap();
        assert!(parse_query(&raw).is_none());
        assert!(Message::from_vec(&raw).unwrap().queries[0]
            .name()
            .to_ascii()
            .contains('\\'));
        assert!(parse_query(&raw_with_labels(&[b"-lead", b"example"]).unwrap()).is_none());
        assert!(parse_query(&raw_with_labels(&[b"a*b", b"example"]).unwrap()).is_none());
        assert!(parse_query(&raw_with_labels(&[b"*", b"example"]).unwrap()).is_some());
        assert!(parse_query(&raw_with_labels(&[b"a_b-c", b"example"]).unwrap()).is_some());
    }
    #[test]
    fn parse_query_bails_on_oversized_name() {
        let mut buf = vec![0u8; 12];
        buf[5] = 1; // QDCOUNT = 1
        for _ in 0..5 {
            buf.push(63);
            buf.extend(std::iter::repeat_n(b'a', 63));
        }
        buf.push(0); // root
        buf.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        assert!(parse_query(&buf).is_none());
        assert!(Message::from_vec(&buf).is_err(), "hickory also rejects it");
    }

    fn header(an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut h = vec![0u8; 12];
        h[5] = 1; // QDCOUNT = 1
        h[6..8].copy_from_slice(&an.to_be_bytes());
        h[8..10].copy_from_slice(&ns.to_be_bytes());
        h[10..12].copy_from_slice(&ar.to_be_bytes());
        h
    }

    fn question_wire() -> Vec<u8> {
        let mut q = vec![1, b'a', 4];
        q.extend_from_slice(b"test");
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        q
    }

    fn opt_record(payload: u16, dnssec_ok: bool) -> Vec<u8> {
        let mut r = vec![0u8]; // root owner name
        r.extend_from_slice(&TYPE_OPT.to_be_bytes());
        r.extend_from_slice(&payload.to_be_bytes()); // CLASS = UDP payload size
        r.extend_from_slice(&[0, 0, if dnssec_ok { 0x80 } else { 0 }, 0]);
        r.extend_from_slice(&0u16.to_be_bytes()); // RDLEN = 0
        r
    }

    #[test]
    fn parse_query_edns_structural() {
        let mut ok = header(0, 0, 1);
        ok.extend(question_wire());
        ok.extend(opt_record(1232, true));
        let p = parse_query(&ok).expect("single additional OPT is valid");
        assert_eq!(p.edns_payload, Some(1232));
        assert!(p.dnssec_ok);
        assert!(Message::from_vec(&ok).is_ok());
        let mut dup = header(0, 0, 2);
        dup.extend(question_wire());
        dup.extend(opt_record(1232, false));
        dup.extend(opt_record(1232, false));
        assert!(parse_query(&dup).is_none());
        assert!(Message::from_vec(&dup).is_err());
        let mut misplaced = header(1, 0, 0);
        misplaced.extend(question_wire());
        misplaced.extend(opt_record(1232, false));
        assert!(parse_query(&misplaced).is_none());
    }
    #[test]
    fn parse_query_bails_on_multi_question() {
        let mut buf = header(0, 0, 0);
        buf[5] = 2; // QDCOUNT = 2
        buf.extend(question_wire());
        buf.extend(question_wire());
        assert!(parse_query(&buf).is_none());
    }
}
