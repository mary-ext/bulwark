//! Minimal DNS wire-format helpers for the wire-byte cache fast path.
//!
//! A cached response is stored as the bytes we already encoded once, plus the
//! byte offsets of every resource-record TTL field. Serving a hit is then a flat
//! `Vec<u8>` clone followed by patching the transaction id and rewriting each TTL
//! in place — skipping both the per-hit `Message` clone and the `Message::to_vec`
//! re-encode the server would otherwise pay (~235 ns/hit, measured).
//!
//! The scanner walks the wire exactly as a resolver would, but only far enough
//! to locate TTL fields:
//!
//! ```text
//! header(12) | question* | RR*
//! RR = NAME | TYPE(2) | CLASS(2) | TTL(4) | RDLENGTH(2) | RDATA(rdlength)
//!                     ^ ttl offset = (end of NAME) + 4
//! ```
//!
//! Names may use compression pointers, which only affects how the *end* of a
//! NAME is found — the fixed fields after it are unaffected. OPT pseudo-records
//! (type 41) are skipped: their "TTL" field is the EDNS extended rcode / version
//! / flags, not a real TTL, and must not be rewritten.

/// The DNS record type for OPT (EDNS) pseudo-records, whose TTL field is not a
/// TTL and must never be patched.
const TYPE_OPT: u16 = 41;

/// Advance past a DNS name starting at `pos`, returning the offset just after
/// it. Returns `None` on a malformed/out-of-bounds name. We only need the name's
/// *length*, so a compression pointer (which always terminates a name) is two
/// bytes and we do not follow it.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let b = *buf.get(pos)?;
        match b & 0xC0 {
            // End of name.
            0x00 if b == 0 => return Some(pos + 1),
            // Label: 1 length byte + `b` content bytes.
            0x00 => pos = pos.checked_add(1 + b as usize)?,
            // Compression pointer: 2 bytes, terminates the name.
            0xC0 => return pos.checked_add(2),
            // 0x40 / 0x80 are reserved — treat as malformed.
            _ => return None,
        }
    }
}

/// Scan an encoded DNS message and return the byte offset of every resource
/// record's TTL field (answers + authorities + additionals), excluding OPT
/// pseudo-records. Returns `None` if the message is malformed or its structure
/// can't be walked safely, in which case the caller should fall back to the
/// `Message`-based cache path.
pub fn scan_ttl_offsets(buf: &[u8]) -> Option<Vec<u32>> {
    if buf.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut pos = 12;
    // Questions: NAME + QTYPE(2) + QCLASS(2), no TTL.
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
        // Need TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 fixed bytes.
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

/// Patch a cloned response in place: overwrite the transaction id (bytes 0..2)
/// and rewrite every TTL at the precomputed offsets to `ttl`. Offsets out of
/// bounds are skipped defensively (they never are for offsets from
/// [`scan_ttl_offsets`] on the same buffer).
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
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
            // Adds an OPT record to the additional section on the wire.
            m.edns = Some(Default::default());
        }
        m
    }

    /// After scan + patch, every answer TTL equals the patched value and the
    /// message still decodes to the same records.
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

    /// The OPT pseudo-record's "TTL" (EDNS fields) must be left untouched.
    #[test]
    fn does_not_patch_opt_record() {
        let msg = response_with(&[(300, RData::A(A::new(1, 2, 3, 4)))], true);
        let mut wire = msg.to_vec().unwrap();
        // Only the single real answer's TTL is an offset; the OPT record is not.
        let offsets = scan_ttl_offsets(&wire).expect("scan");
        assert_eq!(offsets.len(), 1, "OPT must be excluded");

        patch(&mut wire, 0x1111, 10, &offsets);
        let back = Message::from_vec(&wire).unwrap();
        assert_eq!(back.answers[0].ttl, 10);
        // EDNS still parses (its version/flags weren't clobbered into a TTL).
        assert!(back.edns.is_some());
    }

    /// NXDOMAIN with an SOA in the authority section: the SOA TTL is patched.
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

    /// A response with no records scans to an empty offset list (id still patches).
    #[test]
    fn empty_answers_ok() {
        let msg = response_with(&[], false);
        let mut wire = msg.to_vec().unwrap();
        let offsets = scan_ttl_offsets(&wire).expect("scan");
        assert!(offsets.is_empty());
        patch(&mut wire, 0x2222, 1, &offsets);
        assert_eq!(Message::from_vec(&wire).unwrap().metadata.id, 0x2222);
    }

    /// Malformed / truncated input never panics and returns None.
    #[test]
    fn malformed_returns_none() {
        assert!(scan_ttl_offsets(&[]).is_none());
        assert!(scan_ttl_offsets(&[0u8; 5]).is_none());
        // Header claims 1 answer but the body is missing.
        let mut buf = vec![0u8; 12];
        buf[6] = 0; // ANCOUNT hi
        buf[7] = 1; // ANCOUNT lo
        assert!(scan_ttl_offsets(&buf).is_none());
    }
}
