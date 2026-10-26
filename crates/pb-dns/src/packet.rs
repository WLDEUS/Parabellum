//! Minimal DNS packet building / parsing (RFC 1035) for the dnscrypt-proxy health check:
//! one `A` query over UDP, response validated (id, QR bit, opcode, question echo) and classified by RCODE.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

/// Record type `A`.
pub const QTYPE_A: u16 = 1;
/// Class `IN`.
pub const QCLASS_IN: u16 = 1;
/// Name used by the health check.
pub const PROBE_NAME: &str = "example.com";

/// Packet errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("invalid query name")]
    BadName,
    #[error("truncated packet")]
    Truncated,
    #[error("unexpected id")]
    WrongId,
    #[error("not a response")]
    NotResponse,
    #[error("malformed packet")]
    Malformed,
}

/// Parsed response header facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseInfo {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    pub answers: u16,
}

impl ResponseInfo {
    /// NOERROR or NXDOMAIN: the resolver works (upstream reachable).
    pub fn is_healthy(&self) -> bool {
        self.rcode == 0 || self.rcode == 3
    }
}

/// Encode a domain name as DNS labels.
pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), PacketError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err(PacketError::BadName);
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(PacketError::BadName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Build a standard recursive query (RD=1) with one question.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, PacketError> {
    let mut p = Vec::with_capacity(32 + name.len());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
    encode_name(name, &mut p)?;
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(p)
}

fn u16_at(b: &[u8], i: usize) -> Result<u16, PacketError> {
    let s = b.get(i..i + 2).ok_or(PacketError::Truncated)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

/// Skip a (possibly compressed) name starting at `i`; returns the offset right after it.
fn skip_name(b: &[u8], mut i: usize) -> Result<usize, PacketError> {
    for _ in 0..128 {
        let len = *b.get(i).ok_or(PacketError::Truncated)?;
        match len {
            0 => return Ok(i + 1),
            l if l & 0xC0 == 0xC0 => {
                b.get(i + 1).ok_or(PacketError::Truncated)?;
                return Ok(i + 2);
            }
            l if l & 0xC0 == 0 => {
                i += 1 + l as usize;
                if i > b.len() {
                    return Err(PacketError::Truncated);
                }
            }
            _ => return Err(PacketError::Malformed),
        }
    }
    Err(PacketError::Malformed)
}

/// Validate a response to the query built by [`build_query`] with `expected_id` / `qtype`.
pub fn parse_response(b: &[u8], expected_id: u16, qtype: u16) -> Result<ResponseInfo, PacketError> {
    if b.len() < 12 {
        return Err(PacketError::Truncated);
    }
    let id = u16_at(b, 0)?;
    if id != expected_id {
        return Err(PacketError::WrongId);
    }
    let flags = u16_at(b, 2)?;
    if flags & 0x8000 == 0 {
        return Err(PacketError::NotResponse);
    }
    if (flags >> 11) & 0xF != 0 {
        return Err(PacketError::Malformed); // opcode must be QUERY
    }
    let qd = u16_at(b, 4)?;
    let an = u16_at(b, 6)?;
    if qd != 1 {
        return Err(PacketError::Malformed);
    }
    let after = skip_name(b, 12)?;
    if u16_at(b, after)? != qtype || u16_at(b, after + 2)? != QCLASS_IN {
        return Err(PacketError::Malformed);
    }
    Ok(ResponseInfo {
        id,
        rcode: (flags & 0x000F) as u8,
        truncated: flags & 0x0200 != 0,
        answers: an,
    })
}

fn next_id() -> u16 {
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16)
        ^ ((nanos >> 16) as u16)
        ^ COUNTER.fetch_add(0x9E37, Ordering::Relaxed)
        ^ (std::process::id() as u16)
}

/// Send one `A` query for [`PROBE_NAME`] to `server` over UDP and wait up to `timeout`.
/// `Ok(info)` for any well-formed response (check [`ResponseInfo::is_healthy`]).
pub async fn probe(server: SocketAddr, timeout: Duration) -> Result<ResponseInfo, String> {
    let bind: SocketAddr = if server.is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    }
    .parse()
    .map_err(|e| format!("{e}"))?;
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    sock.connect(server).await.map_err(|e| e.to_string())?;
    let id = next_id();
    let q = build_query(id, PROBE_NAME, QTYPE_A).map_err(|e| e.to_string())?;
    let fut = async {
        sock.send(&q).await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 1500];
        loop {
            let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
            match parse_response(buf.get(..n).unwrap_or(&[]), id, QTYPE_A) {
                Ok(info) => return Ok(info),
                Err(PacketError::WrongId) => continue, // stale answer, keep waiting
                Err(e) => return Err(e.to_string()),
            }
        }
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| "délai dépassé".to_string())?
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Turn a query into a response with `rcode` and one A answer (compressed name pointer).
    pub(crate) fn make_response(query: &[u8], rcode: u8) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] = 0x81; // QR + RD
        r[3] = 0x80 | rcode; // RA + rcode
        r[6] = 0;
        r[7] = 1; // ANCOUNT
        r.extend_from_slice(&[0xC0, 12]); // pointer to question name
        r.extend_from_slice(&QTYPE_A.to_be_bytes());
        r.extend_from_slice(&QCLASS_IN.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&[93, 184, 215, 14]);
        r
    }

    #[test]
    fn round_trip() {
        let q = build_query(0x1234, "example.com", QTYPE_A).unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&q[12..25], b"\x07example\x03com\x00");
        let r = make_response(&q, 0);
        let info = parse_response(&r, 0x1234, QTYPE_A).unwrap();
        assert!(info.is_healthy());
        assert_eq!(info.answers, 1);
        assert_eq!(
            parse_response(&r, 0x9999, QTYPE_A),
            Err(PacketError::WrongId)
        );
        assert_eq!(
            parse_response(&q, 0x1234, QTYPE_A),
            Err(PacketError::NotResponse)
        );
        assert_eq!(
            parse_response(&r[..11], 0x1234, QTYPE_A),
            Err(PacketError::Truncated)
        );
        let servfail = make_response(&q, 2);
        assert!(!parse_response(&servfail, 0x1234, QTYPE_A)
            .unwrap()
            .is_healthy());
        let nx = make_response(&q, 3);
        assert!(parse_response(&nx, 0x1234, QTYPE_A).unwrap().is_healthy());
        assert_eq!(build_query(1, "", QTYPE_A), Err(PacketError::BadName));
        assert_eq!(
            build_query(1, &format!("{}.com", "a".repeat(64)), QTYPE_A),
            Err(PacketError::BadName)
        );
        // Garbage must not panic.
        for len in 0..r.len() {
            let _ = parse_response(&r[..len], 0x1234, QTYPE_A);
        }
        let mut loopy = r.clone();
        loopy[12] = 0x80; // reserved label type
        assert!(parse_response(&loopy, 0x1234, QTYPE_A).is_err());
    }

    #[tokio::test]
    async fn probes_a_udp_server() {
        let srv = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = srv.recv_from(&mut buf).await {
                let resp = make_response(&buf[..n], 0);
                let _ = srv.send_to(&resp, peer).await;
            }
        });
        let info = probe(addr, Duration::from_secs(2)).await.unwrap();
        assert!(info.is_healthy());
        // Nobody listening: timeout or ICMP refusal, never a hang.
        let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        assert!(probe(dead_addr, Duration::from_millis(300)).await.is_err());
    }
}
