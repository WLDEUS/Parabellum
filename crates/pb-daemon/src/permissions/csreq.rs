//! Compiled code requirements (the `csreq` column of TCC's `access` table): does the grant require code
//! signed by Apple itself (`anchor apple`)?
//!
//! Blob layout (`Security/requirement.h`, `reqreader.cpp`): big-endian `u32` magic `0xfade0c00`, total
//! length, kind (1 = expression), then the expression in prefix form. Data values are a `u32` length plus
//! bytes padded to 4. Only a top-level conjunct `anchor apple` (`opAppleAnchor`) counts: `anchor apple
//! generic` (`opAppleGenericAnchor`) also matches every Developer ID and App Store app. Anything not
//! understood answers `None` (unknown), never "Apple".

const MAGIC_REQUIREMENT: u32 = 0xfade_0c00;
const EXPR_FORM: u32 = 1;
/// Op flags (`opFlagMask`) carried in the high byte.
const OP_FLAG_MASK: u32 = 0xff00_0000;
const MAX_DEPTH: u32 = 64;
const MAX_BLOB: usize = 64 * 1024;

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let s = self.b.get(self.pos..self.pos.checked_add(4)?)?;
        self.pos += 4;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        (end <= self.b.len()).then(|| self.pos = end)
    }

    /// Length-prefixed data, padded to 4 bytes.
    fn data(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        let start = self.pos;
        self.skip(len)?;
        let out = &self.b[start..start + len];
        self.skip((4 - len % 4) % 4)?;
        Some(out)
    }

    /// A match suffix (`matchOp` + its operand).
    fn match_expr(&mut self) -> Option<()> {
        match self.u32()? {
            // matchExists, matchAbsent
            0 | 14 => Some(()),
            // matchEqual … matchGreaterEqual: a value
            1..=8 => self.data().map(|_| ()),
            // matchOn … matchOnOrAfter: an absolute time (8 bytes)
            9..=13 => self.skip(8),
            _ => None,
        }
    }

    /// Parses one expression; `Some(true)` when it can only be satisfied by code signed by Apple itself.
    fn expr(&mut self, depth: u32) -> Option<bool> {
        if depth > MAX_DEPTH {
            return None;
        }
        let op = self.u32()? & !OP_FLAG_MASK;
        Some(match op {
            0 | 1 => false, // opFalse, opTrue
            2 | 8 | 18 | 19 => {
                // opIdent, opCDHash, opNamedAnchor, opNamedCode
                self.data()?;
                false
            }
            3 => true, // opAppleAnchor
            4 => {
                // opAnchorHash: slot, hash
                self.u32()?;
                self.data()?;
                false
            }
            5 => {
                // opInfoKeyValue (legacy): key, value
                self.data()?;
                self.data()?;
                false
            }
            6 => {
                // opAnd
                let l = self.expr(depth + 1)?;
                let r = self.expr(depth + 1)?;
                l || r
            }
            7 => {
                // opOr: Apple only if both branches are
                let l = self.expr(depth + 1)?;
                let r = self.expr(depth + 1)?;
                l && r
            }
            9 => {
                // opNot
                self.expr(depth + 1)?;
                false
            }
            10 | 16 => {
                // opInfoKeyField, opEntitlementField: key, match
                self.data()?;
                self.match_expr()?;
                false
            }
            11 | 14 | 17 | 22 => {
                // opCertField, opCertGeneric, opCertPolicy, opCertFieldDate: slot, key/oid, match
                self.u32()?;
                self.data()?;
                self.match_expr()?;
                false
            }
            12 | 20 => {
                // opTrustedCert (slot), opPlatform (platform id)
                self.u32()?;
                false
            }
            // opTrustedCerts, opAppleGenericAnchor, opNotarized, opLegacyDevID
            13 | 15 | 21 | 23 => false,
            _ => return None,
        })
    }
}

/// `Some(true)`: the requirement demands code signed by Apple itself; `Some(false)`: parsed, it does not;
/// `None`: missing, not a single expression-form requirement, or not understood.
pub fn requires_apple_anchor(blob: &[u8]) -> Option<bool> {
    if blob.len() > MAX_BLOB {
        return None;
    }
    let mut r = Reader { b: blob, pos: 0 };
    if r.u32()? != MAGIC_REQUIREMENT {
        return None;
    }
    let len = r.u32()? as usize;
    if len < 12 || len > blob.len() {
        return None;
    }
    if r.u32()? != EXPR_FORM {
        return None;
    }
    let mut body = Reader {
        b: &blob[..len],
        pos: 12,
    };
    body.expr(0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Test builder for compiled requirements.
    #[derive(Default)]
    pub struct Req(Vec<u8>);

    impl Req {
        pub fn op(mut self, op: u32) -> Self {
            self.0.extend_from_slice(&op.to_be_bytes());
            self
        }
        pub fn data(mut self, d: &[u8]) -> Self {
            self.0.extend_from_slice(&(d.len() as u32).to_be_bytes());
            self.0.extend_from_slice(d);
            self.0.resize(self.0.len().div_ceil(4) * 4, 0);
            self
        }
        pub fn build(self) -> Vec<u8> {
            let mut v = MAGIC_REQUIREMENT.to_be_bytes().to_vec();
            v.extend_from_slice(&((self.0.len() + 12) as u32).to_be_bytes());
            v.extend_from_slice(&EXPR_FORM.to_be_bytes());
            v.extend(self.0);
            v
        }
    }

    /// `identifier "<id>" and anchor apple`.
    pub fn apple(id: &str) -> Vec<u8> {
        Req::default().op(6).op(2).data(id.as_bytes()).op(3).build()
    }

    /// `identifier "<id>" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6]
    /// exists and certificate leaf[subject.OU] = "<team>"` (Developer ID).
    pub fn developer_id(id: &str, team: &str) -> Vec<u8> {
        Req::default()
            .op(6)
            .op(2)
            .data(id.as_bytes())
            .op(6)
            .op(15)
            .op(6)
            .op(14)
            .op(1)
            .data(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x06])
            .op(0)
            .op(11)
            .op(0)
            .data(b"subject.OU")
            .op(1)
            .data(team.as_bytes())
            .build()
    }

    #[test]
    fn terminal_requirement_from_a_real_tcc_db() {
        // `identifier "com.apple.Terminal" and anchor apple`, as stored by tccd.
        let hex = "fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003";
        let blob = hex::decode(hex).unwrap();
        assert_eq!(blob, apple("com.apple.Terminal"));
        assert_eq!(requires_apple_anchor(&blob), Some(true));
    }

    #[test]
    fn developer_id_and_tricks_are_not_apple() {
        assert_eq!(
            requires_apple_anchor(&developer_id("com.apple.fake", "ABCDE12345")),
            Some(false)
        );
        // anchor apple OR identifier: satisfiable without Apple.
        let or = Req::default()
            .op(7)
            .op(3)
            .op(2)
            .data(b"com.apple.x")
            .build();
        assert_eq!(requires_apple_anchor(&or), Some(false));
        // NOT anchor apple.
        let not = Req::default().op(9).op(3).build();
        assert_eq!(requires_apple_anchor(&not), Some(false));
        // Flags in the high byte are ignored.
        let flagged = Req::default().op(0x4000_0003).build();
        assert_eq!(requires_apple_anchor(&flagged), Some(true));
    }

    #[test]
    fn malformed_blobs_are_unknown() {
        let good = apple("com.apple.Terminal");
        for n in 0..good.len() {
            let mut cut = good[..n].to_vec();
            if n >= 8 {
                // keep the declared length consistent with the truncated blob
                cut[4..8].copy_from_slice(&(n as u32).to_be_bytes());
            }
            assert_eq!(requires_apple_anchor(&cut), None, "truncated at {n}");
        }
        let mut bad_magic = good.clone();
        bad_magic[3] = 1;
        assert_eq!(requires_apple_anchor(&bad_magic), None);
        assert_eq!(requires_apple_anchor(&Req::default().op(99).build()), None);
        // Deep nesting is bounded.
        let mut deep = Req::default();
        for _ in 0..200 {
            deep = deep.op(9);
        }
        assert_eq!(requires_apple_anchor(&deep.op(3).build()), None);
    }
}
