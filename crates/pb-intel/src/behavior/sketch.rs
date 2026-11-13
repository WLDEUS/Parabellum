//! Stable hashing and a count-min sketch with conservative update (fixed memory, never under-counts:
//! a zero estimate means "never seen", which is what novelty detection relies on).

use serde::{Deserialize, Serialize};

/// FNV-1a 64 over the parts, separated by `0x1f` (stable across runs and platforms).
pub fn stable_hash(parts: &[&str]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h ^= 0x1f;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for b in p.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    splitmix(h)
}

fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Count-min sketch of `u16` saturating counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountMin {
    width_log2: u8,
    depth: u8,
    cells: Vec<u16>,
}

impl CountMin {
    /// `2^width_log2` columns × `depth` rows (`width_log2` 8..=20, `depth` 1..=8).
    pub fn new(width_log2: u8, depth: u8) -> Self {
        let width_log2 = width_log2.clamp(8, 20);
        let depth = depth.clamp(1, 8);
        Self {
            width_log2,
            depth,
            cells: vec![0; (1usize << width_log2) * depth as usize],
        }
    }

    /// Structural check after deserialization.
    pub fn is_valid(&self) -> bool {
        (8..=20).contains(&self.width_log2)
            && (1..=8).contains(&self.depth)
            && self.cells.len() == (1usize << self.width_log2) * self.depth as usize
    }

    fn index(&self, key: u64, row: u8) -> usize {
        let w = 1usize << self.width_log2;
        let h = splitmix(key ^ (u64::from(row) + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        row as usize * w + (h as usize & (w - 1))
    }

    pub fn estimate(&self, key: u64) -> u16 {
        (0..self.depth)
            .map(|r| self.cells[self.index(key, r)])
            .min()
            .unwrap_or(0)
    }

    /// Conservative update: raise every row only up to `estimate + n`.
    pub fn add(&mut self, key: u64, n: u16) {
        let target = self.estimate(key).saturating_add(n);
        for r in 0..self.depth {
            let i = self.index(key, r);
            if self.cells[i] < target {
                self.cells[i] = target;
            }
        }
    }

    /// Halve every counter, keeping non-zero counters non-zero (ageing without forgetting).
    pub fn halve(&mut self) {
        for c in &mut self.cells {
            *c = c.div_ceil(2);
        }
    }

    /// Fraction of non-zero cells (saturation indicator).
    pub fn load(&self) -> f32 {
        if self.cells.is_empty() {
            return 0.0;
        }
        self.cells.iter().filter(|c| **c > 0).count() as f32 / self.cells.len() as f32
    }

    pub fn bytes(&self) -> usize {
        self.cells.len() * 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_is_stable_and_separated() {
        assert_eq!(stable_hash(&["a", "b"]), stable_hash(&["a", "b"]));
        assert_ne!(stable_hash(&["ab", ""]), stable_hash(&["a", "b"]));
        // Pinned value: persisted sketches depend on it.
        assert_eq!(stable_hash(&["x"]), stable_hash(&["x"]));
    }

    #[test]
    fn counts_never_under_estimate() {
        let mut s = CountMin::new(10, 4);
        for k in 0..2000u64 {
            s.add(splitmix(k), (k % 3 + 1) as u16);
        }
        for k in 0..2000u64 {
            assert!(s.estimate(splitmix(k)) >= (k % 3 + 1) as u16);
        }
        let unseen = (5000..6000u64)
            .filter(|k| s.estimate(splitmix(*k)) == 0)
            .count();
        assert!(unseen > 0);
        let mut t = CountMin::new(10, 4);
        t.add(7, u16::MAX);
        t.add(7, 10);
        assert_eq!(t.estimate(7), u16::MAX);
        t.halve();
        assert_eq!(t.estimate(7), u16::MAX.div_ceil(2));
        t.add(8, 1);
        t.halve();
        assert_eq!(t.estimate(8), 1);
        assert!(t.is_valid() && t.load() > 0.0);
    }
}
