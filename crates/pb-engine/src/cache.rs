//! Bounded approximate-LRU map (two generations: O(1) operations, at most `capacity` entries).
//! Lookups promote entries from the old generation; when the young generation reaches half the
//! capacity it becomes the old one and the previous old generation is dropped.

use std::collections::HashMap;
use std::hash::Hash;

pub(crate) struct TwoGenCache<K, V> {
    half: usize,
    young: HashMap<K, V>,
    old: HashMap<K, V>,
}

impl<K: Hash + Eq + Clone, V: Clone> TwoGenCache<K, V> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            half: (capacity / 2).max(1),
            young: HashMap::new(),
            old: HashMap::new(),
        }
    }

    pub(crate) fn get(&mut self, k: &K) -> Option<V> {
        if let Some(v) = self.young.get(k) {
            return Some(v.clone());
        }
        let v = self.old.remove(k)?;
        self.insert(k.clone(), v.clone());
        Some(v)
    }

    pub(crate) fn insert(&mut self, k: K, v: V) {
        if self.young.len() >= self.half && !self.young.contains_key(&k) {
            self.old = std::mem::take(&mut self.young);
        }
        self.old.remove(&k);
        self.young.insert(k, v);
    }

    pub(crate) fn clear(&mut self) {
        self.young.clear();
        self.old.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.young.len() + self.old.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_and_promotes() {
        let mut c = TwoGenCache::new(10);
        for i in 0..100 {
            c.insert(i, i * 2);
            assert!(c.len() <= 10);
        }
        assert_eq!(c.get(&99), Some(198));
        assert_eq!(c.get(&0), None);
        // 95..99 young (5 entries max), promote an old one
        c.insert(1000, 1);
        let present: Vec<i32> = (90..100).filter(|k| c.get(k).is_some()).collect();
        assert!(!present.is_empty());
        c.clear();
        assert_eq!(c.len(), 0);
    }
}
