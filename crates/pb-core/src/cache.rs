//! Small time-bounded cache for request handlers whose answer is expensive to compute (spawns a process,
//! parses big files, waits on a lock held by a slow background task) but changes rarely.
//!
//! - A value is served while younger than the TTL; after that the next caller recomputes it.
//! - Writers [`TtlCell::invalidate`] the cell on events that change the answer (snapshot created, DNS
//!   toggled…), so a cached answer is never wrong for longer than one TTL even if an event is missed.
//! - A computation started before an invalidation never stores its (possibly stale) result: callers take
//!   a [`TtlCell::generation`] before computing and [`TtlCell::put`] it back with the value.
//!
//! The lock is a std mutex held only to copy the slot: never across an `.await`.

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Slot<V> {
    value: Option<(Instant, V)>,
    generation: u64,
}

/// One cached value with a time-to-live and an invalidation generation.
#[derive(Debug)]
pub struct TtlCell<V> {
    ttl: Duration,
    slot: Mutex<Slot<V>>,
}

impl<V: Clone> TtlCell<V> {
    /// Empty cell (usable in a `static`).
    pub const fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: Mutex::new(Slot {
                value: None,
                generation: 0,
            }),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Slot<V>> {
        self.slot.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The cached value if it is younger than the TTL.
    pub fn get(&self) -> Option<V> {
        self.get_at(Instant::now())
    }

    /// [`Self::get`] at an explicit time (tests).
    pub fn get_at(&self, now: Instant) -> Option<V> {
        let g = self.lock();
        match &g.value {
            Some((at, v)) if now.saturating_duration_since(*at) < self.ttl => Some(v.clone()),
            _ => None,
        }
    }

    /// Current generation: take it before computing a value, pass it to [`Self::put`].
    pub fn generation(&self) -> u64 {
        self.lock().generation
    }

    /// Store `value` computed since `generation` was read. Ignored (returns false) when the cell was
    /// invalidated in between: the value may predate the change that caused the invalidation.
    pub fn put(&self, generation: u64, value: V) -> bool {
        self.put_at(generation, value, Instant::now())
    }

    /// [`Self::put`] at an explicit time (tests).
    pub fn put_at(&self, generation: u64, value: V, now: Instant) -> bool {
        let mut g = self.lock();
        if g.generation != generation {
            return false;
        }
        g.value = Some((now, value));
        true
    }

    /// Drop the cached value; in-flight computations will not store theirs.
    pub fn invalidate(&self) {
        let mut g = self.lock();
        g.value = None;
        g.generation = g.generation.wrapping_add(1);
    }

    /// Cached value, or `compute()` (stored for the next callers unless invalidated meanwhile).
    pub async fn get_or_refresh<F, Fut>(&self, compute: F) -> V
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
    {
        if let Some(v) = self.get() {
            return v;
        }
        let generation = self.generation();
        let v = compute().await;
        self.put(generation, v.clone());
        v
    }

    /// Like [`Self::get_or_refresh`] for fallible computations: only `Ok` values are cached.
    pub async fn get_or_try_refresh<E, F, Fut>(&self, compute: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        if let Some(v) = self.get() {
            return Ok(v);
        }
        let generation = self.generation();
        let v = compute().await?;
        self.put(generation, v.clone());
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal executor for the async helpers (pb-core has no async runtime dependency).
    fn block_on<F: Future>(f: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = pin!(f);
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn serves_until_ttl_then_expires() {
        let c = TtlCell::new(Duration::from_secs(10));
        let t0 = Instant::now();
        assert_eq!(c.get_at(t0), None);
        assert!(c.put_at(c.generation(), 7, t0));
        assert_eq!(c.get_at(t0), Some(7));
        assert_eq!(c.get_at(t0 + Duration::from_secs(9)), Some(7));
        assert_eq!(c.get_at(t0 + Duration::from_secs(10)), None);
        // A clock going backwards (or `now` before the store) still counts as fresh.
        assert_eq!(c.get_at(t0 - Duration::from_millis(1)), Some(7));
    }

    #[test]
    fn invalidation_drops_value_and_rejects_stale_puts() {
        let c = TtlCell::new(Duration::from_secs(60));
        let g = c.generation();
        assert!(c.put(g, "old"));
        let before = c.generation();
        c.invalidate();
        assert_eq!(c.get(), None);
        // A computation started before the invalidation must not repopulate the cell.
        assert!(!c.put(before, "stale"));
        assert_eq!(c.get(), None);
        assert!(c.put(c.generation(), "new"));
        assert_eq!(c.get(), Some("new"));
    }

    #[test]
    fn get_or_refresh_computes_once_while_fresh() {
        let c = TtlCell::new(Duration::from_secs(60));
        let mut calls = 0;
        let a = block_on(c.get_or_refresh(|| {
            calls += 1;
            async { 1 }
        }));
        let b = block_on(c.get_or_refresh(|| {
            calls += 1;
            async { 2 }
        }));
        assert_eq!((a, b, calls), (1, 1, 1));
        c.invalidate();
        assert_eq!(block_on(c.get_or_refresh(|| async { 3 })), 3);
    }

    #[test]
    fn errors_are_not_cached() {
        let c: TtlCell<u32> = TtlCell::new(Duration::from_secs(60));
        let r: Result<u32, &str> = block_on(c.get_or_try_refresh(|| async { Err("boom") }));
        assert_eq!(r, Err("boom"));
        assert_eq!(c.get(), None);
        let r: Result<u32, &str> = block_on(c.get_or_try_refresh(|| async { Ok(5) }));
        assert_eq!(r, Ok(5));
        let r: Result<u32, &str> = block_on(c.get_or_try_refresh(|| async { Ok(6) }));
        assert_eq!(r, Ok(5), "served from cache");
    }

    #[test]
    fn zero_ttl_never_serves() {
        let c = TtlCell::new(Duration::ZERO);
        assert!(c.put(c.generation(), 1));
        assert_eq!(c.get(), None);
    }

    #[test]
    fn usable_in_a_static() {
        static CELL: TtlCell<u8> = TtlCell::new(Duration::from_secs(1));
        CELL.invalidate();
        assert!(CELL.put(CELL.generation(), 9));
        assert_eq!(CELL.get(), Some(9));
    }
}
