//! Event bus: [`DaemonEvent`]s fanned out to subscribed IPC connections.
//!
//! A `tokio::sync::broadcast` channel: publishing never blocks; a subscriber that falls more than
//! [`BUS_CAPACITY`] events behind gets `Lagged` and its connection is dropped by the IPC server.

use pb_core::ipc::DaemonEvent;
use tokio::sync::broadcast;

/// Events buffered per subscriber before it is considered too slow.
pub const BUS_CAPACITY: usize = 1024;

/// Cloneable publisher.
#[derive(Clone, Debug)]
pub struct EventBus {
    tx: broadcast::Sender<DaemonEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Self { tx }
    }

    /// Publish to every current subscriber (no-op without subscribers).
    pub fn publish(&self, ev: DaemonEvent) {
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DaemonEvent> {
        self.tx.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_core::model::*;

    fn ev(n: i64) -> DaemonEvent {
        DaemonEvent::UpdateFinished(UpdateResult {
            target: UpdateTarget::Db,
            ok: true,
            started_at: n,
            finished_at: n,
            messages: vec![],
            new_db_version: None,
        })
    }

    #[tokio::test]
    async fn fan_out_and_lag() {
        let bus = EventBus::new();
        bus.publish(ev(0)); // nobody listening: dropped
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
        bus.publish(ev(1));
        assert_eq!(a.recv().await.unwrap(), ev(1));
        assert_eq!(b.recv().await.unwrap(), ev(1));
        for i in 0..(BUS_CAPACITY as i64 + 10) {
            bus.publish(ev(i));
        }
        assert!(matches!(
            a.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
    }
}
