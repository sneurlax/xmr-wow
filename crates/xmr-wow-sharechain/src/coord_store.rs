// xmr-wow-sharechain: coordination message store and broadcast registry

use std::collections::HashMap;
use parking_lot::RwLock;
use tokio::sync::broadcast;

/// Per-swap message log; stores raw bytes in insertion order.
pub struct CoordMessageStore {
    messages: RwLock<HashMap<[u8; 32], Vec<Vec<u8>>>>,
}

impl CoordMessageStore {
    pub fn new() -> Self {
        Self {
            messages: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the 0-based insertion index of the appended message.
    pub fn publish(&self, swap_id: [u8; 32], raw: Vec<u8>) -> usize {
        let mut guard = self.messages.write();
        let bucket = guard.entry(swap_id).or_insert_with(Vec::new);
        let idx = bucket.len();
        bucket.push(raw);
        idx
    }

    /// Returns messages from `after_index` (inclusive); empty if unknown or out of range.
    pub fn get_after(&self, swap_id: &[u8; 32], after_index: usize) -> Vec<Vec<u8>> {
        let guard = self.messages.read();
        match guard.get(swap_id) {
            None => Vec::new(),
            Some(v) => {
                if after_index >= v.len() {
                    Vec::new()
                } else {
                    v[after_index..].to_vec()
                }
            }
        }
    }

    pub fn get_all(&self, swap_id: &[u8; 32]) -> Vec<Vec<u8>> {
        self.get_after(swap_id, 0)
    }

    pub fn prune(&self, swap_id: &[u8; 32]) {
        let mut guard = self.messages.write();
        guard.remove(swap_id);
    }

    pub fn message_count(&self, swap_id: &[u8; 32]) -> usize {
        let guard = self.messages.read();
        guard.get(swap_id).map(|v| v.len()).unwrap_or(0)
    }
}

impl Default for CoordMessageStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-swap broadcast channels, created lazily; capacity 64.
pub struct BroadcastRegistry {
    senders: RwLock<HashMap<[u8; 32], broadcast::Sender<Vec<u8>>>>,
}

const BROADCAST_CAPACITY: usize = 64;

impl BroadcastRegistry {
    pub fn new() -> Self {
        Self {
            senders: RwLock::new(HashMap::new()),
        }
    }

    pub fn send(&self, swap_id: [u8; 32], raw: Vec<u8>) {
        // fast path: read lock
        {
            let guard = self.senders.read();
            if let Some(tx) = guard.get(&swap_id) {
                let _ = tx.send(raw);
                return;
            }
        }
        // slow path: write lock
        let mut guard = self.senders.write();
        let tx = guard
            .entry(swap_id)
            .or_insert_with(|| broadcast::channel(BROADCAST_CAPACITY).0);
        let _ = tx.send(raw);
    }

    pub fn subscribe(&self, swap_id: [u8; 32]) -> broadcast::Receiver<Vec<u8>> {
        // fast path: read lock
        {
            let guard = self.senders.read();
            if let Some(tx) = guard.get(&swap_id) {
                return tx.subscribe();
            }
        }
        // slow path: write lock
        let mut guard = self.senders.write();
        let tx = guard
            .entry(swap_id)
            .or_insert_with(|| broadcast::channel(BROADCAST_CAPACITY).0);
        tx.subscribe()
    }

    pub fn remove(&self, swap_id: &[u8; 32]) {
        let mut guard = self.senders.write();
        guard.remove(swap_id);
    }
}

impl Default for BroadcastRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn swap_id(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn publish_returns_insertion_index() {
        let store = CoordMessageStore::new();
        let id = swap_id(1);
        assert_eq!(store.publish(id, b"msg0".to_vec()), 0);
        assert_eq!(store.publish(id, b"msg1".to_vec()), 1);
        assert_eq!(store.publish(id, b"msg2".to_vec()), 2);
    }

    #[test]
    fn get_after_zero_returns_all() {
        let store = CoordMessageStore::new();
        let id = swap_id(2);
        store.publish(id, b"a".to_vec());
        store.publish(id, b"b".to_vec());
        store.publish(id, b"c".to_vec());
        let msgs = store.get_after(&id, 0);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0], b"a");
        assert_eq!(msgs[1], b"b");
        assert_eq!(msgs[2], b"c");
    }

    #[test]
    fn get_after_cursor_returns_tail() {
        let store = CoordMessageStore::new();
        let id = swap_id(3);
        store.publish(id, b"x".to_vec());
        store.publish(id, b"y".to_vec());
        store.publish(id, b"z".to_vec());
        let msgs = store.get_after(&id, 2);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0], b"z");
    }

    #[test]
    fn get_all_equals_get_after_zero() {
        let store = CoordMessageStore::new();
        let id = swap_id(4);
        store.publish(id, b"one".to_vec());
        store.publish(id, b"two".to_vec());
        assert_eq!(store.get_all(&id), store.get_after(&id, 0));
    }

    #[test]
    fn get_after_unknown_swap_returns_empty() {
        let store = CoordMessageStore::new();
        let unknown = swap_id(99);
        assert!(store.get_after(&unknown, 0).is_empty());
    }

    #[test]
    fn get_after_beyond_end_returns_empty() {
        let store = CoordMessageStore::new();
        let id = swap_id(5);
        store.publish(id, b"only".to_vec());
        assert!(store.get_after(&id, 1).is_empty());
        assert!(store.get_after(&id, 100).is_empty());
    }

    #[test]
    fn prune_removes_all_messages() {
        let store = CoordMessageStore::new();
        let id = swap_id(6);
        store.publish(id, b"keep".to_vec());
        assert_eq!(store.message_count(&id), 1);
        store.prune(&id);
        assert_eq!(store.message_count(&id), 0);
        assert!(store.get_all(&id).is_empty());
    }

    #[test]
    fn message_count_returns_correct_count() {
        let store = CoordMessageStore::new();
        let id = swap_id(7);
        assert_eq!(store.message_count(&id), 0);
        store.publish(id, b"a".to_vec());
        assert_eq!(store.message_count(&id), 1);
        store.publish(id, b"b".to_vec());
        assert_eq!(store.message_count(&id), 2);
    }

    #[test]
    fn multiple_swap_ids_are_isolated() {
        let store = CoordMessageStore::new();
        let id1 = swap_id(10);
        let id2 = swap_id(11);
        store.publish(id1, b"for-1".to_vec());
        store.publish(id2, b"for-2".to_vec());
        assert_eq!(store.get_all(&id1), vec![b"for-1".to_vec()]);
        assert_eq!(store.get_all(&id2), vec![b"for-2".to_vec()]);
    }

    #[tokio::test]
    async fn broadcast_send_creates_channel_lazily() {
        let reg = BroadcastRegistry::new();
        let id = swap_id(20);
        // No panic when sending with no subscribers
        reg.send(id, b"hello".to_vec());
    }

    #[tokio::test]
    async fn broadcast_subscribe_receives_published_messages() {
        let reg = BroadcastRegistry::new();
        let id = swap_id(21);
        let mut rx = reg.subscribe(id);
        reg.send(id, b"first".to_vec());
        let received = rx.recv().await.unwrap();
        assert_eq!(received, b"first");
    }

    #[tokio::test]
    async fn broadcast_send_no_subscribers_does_not_panic() {
        let reg = BroadcastRegistry::new();
        let id = swap_id(22);
        // send without any subscriber: must not panic
        reg.send(id, b"no-one-listening".to_vec());
        reg.send(id, b"still-fine".to_vec());
    }

    #[tokio::test]
    async fn broadcast_remove_drops_channel() {
        let reg = BroadcastRegistry::new();
        let id = swap_id(23);
        let mut rx = reg.subscribe(id);
        reg.remove(&id);
        // After remove, the sender is gone; receiver should get a Closed error
        reg.send(id, b"after-remove".to_vec()); // new channel, but rx is from old one
        // The original rx is now lagged or closed
        let _ = rx.try_recv(); // may be empty: the channel was re-created
        // Main assertion: remove doesn't panic
    }

    #[tokio::test]
    async fn broadcast_lagged_receiver_gets_lagged_error() {
        let reg = BroadcastRegistry::new();
        let id = swap_id(24);
        let mut rx = reg.subscribe(id);
        // Overflow the 64-message buffer
        for i in 0u8..=64 {
            reg.send(id, vec![i]);
        }
        // The receiver should report a Lagged error since it was never polled
        let result = rx.recv().await;
        assert!(
            matches!(result, Err(broadcast::error::RecvError::Lagged(_))),
            "expected Lagged, got: {:?}",
            result
        );
    }
}
