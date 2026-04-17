//! Async transport trait for `CoordMessage` with sharechain and out-of-band implementations.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::AsyncBufReadExt;

use crate::coord_message::CoordMessage;
use crate::node_client::NodeClient;
use crate::protocol_message::ProtocolMessage;
use crate::store::SwapStore;

/// Errors produced by SwapMessenger operations.
#[derive(Debug, thiserror::Error)]
pub enum MessengerError {
    /// Transport-layer failure (network, serialization at transport level, etc.).
    #[error("transport error: {0}")]
    Transport(String),

    /// Message serialization or deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Async transport for `CoordMessage` envelopes; supports `Box<dyn SwapMessenger>` dispatch.
#[async_trait]
pub trait SwapMessenger: Send + Sync {
    /// Send a `CoordMessage` to the transport layer.
    async fn send(&self, msg: CoordMessage) -> Result<(), MessengerError>;

    /// Receive the next pending `CoordMessage` for the given swap identifier.
    ///
    /// Returns `Ok(None)` if no message is available yet.
    async fn receive(&self, swap_id: &[u8; 32]) -> Result<Option<CoordMessage>, MessengerError>;
}

/// Routes messages via the WOW sharechain node.
pub struct SharechainMessenger {
    /// URL of the sharechain node (e.g. `http://127.0.0.1:34568`).
    pub node_url: String,
    /// Shared swap store for cursor persistence across receive calls.
    pub store: Arc<Mutex<SwapStore>>,
}

#[async_trait]
impl SwapMessenger for SharechainMessenger {
    async fn send(&self, msg: CoordMessage) -> Result<(), MessengerError> {
        let raw =
            serde_json::to_vec(&msg).map_err(|e| MessengerError::Serialization(e.to_string()))?;
        let client = NodeClient::new(&self.node_url);
        client
            .publish_coord_message(&msg.swap_id, raw)
            .await
            .map_err(|e| MessengerError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn receive(&self, swap_id: &[u8; 32]) -> Result<Option<CoordMessage>, MessengerError> {
        let after_index = {
            let store = self.store.lock().unwrap();
            store
                .get_cursor(swap_id)
                .map_err(|e| MessengerError::Transport(e.to_string()))?
        };
        let client = NodeClient::new(&self.node_url);
        let (msgs, next_index) = client
            .poll_coord_messages(swap_id, after_index)
            .await
            .map_err(|e| MessengerError::Transport(e.to_string()))?;
        match msgs.into_iter().next() {
            None => Ok(None),
            Some(raw) => {
                {
                    let store = self.store.lock().unwrap();
                    store
                        .set_cursor(swap_id, next_index)
                        .map_err(|e| MessengerError::Transport(e.to_string()))?;
                }
                let coord: CoordMessage = serde_json::from_slice(&raw)
                    .map_err(|e| MessengerError::Serialization(e.to_string()))?;
                Ok(Some(coord))
            }
        }
    }
}

/// Copy-paste transport: `send` prints an `xmrwow1:` string to stdout; `receive` reads one from stdin.
pub struct OobMessenger;

#[async_trait]
impl SwapMessenger for OobMessenger {
    async fn send(&self, msg: CoordMessage) -> Result<(), MessengerError> {
        let proto = crate::coord_message::unwrap_protocol_message(&msg)
            .map_err(|e| MessengerError::Serialization(e.to_string()))?;
        let encoded = crate::protocol_message::encode_message(&proto);
        println!("---");
        println!("{}", encoded);
        println!("---");
        Ok(())
    }

    async fn receive(&self, swap_id: &[u8; 32]) -> Result<Option<CoordMessage>, MessengerError> {
        println!("Paste your counterparty's message and press Enter:");
        let stdin = tokio::io::stdin();
        let mut reader = tokio::io::BufReader::new(stdin);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| MessengerError::Transport(e.to_string()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let proto: ProtocolMessage = crate::protocol_message::decode_message(trimmed)
            .map_err(|e| MessengerError::Transport(e.to_string()))?;
        let coord = crate::coord_message::wrap_protocol_message(*swap_id, &proto)
            .map_err(|e| MessengerError::Serialization(e.to_string()))?;
        Ok(Some(coord))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SwapStore;

    fn make_test_store() -> Arc<Mutex<SwapStore>> {
        Arc::new(Mutex::new(SwapStore::open_in_memory().unwrap()))
    }

    #[test]
    fn messenger_error_transport_display() {
        let err = MessengerError::Transport("network down".into());
        assert_eq!(format!("{err}"), "transport error: network down");
    }

    #[test]
    fn messenger_error_serialization_display() {
        let err = MessengerError::Serialization("bad bytes".into());
        assert_eq!(format!("{err}"), "serialization error: bad bytes");
    }

    #[tokio::test]
    async fn sharechain_send_returns_err_not_panic() {
        let m = SharechainMessenger {
            node_url: "http://127.0.0.1:34568".into(),
            store: make_test_store(),
        };
        let coord = CoordMessage {
            swap_id: [0u8; 32],
            payload: vec![],
            encryption_hint: None,
        };
        let result = m.send(coord).await;
        assert!(result.is_err(), "send must return Err");
        assert!(
            matches!(result.unwrap_err(), MessengerError::Transport(_)),
            "send error must be Transport variant"
        );
    }

    #[tokio::test]
    async fn sharechain_receive_returns_err_not_panic() {
        let m = SharechainMessenger {
            node_url: "http://127.0.0.1:34568".into(),
            store: make_test_store(),
        };
        let swap_id = [0u8; 32];
        let result = m.receive(&swap_id).await;
        assert!(result.is_err(), "receive must return Err");
        assert!(
            matches!(result.unwrap_err(), MessengerError::Transport(_)),
            "receive error must be Transport variant"
        );
    }

    /// OobMessenger::send with a valid CoordMessage wrapping a ProtocolMessage::Init
    /// returns Ok(()): the xmrwow1: encoded string is printed to stdout as a side effect.
    #[tokio::test]
    async fn oob_send_returns_ok_with_valid_coord_message() {
        use crate::coord_message::wrap_protocol_message;
        use crate::protocol_message::ProtocolMessage;
        use rand::rngs::OsRng;
        use xmr_wow_crypto::{DleqProof, KeyContribution};

        let contrib = KeyContribution::generate(&mut OsRng);
        let proof = DleqProof::prove(
            &contrib.secret,
            &contrib.public,
            b"xmr-wow-swap-v1",
            &mut OsRng,
        );
        let proto = ProtocolMessage::Init {
            pubkey: contrib.public_bytes(),
            proof,
            amount_xmr: 1_000_000_000_000,
            amount_wow: 500_000_000_000_000,
            xmr_refund_delay_seconds: 2000,
            wow_refund_delay_seconds: 1000,
            refund_timing: None,
            alice_refund_address: None,
        };
        let swap_id = [0x42u8; 32];
        let coord = wrap_protocol_message(swap_id, &proto).expect("wrap must succeed");

        let m = OobMessenger;
        let result = m.send(coord).await;
        assert!(
            result.is_ok(),
            "send must return Ok for a valid CoordMessage: {:?}",
            result
        );
    }

    #[test]
    fn oob_messenger_has_no_fields() {
        let _ = OobMessenger;
    }

    // Note: OobMessenger::receive reads from stdin which is not unit-testable in isolation.
    // The receive path is verified via integration/manual testing.

    #[test]
    fn sharechain_messenger_is_object_safe() {
        let m: Box<dyn SwapMessenger + Send + Sync> = Box::new(SharechainMessenger {
            node_url: "http://127.0.0.1:34568".into(),
            store: make_test_store(),
        });
        // Just holding the Box is enough: this is a compile-time proof.
        let _ = m;
    }

    #[test]
    fn oob_messenger_is_object_safe() {
        let m: Box<dyn SwapMessenger + Send + Sync> = Box::new(OobMessenger);
        let _ = m;
    }
}
