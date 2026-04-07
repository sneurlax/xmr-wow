//! SwapMessenger: async trait for sending and receiving CoordMessages.
//!
//! This module defines the stable trait contract for swap protocol message transport.
//! Two stub implementations are provided:
//!
//! - `SharechainMessenger`: routes messages via the WOW sharechain
//! - `OobMessenger`: routes messages via an out-of-band channel
//!
//! Both stubs return `Err(MessengerError::Transport(_))` in v1.4.
//! Phases 30-31 replace them with real transport logic against this frozen interface.

use async_trait::async_trait;

use crate::coord_message::CoordMessage;
use crate::node_client::NodeClient;

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

/// Async trait for sending and receiving `CoordMessage` envelopes.
///
/// Both `SharechainMessenger` and `OobMessenger` implement this trait, enabling
/// `Box<dyn SwapMessenger>` dispatch for the `--transport` CLI flag (XPORT-03).
///
/// The trait is frozen as of v1.4. Do not change method signatures after Phase 29.
#[async_trait]
pub trait SwapMessenger: Send + Sync {
    /// Send a `CoordMessage` to the transport layer.
    async fn send(&self, msg: CoordMessage) -> Result<(), MessengerError>;

    /// Receive the next pending `CoordMessage` for the given swap identifier.
    ///
    /// Returns `Ok(None)` if no message is available yet.
    async fn receive(&self, swap_id: &[u8; 32]) -> Result<Option<CoordMessage>, MessengerError>;
}

// ---------------------------------------------------------------------------
// SharechainMessenger
// ---------------------------------------------------------------------------

/// Stub implementation that will route messages via the WOW sharechain.
///
/// In v1.4 both `send` and `receive` return `Err(MessengerError::Transport(_))`.
/// Phase 30 will replace the stub bodies with real sharechain RPC calls.
pub struct SharechainMessenger {
    /// URL of the sharechain node (e.g. `http://127.0.0.1:34568`).
    pub node_url: String,
}

#[async_trait]
impl SwapMessenger for SharechainMessenger {
    async fn send(&self, msg: CoordMessage) -> Result<(), MessengerError> {
        let raw = serde_json::to_vec(&msg)
            .map_err(|e| MessengerError::Serialization(e.to_string()))?;
        let client = NodeClient::new(&self.node_url);
        client.publish_coord_message(&msg.swap_id, raw)
            .await
            .map_err(|e| MessengerError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn receive(&self, swap_id: &[u8; 32]) -> Result<Option<CoordMessage>, MessengerError> {
        let client = NodeClient::new(&self.node_url);
        let (msgs, _next) = client.poll_coord_messages(swap_id, 0)
            .await
            .map_err(|e| MessengerError::Transport(e.to_string()))?;
        match msgs.into_iter().next() {
            None => Ok(None),
            Some(raw) => {
                let coord: CoordMessage = serde_json::from_slice(&raw)
                    .map_err(|e| MessengerError::Serialization(e.to_string()))?;
                Ok(Some(coord))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OobMessenger
// ---------------------------------------------------------------------------

/// Stub implementation that will route messages via an out-of-band channel.
///
/// In v1.4 both `send` and `receive` return `Err(MessengerError::Transport(_))`.
/// Phase 31 will replace the stub bodies with real out-of-band transport logic.
pub struct OobMessenger;

#[async_trait]
impl SwapMessenger for OobMessenger {
    async fn send(&self, _msg: CoordMessage) -> Result<(), MessengerError> {
        Err(MessengerError::Transport(
            "out-of-band transport not yet implemented".into(),
        ))
    }

    async fn receive(&self, _swap_id: &[u8; 32]) -> Result<Option<CoordMessage>, MessengerError> {
        Err(MessengerError::Transport(
            "out-of-band transport not yet implemented".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- MessengerError display ---

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

    // --- SharechainMessenger stubs ---

    #[tokio::test]
    async fn sharechain_send_returns_err_not_panic() {
        let m = SharechainMessenger {
            node_url: "http://127.0.0.1:34568".into(),
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
        };
        let swap_id = [0u8; 32];
        let result = m.receive(&swap_id).await;
        assert!(result.is_err(), "receive must return Err");
        assert!(
            matches!(result.unwrap_err(), MessengerError::Transport(_)),
            "receive error must be Transport variant"
        );
    }

    // --- OobMessenger stubs ---

    #[tokio::test]
    async fn oob_send_returns_err_not_panic() {
        let m = OobMessenger;
        let coord = CoordMessage {
            swap_id: [1u8; 32],
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
    async fn oob_receive_returns_err_not_panic() {
        let m = OobMessenger;
        let swap_id = [1u8; 32];
        let result = m.receive(&swap_id).await;
        assert!(result.is_err(), "receive must return Err");
        assert!(
            matches!(result.unwrap_err(), MessengerError::Transport(_)),
            "receive error must be Transport variant"
        );
    }

    // --- Object-safety: compile-time proof ---

    #[test]
    fn sharechain_messenger_is_object_safe() {
        let m: Box<dyn SwapMessenger + Send + Sync> = Box::new(SharechainMessenger {
            node_url: "http://127.0.0.1:34568".into(),
        });
        // Just holding the Box is enough — this is a compile-time proof.
        let _ = m;
    }

    #[test]
    fn oob_messenger_is_object_safe() {
        let m: Box<dyn SwapMessenger + Send + Sync> = Box::new(OobMessenger);
        let _ = m;
    }
}
