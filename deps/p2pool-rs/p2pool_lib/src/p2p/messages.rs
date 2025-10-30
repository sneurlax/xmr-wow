// P2Pool for Monero - P2P protocol messages
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// The p2pool P2P protocol is a simple binary framing protocol over TCP.
// Each message is:
//   [message_id: u8] [payload_size: u32 LE] [payload: bytes]
//
// Protocol versions (from p2p_server.h):
//   1.0 = 0x00010000  original
//   1.1 = 0x00010001  added BLOCK_BROADCAST_COMPACT
//   1.2 = 0x00010002  added BLOCK_NOTIFY
//   1.3 = 0x00010003  added AUX_JOB_DONATION
//   1.4 = 0x00010004  added MONERO_BLOCK_BROADCAST (current)
//
// Handshake sequence:
//   Both sides send HANDSHAKE_CHALLENGE immediately on connect.
//   Each challenge contains: [challenge: 8B] [peer_id: 8B]
//   The receiver computes: H = keccak256(challenge || consensus_id || salt)
//     where salt is 8 random bytes it chooses.
//   Both sides send HANDSHAKE_SOLUTION: [solution_hash: 32B] [salt: 8B]
//   The initiator's solution must have PoW difficulty >= CHALLENGE_DIFFICULTY (10000).
//   After handshake both sides send LISTEN_PORT.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

/// P2P protocol version constants.
pub const PROTOCOL_VERSION_1_0: u32 = 0x0001_0000;
pub const PROTOCOL_VERSION_1_1: u32 = 0x0001_0001;
pub const PROTOCOL_VERSION_1_2: u32 = 0x0001_0002;
pub const PROTOCOL_VERSION_1_3: u32 = 0x0001_0003;
pub const PROTOCOL_VERSION_1_4: u32 = 0x0001_0004;
pub const SUPPORTED_PROTOCOL_VERSION: u32 = PROTOCOL_VERSION_1_4;

/// Default P2P listening ports.
pub const DEFAULT_P2P_PORT: u16 = 37889;
pub const DEFAULT_P2P_PORT_MINI: u16 = 37888;
pub const DEFAULT_P2P_PORT_NANO: u16 = 37890;
pub const DEFAULT_P2P_PORT_ONION: u16 = 28722;

/// Maximum peers returned in a PEER_LIST_RESPONSE.
pub const PEER_LIST_RESPONSE_MAX_PEERS: usize = 16;

/// Handshake challenge size (8 bytes random).
pub const CHALLENGE_SIZE: usize = 8;
/// Minimum PoW difficulty required for the handshake solution from the initiator.
pub const CHALLENGE_DIFFICULTY: u64 = 10_000;

/// P2P message type identifiers (1 byte on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageId {
    HandshakeChallenge = 0,
    HandshakeSolution = 1,
    ListenPort = 2,
    BlockRequest = 3,
    BlockResponse = 4,
    BlockBroadcast = 5,
    PeerListRequest = 6,
    PeerListResponse = 7,
    BlockBroadcastCompact = 8, // v1.1+
    BlockNotify = 9,           // v1.2+
    AuxJobDonation = 10,       // v1.3+
    MoneroBlockBroadcast = 11, // v1.4+
}

impl MessageId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::HandshakeChallenge),
            1 => Some(Self::HandshakeSolution),
            2 => Some(Self::ListenPort),
            3 => Some(Self::BlockRequest),
            4 => Some(Self::BlockResponse),
            5 => Some(Self::BlockBroadcast),
            6 => Some(Self::PeerListRequest),
            7 => Some(Self::PeerListResponse),
            8 => Some(Self::BlockBroadcastCompact),
            9 => Some(Self::BlockNotify),
            10 => Some(Self::AuxJobDonation),
            11 => Some(Self::MoneroBlockBroadcast),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("buffer too short")]
    TooShort,
    #[error("unknown message id: {0}")]
    UnknownId(u8),
    #[error("invalid payload for message {0:?}")]
    InvalidPayload(MessageId),
    #[error("message too large: {0} bytes")]
    TooLarge(usize),
}

/// The maximum size of a single framed message (1 byte id + 4 bytes size + payload).
pub const MAX_MESSAGE_SIZE: usize = crate::pool_block::MAX_BLOCK_SIZE + 5;

/// A decoded P2P message.
#[derive(Debug, Clone)]
pub enum P2PMessage {
    /// Initial handshake: [challenge: 8B] [peer_id: 8B]
    HandshakeChallenge {
        challenge: [u8; CHALLENGE_SIZE],
        peer_id: u64,
    },
    /// Handshake response: [solution: 32B] [salt: 8B]
    HandshakeSolution {
        solution: p2pool_crypto::Hash,
        salt: [u8; CHALLENGE_SIZE],
    },
    /// Announce our listen port: [port: u16 LE]
    ListenPort(u16),
    /// Request a specific block by sidechain_id: [id: 32B]
    BlockRequest { id: p2pool_crypto::Hash },
    /// Response with a full serialized block: [block_data: bytes]
    BlockResponse { data: Bytes },
    /// Broadcast a new block (full): [block_data: bytes]
    BlockBroadcast { data: Bytes },
    /// Request the peer list (empty payload).
    PeerListRequest,
    /// Response with up to 16 peers:
    /// [count: u8] ([is_v6: u8] [ip: 16B] [port: u16 LE])+
    PeerListResponse { peers: Vec<PeerAddress> },
    /// Compact block broadcast (parent hash + compact representation).
    BlockBroadcastCompact { data: Bytes },
    /// Notify about a known block without sending it: [id: 32B] [height: u64 LE]
    BlockNotify {
        id: p2pool_crypto::Hash,
        height: u64,
    },
    /// Merge-mining auxiliary job donation (signed blob).
    AuxJobDonation { data: Bytes },
    /// Relay a raw Monero block blob to other peers.
    MoneroBlockBroadcast { data: Bytes },
}

/// A peer address as encoded in PEER_LIST_RESPONSE.
#[derive(Debug, Clone)]
pub struct PeerAddress {
    pub is_v6: bool,
    /// Raw 16-byte IP (IPv4 addresses use the IPv4-mapped-in-IPv6 prefix).
    pub ip: [u8; 16],
    pub port: u16,
}

impl P2PMessage {
    /// Encode this message into a framed byte buffer:
    ///   [id: u8] [size: u32 LE] [payload]
    pub fn encode(&self) -> Bytes {
        let mut payload = BytesMut::new();
        let id = self.encode_payload(&mut payload);
        let size = payload.len() as u32;
        let mut out = BytesMut::with_capacity(5 + payload.len());
        out.put_u8(id as u8);
        out.put_u32_le(size);
        out.extend_from_slice(&payload);
        out.freeze()
    }

    fn encode_payload(&self, buf: &mut BytesMut) -> MessageId {
        match self {
            P2PMessage::HandshakeChallenge { challenge, peer_id } => {
                buf.extend_from_slice(challenge);
                buf.put_u64_le(*peer_id);
                MessageId::HandshakeChallenge
            }
            P2PMessage::HandshakeSolution { solution, salt } => {
                buf.extend_from_slice(solution.as_bytes());
                buf.extend_from_slice(salt);
                MessageId::HandshakeSolution
            }
            P2PMessage::ListenPort(port) => {
                buf.put_u16_le(*port);
                MessageId::ListenPort
            }
            P2PMessage::BlockRequest { id } => {
                buf.extend_from_slice(id.as_bytes());
                MessageId::BlockRequest
            }
            P2PMessage::BlockResponse { data } => {
                buf.extend_from_slice(data);
                MessageId::BlockResponse
            }
            P2PMessage::BlockBroadcast { data } => {
                buf.extend_from_slice(data);
                MessageId::BlockBroadcast
            }
            P2PMessage::PeerListRequest => MessageId::PeerListRequest,
            P2PMessage::PeerListResponse { peers } => {
                buf.put_u8(peers.len() as u8);
                for peer in peers {
                    buf.put_u8(peer.is_v6 as u8);
                    buf.extend_from_slice(&peer.ip);
                    buf.put_u16_le(peer.port);
                }
                MessageId::PeerListResponse
            }
            P2PMessage::BlockBroadcastCompact { data } => {
                buf.extend_from_slice(data);
                MessageId::BlockBroadcastCompact
            }
            P2PMessage::BlockNotify { id, height } => {
                buf.extend_from_slice(id.as_bytes());
                buf.put_u64_le(*height);
                MessageId::BlockNotify
            }
            P2PMessage::AuxJobDonation { data } => {
                buf.extend_from_slice(data);
                MessageId::AuxJobDonation
            }
            P2PMessage::MoneroBlockBroadcast { data } => {
                buf.extend_from_slice(data);
                MessageId::MoneroBlockBroadcast
            }
        }
    }

    /// Decode a message from a raw payload buffer.
    pub fn decode(id: MessageId, payload: Bytes) -> Result<Self, MessageError> {
        match id {
            MessageId::HandshakeChallenge => {
                if payload.len() < CHALLENGE_SIZE + 8 {
                    return Err(MessageError::InvalidPayload(id));
                }
                let mut challenge = [0u8; CHALLENGE_SIZE];
                challenge.copy_from_slice(&payload[..CHALLENGE_SIZE]);
                let peer_id = u64::from_le_bytes(
                    payload[CHALLENGE_SIZE..CHALLENGE_SIZE + 8]
                        .try_into()
                        .unwrap(),
                );
                Ok(P2PMessage::HandshakeChallenge { challenge, peer_id })
            }
            MessageId::HandshakeSolution => {
                if payload.len() < 32 + CHALLENGE_SIZE {
                    return Err(MessageError::InvalidPayload(id));
                }
                let solution =
                    p2pool_crypto::Hash::from_bytes(&payload[..32]).unwrap_or_default();
                let mut salt = [0u8; CHALLENGE_SIZE];
                salt.copy_from_slice(&payload[32..32 + CHALLENGE_SIZE]);
                Ok(P2PMessage::HandshakeSolution { solution, salt })
            }
            MessageId::ListenPort => {
                if payload.len() < 2 {
                    return Err(MessageError::InvalidPayload(id));
                }
                let port = u16::from_le_bytes(payload[..2].try_into().unwrap());
                Ok(P2PMessage::ListenPort(port))
            }
            MessageId::BlockRequest => {
                if payload.len() < 32 {
                    return Err(MessageError::InvalidPayload(id));
                }
                let block_id =
                    p2pool_crypto::Hash::from_bytes(&payload[..32]).unwrap_or_default();
                Ok(P2PMessage::BlockRequest { id: block_id })
            }
            MessageId::BlockResponse => Ok(P2PMessage::BlockResponse { data: payload }),
            MessageId::BlockBroadcast => Ok(P2PMessage::BlockBroadcast { data: payload }),
            MessageId::PeerListRequest => Ok(P2PMessage::PeerListRequest),
            MessageId::PeerListResponse => {
                if payload.is_empty() {
                    return Ok(P2PMessage::PeerListResponse { peers: Vec::new() });
                }
                let count = payload[0] as usize;
                let mut peers = Vec::with_capacity(count);
                let mut pos = 1usize;
                for _ in 0..count {
                    if pos + 19 > payload.len() {
                        break;
                    }
                    let is_v6 = payload[pos] != 0;
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&payload[pos + 1..pos + 17]);
                    let port =
                        u16::from_le_bytes(payload[pos + 17..pos + 19].try_into().unwrap());
                    peers.push(PeerAddress { is_v6, ip, port });
                    pos += 19;
                }
                Ok(P2PMessage::PeerListResponse { peers })
            }
            MessageId::BlockBroadcastCompact => {
                Ok(P2PMessage::BlockBroadcastCompact { data: payload })
            }
            MessageId::BlockNotify => {
                if payload.len() < 40 {
                    return Err(MessageError::InvalidPayload(id));
                }
                let block_id =
                    p2pool_crypto::Hash::from_bytes(&payload[..32]).unwrap_or_default();
                let height = u64::from_le_bytes(payload[32..40].try_into().unwrap());
                Ok(P2PMessage::BlockNotify { id: block_id, height })
            }
            MessageId::AuxJobDonation => Ok(P2PMessage::AuxJobDonation { data: payload }),
            MessageId::MoneroBlockBroadcast => {
                Ok(P2PMessage::MoneroBlockBroadcast { data: payload })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_port_roundtrip() {
        let msg = P2PMessage::ListenPort(37889);
        let encoded = msg.encode();
        assert_eq!(encoded[0], MessageId::ListenPort as u8);
        let size = u32::from_le_bytes(encoded[1..5].try_into().unwrap());
        let payload = encoded.slice(5..5 + size as usize);
        let decoded = P2PMessage::decode(MessageId::ListenPort, payload).unwrap();
        assert!(matches!(decoded, P2PMessage::ListenPort(37889)));
    }

    #[test]
    fn block_request_roundtrip() {
        let mut id = p2pool_crypto::Hash::ZERO;
        id.0[0] = 0xAB;
        let msg = P2PMessage::BlockRequest { id };
        let encoded = msg.encode();
        let size = u32::from_le_bytes(encoded[1..5].try_into().unwrap());
        let payload = encoded.slice(5..5 + size as usize);
        let decoded =
            P2PMessage::decode(MessageId::BlockRequest, payload).unwrap();
        match decoded {
            P2PMessage::BlockRequest { id: decoded_id } => {
                assert_eq!(decoded_id.0[0], 0xAB)
            }
            _ => panic!("wrong variant"),
        }
    }
}
