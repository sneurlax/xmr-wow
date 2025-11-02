// xmr-wow-sharechain: P2P protocol messages
//
// Adapted from deps/p2pool-rs/p2pool_lib/src/p2p/messages.rs.
// Wire format is identical to p2pool for maximum compatibility.
// Each message is: [id: u8][size: u32 LE][payload: bytes]
//
// Changes from p2pool-rs:
//   - Removed p2pool_crypto dependency; hashes are plain [u8;32].
//   - Removed pool_block::MAX_BLOCK_SIZE reference; use our own cap.
//   - Removed AuxJobDonation / MoneroBlockBroadcast (kept as stubs).
//   - Added SwapShareBroadcast (message ID 12).

use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

// --- Protocol version constants -----------------------------------------------

pub const PROTOCOL_VERSION_1_0: u32 = 0x0001_0000;
pub const PROTOCOL_VERSION_1_1: u32 = 0x0001_0001;
pub const PROTOCOL_VERSION_1_2: u32 = 0x0001_0002;
pub const PROTOCOL_VERSION_1_3: u32 = 0x0001_0003;
pub const PROTOCOL_VERSION_1_4: u32 = 0x0001_0004;
pub const SUPPORTED_PROTOCOL_VERSION: u32 = PROTOCOL_VERSION_1_4;

// --- Port defaults ------------------------------------------------------------

pub const DEFAULT_P2P_PORT: u16 = 37889;

// --- Handshake constants ------------------------------------------------------

pub const CHALLENGE_SIZE: usize = 8;
/// Minimum PoW difficulty required for the handshake solution (initiator side).
pub const CHALLENGE_DIFFICULTY: u64 = 10_000;

// --- Size cap ----------------------------------------------------------------

/// Maximum permitted payload size for a single framed message.
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

// --- MessageId ---------------------------------------------------------------

/// P2P message type identifiers (one byte on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageId {
    HandshakeChallenge   = 0,
    HandshakeSolution    = 1,
    ListenPort           = 2,
    BlockRequest         = 3,
    BlockResponse        = 4,
    BlockBroadcast       = 5,
    PeerListRequest      = 6,
    PeerListResponse     = 7,
    BlockBroadcastCompact = 8,
    BlockNotify          = 9,
    /// Stub: retained for wire-format compatibility (v1.3+).
    AuxJobDonation       = 10,
    /// Stub: retained for wire-format compatibility (v1.4+).
    MoneroBlockBroadcast = 11,
    /// New: broadcast a serialized SwapShare.
    SwapShareBroadcast   = 12,
}

impl MessageId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0  => Some(Self::HandshakeChallenge),
            1  => Some(Self::HandshakeSolution),
            2  => Some(Self::ListenPort),
            3  => Some(Self::BlockRequest),
            4  => Some(Self::BlockResponse),
            5  => Some(Self::BlockBroadcast),
            6  => Some(Self::PeerListRequest),
            7  => Some(Self::PeerListResponse),
            8  => Some(Self::BlockBroadcastCompact),
            9  => Some(Self::BlockNotify),
            10 => Some(Self::AuxJobDonation),
            11 => Some(Self::MoneroBlockBroadcast),
            12 => Some(Self::SwapShareBroadcast),
            _  => None,
        }
    }
}

// --- Errors -------------------------------------------------------------------

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

// --- PeerAddress -------------------------------------------------------------

/// A peer address as encoded in `PeerListResponse`.
#[derive(Debug, Clone)]
pub struct PeerAddress {
    pub is_v6: bool,
    /// Raw 16-byte IP; IPv4 addresses use the IPv4-mapped prefix.
    pub ip:    [u8; 16],
    pub port:  u16,
}

// --- P2PMessage ---------------------------------------------------------------

/// A decoded P2P message.
#[derive(Debug, Clone)]
pub enum P2PMessage {
    /// Initial handshake: `[challenge: 8B] [peer_id: 8B]`
    HandshakeChallenge {
        challenge: [u8; CHALLENGE_SIZE],
        peer_id:   u64,
    },
    /// Handshake response: `[solution: 32B] [salt: 8B]`
    HandshakeSolution {
        solution: [u8; 32],
        salt:     [u8; CHALLENGE_SIZE],
    },
    /// Announce our listen port: `[port: u16 LE]`
    ListenPort(u16),
    /// Request a block by share ID: `[id: 32B]`
    BlockRequest { id: [u8; 32] },
    /// Response with full serialised share bytes.
    BlockResponse { data: Bytes },
    /// Broadcast a new share (full serialisation).
    BlockBroadcast { data: Bytes },
    /// Request the peer list (empty payload).
    PeerListRequest,
    /// Response with up to 16 peers: `[count: u8]([is_v6: u8][ip: 16B][port: u16 LE])+`
    PeerListResponse { peers: Vec<PeerAddress> },
    /// Compact block broadcast (parent hash + compact payload).
    BlockBroadcastCompact { data: Bytes },
    /// Notify about a known share without sending it: `[id: 32B][height: u64 LE]`
    BlockNotify { id: [u8; 32], height: u64 },
    /// Stub for wire-format compatibility (v1.3+).
    AuxJobDonation { data: Bytes },
    /// Stub for wire-format compatibility (v1.4+).
    MoneroBlockBroadcast { data: Bytes },
    /// Broadcast a serialised `SwapShare` (message ID 12).
    SwapShareBroadcast { data: Bytes },
}

impl P2PMessage {
    // -- Encoding -------------------------------------------------------------

    /// Encode this message into a framed byte buffer: `[id: u8][size: u32 LE][payload]`.
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
                buf.extend_from_slice(solution);
                buf.extend_from_slice(salt);
                MessageId::HandshakeSolution
            }
            P2PMessage::ListenPort(port) => {
                buf.put_u16_le(*port);
                MessageId::ListenPort
            }
            P2PMessage::BlockRequest { id } => {
                buf.extend_from_slice(id);
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
                buf.put_u8(peers.len().min(255) as u8);
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
                buf.extend_from_slice(id);
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
            P2PMessage::SwapShareBroadcast { data } => {
                buf.extend_from_slice(data);
                MessageId::SwapShareBroadcast
            }
        }
    }

    // -- Decoding -------------------------------------------------------------

    /// Decode a message from a raw payload buffer given its `MessageId`.
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
                let mut solution = [0u8; 32];
                solution.copy_from_slice(&payload[..32]);
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
                let mut block_id = [0u8; 32];
                block_id.copy_from_slice(&payload[..32]);
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
                let mut block_id = [0u8; 32];
                block_id.copy_from_slice(&payload[..32]);
                let height = u64::from_le_bytes(payload[32..40].try_into().unwrap());
                Ok(P2PMessage::BlockNotify { id: block_id, height })
            }

            MessageId::AuxJobDonation => Ok(P2PMessage::AuxJobDonation { data: payload }),
            MessageId::MoneroBlockBroadcast => {
                Ok(P2PMessage::MoneroBlockBroadcast { data: payload })
            }
            MessageId::SwapShareBroadcast => {
                Ok(P2PMessage::SwapShareBroadcast { data: payload })
            }
        }
    }
}

// --- Tests --------------------------------------------------------------------

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
        let mut id = [0u8; 32];
        id[0] = 0xAB;
        let msg = P2PMessage::BlockRequest { id };
        let encoded = msg.encode();
        let size = u32::from_le_bytes(encoded[1..5].try_into().unwrap());
        let payload = encoded.slice(5..5 + size as usize);
        let decoded = P2PMessage::decode(MessageId::BlockRequest, payload).unwrap();
        match decoded {
            P2PMessage::BlockRequest { id: decoded_id } => assert_eq!(decoded_id[0], 0xAB),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn handshake_challenge_roundtrip() {
        let challenge = [0x12u8; CHALLENGE_SIZE];
        let peer_id = 0xDEAD_BEEF_CAFE_BABEu64;
        let msg = P2PMessage::HandshakeChallenge { challenge, peer_id };
        let encoded = msg.encode();
        assert_eq!(encoded[0], MessageId::HandshakeChallenge as u8);
        let size = u32::from_le_bytes(encoded[1..5].try_into().unwrap()) as usize;
        let payload = encoded.slice(5..5 + size);
        match P2PMessage::decode(MessageId::HandshakeChallenge, payload).unwrap() {
            P2PMessage::HandshakeChallenge { challenge: c, peer_id: p } => {
                assert_eq!(c, [0x12u8; CHALLENGE_SIZE]);
                assert_eq!(p, 0xDEAD_BEEF_CAFE_BABEu64);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn swap_share_broadcast_roundtrip() {
        let data = Bytes::from_static(b"hello swap share");
        let msg = P2PMessage::SwapShareBroadcast { data: data.clone() };
        let encoded = msg.encode();
        assert_eq!(encoded[0], MessageId::SwapShareBroadcast as u8);
        let size = u32::from_le_bytes(encoded[1..5].try_into().unwrap()) as usize;
        let payload = encoded.slice(5..5 + size);
        match P2PMessage::decode(MessageId::SwapShareBroadcast, payload).unwrap() {
            P2PMessage::SwapShareBroadcast { data: d } => assert_eq!(d, data),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn peer_list_response_roundtrip() {
        let peers = vec![
            PeerAddress { is_v6: false, ip: [0u8; 16], port: 37889 },
            PeerAddress { is_v6: true,  ip: [1u8; 16], port: 37890 },
        ];
        let msg = P2PMessage::PeerListResponse { peers };
        let encoded = msg.encode();
        let size = u32::from_le_bytes(encoded[1..5].try_into().unwrap()) as usize;
        let payload = encoded.slice(5..5 + size);
        match P2PMessage::decode(MessageId::PeerListResponse, payload).unwrap() {
            P2PMessage::PeerListResponse { peers: p } => {
                assert_eq!(p.len(), 2);
                assert_eq!(p[0].port, 37889);
                assert!(!p[0].is_v6);
                assert_eq!(p[1].port, 37890);
                assert!(p[1].is_v6);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn block_notify_roundtrip() {
        let mut id = [0u8; 32];
        id[31] = 0xFF;
        let msg = P2PMessage::BlockNotify { id, height: 12345 };
        let encoded = msg.encode();
        let size = u32::from_le_bytes(encoded[1..5].try_into().unwrap()) as usize;
        let payload = encoded.slice(5..5 + size);
        match P2PMessage::decode(MessageId::BlockNotify, payload).unwrap() {
            P2PMessage::BlockNotify { id: i, height: h } => {
                assert_eq!(i[31], 0xFF);
                assert_eq!(h, 12345);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn message_id_from_u8_all_known() {
        for id in 0u8..=12 {
            assert!(MessageId::from_u8(id).is_some(), "id {id} should be known");
        }
        assert!(MessageId::from_u8(13).is_none());
        assert!(MessageId::from_u8(255).is_none());
    }
}
