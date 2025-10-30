// P2Pool for Monero - Peer connection state
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only

use super::messages::{MessageId, CHALLENGE_SIZE};
use p2pool_crypto::Hash;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Software identifiers sent in the handshake (future use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SoftwareId {
    #[default]
    P2Pool = 0,
    GoObserver = 1,
}

/// The connection state of a P2P peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    #[default]
    Connecting,
    AwaitingChallengeSolution,
    AwaitingListenPort,
    Ready,
    Disconnected,
}

/// Persisted peer record (for the peer list on disk).
#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub addr: SocketAddr,
    pub num_failed_connections: u32,
    pub last_seen: u64,
}

/// Per-connection peer state, corresponding to the C++ `P2PClient`.
#[derive(Clone)]
pub struct Peer {
    /// Remote address.
    pub addr: SocketAddr,
    /// Whether we initiated this connection.
    pub is_outbound: bool,
    /// Unique 64-bit peer identifier (random, chosen by each peer on startup).
    pub peer_id: u64,

    /// Connection state machine.
    pub state: ConnectionState,

    /// Our challenge we sent to the peer.
    pub our_challenge: [u8; CHALLENGE_SIZE],
    /// Their challenge they sent us (we must solve it).
    pub their_challenge: [u8; CHALLENGE_SIZE],

    pub handshake_solution_sent: bool,
    pub handshake_complete: bool,
    pub handshake_invalid: bool,

    /// Port the peer is listening on (-1 if unknown).
    pub listen_port: Option<u16>,

    /// Protocol version negotiated with the peer.
    pub protocol_version: u32,
    /// Software version of the peer.
    pub software_version: u32,
    pub software_id: SoftwareId,

    /// Round-trip time in milliseconds (-1 if unknown).
    pub ping_ms: Option<i64>,

    /// Pending block requests we have sent to this peer.
    pub pending_block_requests: VecDeque<u64>,

    /// Next message we expect to receive (used by the state machine).
    pub expected_message: MessageId,

    /// Time of last received message (for liveness checking).
    pub last_alive: Instant,

    /// Last time we broadcast a block to this peer.
    pub last_broadcast_timestamp: u64,

    /// Height ceiling for block broadcasts (don't send blocks above this).
    pub broadcast_max_height: u64,

    /// Ring buffer of recently broadcast block hashes (for dedup).
    pub broadcasted_hashes: [Hash; 8],
    pub broadcasted_hashes_index: usize,

    /// Time we established the connection.
    pub connected_time: Instant,
}

impl Peer {
    pub fn new(addr: SocketAddr, is_outbound: bool, our_peer_id: u64) -> Self {
        Self {
            addr,
            is_outbound,
            peer_id: 0,
            state: ConnectionState::Connecting,
            our_challenge: [0u8; CHALLENGE_SIZE],
            their_challenge: [0u8; CHALLENGE_SIZE],
            handshake_solution_sent: false,
            handshake_complete: false,
            handshake_invalid: false,
            listen_port: None,
            protocol_version: 0,
            software_version: 0,
            software_id: SoftwareId::P2Pool,
            ping_ms: None,
            pending_block_requests: VecDeque::new(),
            expected_message: MessageId::HandshakeChallenge,
            last_alive: Instant::now(),
            last_broadcast_timestamp: 0,
            broadcast_max_height: 0,
            broadcasted_hashes: [Hash::ZERO; 8],
            broadcasted_hashes_index: 0,
            connected_time: Instant::now(),
        }
    }

    /// Whether this peer has completed the handshake and is ready to exchange blocks.
    pub fn is_good(&self) -> bool {
        self.handshake_complete && !self.handshake_invalid && self.listen_port.is_some()
    }

    /// Record a recently broadcast hash to avoid re-broadcasting the same block.
    pub fn record_broadcast(&mut self, hash: Hash) {
        let i = self.broadcasted_hashes_index % 8;
        self.broadcasted_hashes[i] = hash;
        self.broadcasted_hashes_index += 1;
    }

    /// Check whether we recently broadcast this hash to this peer.
    pub fn already_broadcast(&self, hash: &Hash) -> bool {
        self.broadcasted_hashes.contains(hash)
    }

    /// Whether the peer has been silent for longer than `timeout`.
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_alive.elapsed() > timeout
    }
}
