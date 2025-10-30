// P2Pool for Monero - P2P server (TCP listener + connection manager)
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// The P2PServer accepts incoming TCP connections and manages outgoing
// connections to known peers. Each connection runs through a handshake
// before block/peer-list exchange begins.
//
// Architecture (async Tokio):
//   - One `TcpListener` task accepts incoming connections.
//   - Each connection runs as a Tokio task, reading framed messages.
//   - A shared `SideChain` is accessed via `Arc<RwLock<...>>`.
//   - When a new block arrives via P2P, it is forwarded to the SideChain
//     and, if valid and tip-changing, re-broadcast to all peers.
//   - A periodic timer task handles: downloading missing blocks, pruning
//     timed-out peers, refreshing the peer list, etc.

use super::messages::{MessageId, P2PMessage, SUPPORTED_PROTOCOL_VERSION};
use super::peer::{ConnectionState, Peer};
use crate::pool_block::PoolBlock;
use crate::side_chain::SideChain;
use p2pool_config::P2pConfig;
use p2pool_crypto::Hash;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Commands sent to the server actor from the block-template builder or other components.
pub enum P2PCommand {
    /// Broadcast a newly found block to all peers.
    BroadcastBlock(Box<PoolBlock>),
    /// Request a specific block from the best-connected peer.
    RequestBlock(Hash),
    /// Cleanly shut down the server.
    Shutdown,
}

/// The P2P server manages all peer connections.
pub struct P2PServer {
    config: P2pConfig,
    sidechain: Arc<SideChain>,
    consensus_id: Vec<u8>,
    /// Our 64-bit peer ID (random, chosen on startup).
    peer_id: u64,
    /// Command channel for external callers.
    cmd_tx: mpsc::Sender<P2PCommand>,
}

impl P2PServer {
    /// Create a new P2PServer.
    ///
    /// Call [`P2PServer::run`] to start the async event loop.
    pub fn new(
        config: P2pConfig,
        sidechain: Arc<SideChain>,
        consensus_id: Vec<u8>,
    ) -> (Self, mpsc::Receiver<P2PCommand>) {
        let peer_id: u64 = rand::random();
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        (
            Self {
                config,
                sidechain,
                consensus_id,
                peer_id,
                cmd_tx,
            },
            cmd_rx,
        )
    }

    pub fn command_sender(&self) -> mpsc::Sender<P2PCommand> {
        self.cmd_tx.clone()
    }

    /// Run the P2P server event loop (blocks until shutdown).
    ///
    /// Spawns:
    ///  - TCP listener task(s) for each configured listen address.
    ///  - Outgoing connection tasks for each configured initial peer.
    ///  - Periodic maintenance timer.
    pub async fn run(self, mut cmd_rx: mpsc::Receiver<P2PCommand>) {
        let sidechain = self.sidechain.clone();
        let consensus_id = self.consensus_id.clone();
        let peer_id = self.peer_id;

        // Shared peer table: addr → Peer state
        let peers: Arc<RwLock<HashMap<SocketAddr, Peer>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Start TCP listeners
        for addr_str in &self.config.listen_addresses {
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    let peers2 = peers.clone();
                    let sc = sidechain.clone();
                    let cid = consensus_id.clone();
                    tokio::spawn(async move {
                        Self::listen_loop(addr, peers2, sc, cid, peer_id).await;
                    });
                }
                Err(e) => error!("invalid listen address {addr_str}: {e}"),
            }
        }

        // Connect to initial peers
        for peer_str in &self.config.peer_list.iter().flat_map(|s| s.split(',')).collect::<Vec<_>>() {
            let peer_str = peer_str.trim().to_string();
            if peer_str.is_empty() {
                continue;
            }
            match peer_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    let peers2 = peers.clone();
                    let sc = sidechain.clone();
                    let cid = consensus_id.clone();
                    tokio::spawn(async move {
                        Self::connect_to_peer(addr, peers2, sc, cid, peer_id).await;
                    });
                }
                Err(e) => warn!("invalid peer address {peer_str}: {e}"),
            }
        }

        // Command loop
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                P2PCommand::BroadcastBlock(block) => {
                    Self::broadcast_block_to_peers(&peers, &block);
                }
                P2PCommand::RequestBlock(id) => {
                    debug!("requesting block {id} from peers");
                    // TODO: pick the fastest peer and send BlockRequest
                }
                P2PCommand::Shutdown => {
                    info!("P2P server shutting down");
                    break;
                }
            }
        }
    }

    async fn listen_loop(
        addr: SocketAddr,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        sidechain: Arc<SideChain>,
        consensus_id: Vec<u8>,
        peer_id: u64,
    ) {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => {
                info!("P2P listening on {addr}");
                l
            }
            Err(e) => {
                error!("failed to bind P2P listener on {addr}: {e}");
                return;
            }
        };
        loop {
            match listener.accept().await {
                Ok((stream, remote_addr)) => {
                    info!("accepted P2P connection from {remote_addr}");
                    let p = peers.clone();
                    let sc = sidechain.clone();
                    let cid = consensus_id.clone();
                    tokio::spawn(async move {
                        Self::handle_connection(stream, remote_addr, false, p, sc, cid, peer_id)
                            .await;
                    });
                }
                Err(e) => error!("accept error: {e}"),
            }
        }
    }

    async fn connect_to_peer(
        addr: SocketAddr,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        sidechain: Arc<SideChain>,
        consensus_id: Vec<u8>,
        peer_id: u64,
    ) {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                info!("connected to peer {addr}");
                Self::handle_connection(stream, addr, true, peers, sidechain, consensus_id, peer_id)
                    .await;
            }
            Err(e) => {
                warn!("failed to connect to peer {addr}: {e}");
            }
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        addr: SocketAddr,
        is_outbound: bool,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        sidechain: Arc<SideChain>,
        consensus_id: Vec<u8>,
        our_peer_id: u64,
    ) {
        use super::handshake::{generate_solution, verify_solution};
        use rand::Rng;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut peer = Peer::new(addr, is_outbound, our_peer_id);

        // Generate and send our challenge
        let our_challenge: [u8; 8] = rand::thread_rng().gen();
        peer.our_challenge = our_challenge;

        let challenge_msg = P2PMessage::HandshakeChallenge {
            challenge: our_challenge,
            peer_id: our_peer_id,
        };

        let (mut reader, mut writer) = stream.into_split();

        let encoded = challenge_msg.encode();
        if let Err(e) = writer.write_all(&encoded).await {
            warn!("failed to send handshake challenge to {addr}: {e}");
            return;
        }

        // Read messages in a loop
        let mut header = [0u8; 5]; // id(1) + size(4)
        loop {
            if reader.read_exact(&mut header).await.is_err() {
                debug!("peer {addr} disconnected");
                break;
            }
            let msg_id_byte = header[0];
            let payload_size = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;

            if payload_size > crate::pool_block::MAX_BLOCK_SIZE + 1024 {
                warn!("oversized message from {addr}: {payload_size} bytes");
                break;
            }

            let mut payload_buf = vec![0u8; payload_size];
            if payload_size > 0 && reader.read_exact(&mut payload_buf).await.is_err() {
                break;
            }

            let Some(msg_id) = MessageId::from_u8(msg_id_byte) else {
                warn!("unknown message id {msg_id_byte} from {addr}");
                break;
            };

            let payload = bytes::Bytes::from(payload_buf);
            let Ok(msg) = P2PMessage::decode(msg_id, payload) else {
                warn!("failed to decode message {msg_id:?} from {addr}");
                break;
            };

            match msg {
                P2PMessage::HandshakeChallenge { challenge, peer_id } => {
                    peer.their_challenge = challenge;
                    peer.peer_id = peer_id;
                    peer.state = ConnectionState::AwaitingChallengeSolution;

                    let (salt, solution) =
                        generate_solution(&challenge, &consensus_id, is_outbound);
                    let sol_msg = P2PMessage::HandshakeSolution { solution, salt };
                    let _ = writer.write_all(&sol_msg.encode()).await;
                    peer.handshake_solution_sent = true;
                }
                P2PMessage::HandshakeSolution { solution, salt } => {
                    let peer_is_initiator = !is_outbound;
                    if !verify_solution(
                        &peer.our_challenge,
                        &consensus_id,
                        &solution,
                        &salt,
                        peer_is_initiator,
                    ) {
                        warn!("invalid handshake solution from {addr}");
                        peer.handshake_invalid = true;
                        break;
                    }
                    peer.handshake_complete = true;
                    peer.state = ConnectionState::AwaitingListenPort;

                    // Send our listen port (hardcoded to 0 for now; real impl uses config)
                    let port_msg = P2PMessage::ListenPort(0);
                    let _ = writer.write_all(&port_msg.encode()).await;
                }
                P2PMessage::ListenPort(port) => {
                    peer.listen_port = Some(port);
                    peer.state = ConnectionState::Ready;
                    info!("peer {addr} ready (listen_port={port})");

                    // Register peer
                    peers.write().unwrap().insert(addr, peer.clone());
                }
                P2PMessage::BlockBroadcast { data } | P2PMessage::BlockBroadcastCompact { data } => {
                    if peer.is_good() {
                        debug!("received block broadcast from {addr} ({} bytes)", data.len());
                        // TODO: deserialize PoolBlock, call sidechain.add_block(), re-broadcast if tip changed
                    }
                }
                P2PMessage::PeerListRequest => {
                    let response = P2PMessage::PeerListResponse { peers: Vec::new() };
                    let _ = writer.write_all(&response.encode()).await;
                }
                _ => {
                    debug!("message {msg_id:?} from {addr} (not yet handled)");
                }
            }

            peer.last_alive = std::time::Instant::now();
        }

        peers.write().unwrap().remove(&addr);
    }

    fn broadcast_block_to_peers(
        peers: &Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        block: &PoolBlock,
    ) {
        let _peers = peers.read().unwrap();
        // TODO: serialize block, send BlockBroadcast to each ready peer
        debug!("broadcasting block {}", block.sidechain_id);
    }
}
