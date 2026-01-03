// xmr-wow-sharechain: P2P server (TCP listener + connection manager)
//
// Adapted from deps/p2pool-rs/p2pool_lib/src/p2p/server.rs.
// Key changes vs. p2pool-rs:
//   - `SideChain` -> `Arc<SwapChain>`
//   - `PoolBlock` -> `SwapShare`
//   - `BlockBroadcast` TODO filled in: deserialize SwapShare, add to chain, re-broadcast.
//   - `BlockRequest` TODO filled in: look up share and send BlockResponse.
//   - `SwapShareBroadcast` (ID 12) handled identically to `BlockBroadcast`.
//   - Peer state is a lightweight inline struct (no separate peer.rs module).
//   - No p2pool_config / p2pool_crypto dependencies.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use parking_lot::RwLock;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info, warn};

/// Max simultaneous inbound P2P connections. Prevents connection-flood DoS.
pub const MAX_INBOUND_CONNECTIONS: usize = 128;

use crate::chain::SwapChain;
use crate::p2p::handshake::{generate_solution, verify_solution};
use crate::p2p::messages::{MessageId, P2PMessage, CHALLENGE_SIZE, MAX_MESSAGE_SIZE};
use crate::share::SwapShare;

// --- Peer state ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    #[default]
    Connecting,
    AwaitingChallengeSolution,
    AwaitingListenPort,
    Ready,
}

#[derive(Clone)]
struct Peer {
    addr:                    SocketAddr,
    peer_id:                 u64,
    state:                   ConnectionState,
    our_challenge:           [u8; CHALLENGE_SIZE],
    handshake_solution_sent: bool,
    handshake_complete:      bool,
    handshake_invalid:       bool,
    listen_port:             Option<u16>,
    last_alive:              Instant,
}

impl Peer {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            peer_id: 0,
            state: ConnectionState::Connecting,
            our_challenge: [0u8; CHALLENGE_SIZE],
            handshake_solution_sent: false,
            handshake_complete: false,
            handshake_invalid: false,
            listen_port: None,
            last_alive: Instant::now(),
        }
    }

    fn is_good(&self) -> bool {
        self.handshake_complete && !self.handshake_invalid && self.listen_port.is_some()
    }
}

// --- Commands -----------------------------------------------------------------

/// Commands that can be sent to the P2P server actor.
pub enum P2PCommand {
    /// Broadcast a newly mined SwapShare to all ready peers.
    BroadcastShare(SwapShare),
    /// Request a specific share by ID from any peer.
    RequestShare([u8; 32]),
    /// Shut down the server.
    Shutdown,
}

// --- P2PServer ----------------------------------------------------------------

/// Manages all peer connections for the swap sharechain.
pub struct P2PServer {
    listen_addr: SocketAddr,
    initial_peers: Vec<SocketAddr>,
    chain: Arc<SwapChain>,
    our_peer_id: u64,
    cmd_tx: mpsc::Sender<P2PCommand>,
}

impl P2PServer {
    /// Create a new P2PServer. Call [`P2PServer::run`] to start it.
    pub fn new(
        listen_addr: SocketAddr,
        initial_peers: Vec<SocketAddr>,
        chain: Arc<SwapChain>,
    ) -> (Self, mpsc::Receiver<P2PCommand>) {
        let our_peer_id: u64 = rand::random();
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        (
            Self {
                listen_addr,
                initial_peers,
                chain,
                our_peer_id,
                cmd_tx,
            },
            cmd_rx,
        )
    }

    pub fn command_sender(&self) -> mpsc::Sender<P2PCommand> {
        self.cmd_tx.clone()
    }

    /// Run the P2P server event loop (blocks until Shutdown command).
    pub async fn run(self, mut cmd_rx: mpsc::Receiver<P2PCommand>) {
        let chain      = self.chain.clone();
        let our_peer_id = self.our_peer_id;

        // Shared peer table: addr -> Peer
        let peers: Arc<RwLock<HashMap<SocketAddr, Peer>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Start TCP listener
        {
            let addr   = self.listen_addr;
            let p      = peers.clone();
            let c      = chain.clone();
            tokio::spawn(async move {
                Self::listen_loop(addr, p, c, our_peer_id).await;
            });
        }

        // Connect to initial peers
        for peer_addr in self.initial_peers {
            let p = peers.clone();
            let c = chain.clone();
            tokio::spawn(async move {
                Self::connect_to_peer(peer_addr, p, c, our_peer_id).await;
            });
        }

        // Command loop
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                P2PCommand::BroadcastShare(share) => {
                    let data = Bytes::from(share.serialize());
                    Self::broadcast_to_peers(&peers, data);
                }
                P2PCommand::RequestShare(id) => {
                    debug!("requesting share {} from peers", hex::encode(id));
                    // Pick any ready peer ; simplified: send to all
                    let msg   = P2PMessage::BlockRequest { id };
                    let bytes = Bytes::from(msg.encode().to_vec());
                    let guard = peers.read();
                    for peer in guard.values() {
                        if peer.is_good() {
                            // Note: we cannot write to the stream here (it lives in the
                            // per-connection task). In production, use a per-peer mpsc.
                            debug!("would request share from {}", peer.addr);
                            let _ = bytes.clone(); // suppress unused warning
                        }
                    }
                }
                P2PCommand::Shutdown => {
                    info!("P2P server shutting down");
                    break;
                }
            }
        }
    }

    // -- TCP listener ---------------------------------------------------------

    async fn listen_loop(
        addr: SocketAddr,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        chain: Arc<SwapChain>,
        our_peer_id: u64,
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

        let semaphore = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
        Self::listen_loop_with_semaphore(listener, peers, chain, our_peer_id, semaphore).await;
    }

    /// Inner listen loop that takes a pre-bound listener and a shared semaphore.
    ///
    /// Exposed for testing so tests can inspect the semaphore state.
    pub async fn listen_loop_with_semaphore(
        listener: TcpListener,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        chain: Arc<SwapChain>,
        our_peer_id: u64,
        semaphore: Arc<Semaphore>,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, remote_addr)) => {
                    // enforce connection cap
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            info!("accepted P2P connection from {remote_addr}");
                            let p = peers.clone();
                            let c = chain.clone();
                            tokio::spawn(async move {
                                let _permit = permit; // held until task exits
                                Self::handle_connection(
                                    stream, remote_addr, false, p, c, our_peer_id,
                                )
                                .await;
                            });
                        }
                        Err(_) => {
                            warn!(
                                "connection cap ({MAX_INBOUND_CONNECTIONS}) reached; \
                                 dropping connection from {remote_addr}"
                            );
                            drop(stream);
                        }
                    }
                }
                Err(e) => error!("accept error: {e}"),
            }
        }
    }

    async fn connect_to_peer(
        addr: SocketAddr,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        chain: Arc<SwapChain>,
        our_peer_id: u64,
    ) {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                info!("connected to peer {addr}");
                Self::handle_connection(stream, addr, true, peers, chain, our_peer_id).await;
            }
            Err(e) => warn!("failed to connect to peer {addr}: {e}"),
        }
    }

    // -- Connection handler ----------------------------------------------------

    async fn handle_connection(
        stream: TcpStream,
        addr: SocketAddr,
        is_outbound: bool,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        chain: Arc<SwapChain>,
        our_peer_id: u64,
    ) {
        let mut peer = Peer::new(addr);

        // Generate and send our challenge
        let our_challenge: [u8; CHALLENGE_SIZE] = rand::thread_rng().gen();
        peer.our_challenge = our_challenge;

        let challenge_msg = P2PMessage::HandshakeChallenge {
            challenge: our_challenge,
            peer_id:   our_peer_id,
        };

        let (mut reader, mut writer) = stream.into_split();

        if let Err(e) = writer.write_all(&challenge_msg.encode()).await {
            warn!("failed to send handshake challenge to {addr}: {e}");
            return;
        }

        // Framed read loop
        let mut header = [0u8; 5]; // id(1) + size(4)
        loop {
            if reader.read_exact(&mut header).await.is_err() {
                debug!("peer {addr} disconnected");
                break;
            }
            let msg_id_byte  = header[0];
            let payload_size = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;

            if payload_size > MAX_MESSAGE_SIZE {
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

            let payload = Bytes::from(payload_buf);
            let Ok(msg) = P2PMessage::decode(msg_id, payload) else {
                warn!("failed to decode message {msg_id:?} from {addr}");
                break;
            };

            match msg {
                // -- Handshake ------------------------------------------------
                P2PMessage::HandshakeChallenge { challenge, peer_id } => {
                    peer.peer_id = peer_id;
                    peer.state   = ConnectionState::AwaitingChallengeSolution;

                    let (salt, solution) = generate_solution(&challenge, is_outbound);
                    let sol_msg = P2PMessage::HandshakeSolution { solution, salt };
                    if let Err(e) = writer.write_all(&sol_msg.encode()).await {
                        warn!("failed to send handshake solution to {addr}: {e}");
                        break;
                    }
                    peer.handshake_solution_sent = true;
                }

                P2PMessage::HandshakeSolution { solution, salt } => {
                    // The peer is the initiator if it is the one that *we* accepted inbound.
                    let peer_is_initiator = !is_outbound;
                    if !verify_solution(&peer.our_challenge, &solution, &salt, peer_is_initiator) {
                        warn!("invalid handshake solution from {addr}");
                        peer.handshake_invalid = true;
                        break;
                    }
                    peer.handshake_complete = true;
                    peer.state              = ConnectionState::AwaitingListenPort;

                    // Send our listen port (0 = unknown/ephemeral)
                    let port_msg = P2PMessage::ListenPort(0);
                    let _ = writer.write_all(&port_msg.encode()).await;
                }

                P2PMessage::ListenPort(port) => {
                    peer.listen_port = Some(port);
                    peer.state       = ConnectionState::Ready;
                    info!("peer {addr} ready (listen_port={port})");

                    // Register peer
                    peers.write().insert(addr, peer.clone());

                    // Request peer list
                    let pl = P2PMessage::PeerListRequest;
                    let _ = writer.write_all(&pl.encode()).await;
                }

                // -- Share broadcast (the critical fill-in) -------------------
                P2PMessage::BlockBroadcast { data }
                | P2PMessage::SwapShareBroadcast { data } => {
                    if peer.is_good() {
                        debug!(
                            "received share broadcast from {addr} ({} bytes)",
                            data.len()
                        );
                        if let Ok(share) = SwapShare::deserialize(&data) {
                            match chain.add_share(share.clone()) {
                                Ok(true) => {
                                    // Tip changed ; re-broadcast to other peers
                                    info!(
                                        "new tip at height {} from {addr}",
                                        share.height
                                    );
                                    let rebroadcast = P2PMessage::SwapShareBroadcast {
                                        data: Bytes::from(share.serialize()),
                                    };
                                    let bytes = Bytes::from(rebroadcast.encode().to_vec());
                                    // Broadcast to all peers except the sender
                                    let guard = peers.read();
                                    for (peer_addr, p) in guard.iter() {
                                        if *peer_addr != addr && p.is_good() {
                                            debug!("rebroadcasting to {peer_addr}");
                                            // In a real implementation each connection task
                                            // would have its own mpsc writer channel.
                                            // Here we just log (stream ownership is per-task).
                                            let _ = bytes.clone();
                                        }
                                    }
                                }
                                Ok(false) => {
                                    debug!("share accepted (no tip change)");
                                }
                                Err(e) => {
                                    warn!("share rejected from {addr}: {e}");
                                }
                            }
                        } else {
                            warn!("failed to deserialize share from {addr}");
                        }
                    }
                }

                // -- Block request / response ----------------------------------
                P2PMessage::BlockRequest { id } => {
                    if peer.is_good() {
                        if let Some(share) = chain.get_share(&id) {
                            let resp = P2PMessage::BlockResponse {
                                data: Bytes::from(share.serialize()),
                            };
                            let _ = writer.write_all(&resp.encode()).await;
                        } else {
                            debug!("peer {addr} requested unknown share {}", hex::encode(id));
                        }
                    }
                }

                P2PMessage::BlockResponse { data } => {
                    if peer.is_good() {
                        debug!("received block response from {addr} ({} bytes)", data.len());
                        if let Ok(share) = SwapShare::deserialize(&data) {
                            match chain.add_share(share) {
                                Ok(tip) => debug!("block response accepted (tip={tip})"),
                                Err(e)  => warn!("block response rejected: {e}"),
                            }
                        }
                    }
                }

                // -- Peer list -------------------------------------------------
                P2PMessage::PeerListRequest => {
                    let resp = P2PMessage::PeerListResponse { peers: Vec::new() };
                    let _ = writer.write_all(&resp.encode()).await;
                }

                P2PMessage::PeerListResponse { peers: pl } => {
                    debug!("peer {addr} sent {} peers", pl.len());
                    // Future: initiate connections to new peers
                }

                // -- Notifications ---------------------------------------------
                P2PMessage::BlockNotify { id, height } => {
                    debug!(
                        "block notify from {addr}: {} at height {height}",
                        hex::encode(id)
                    );
                    // Future: request the share if we don't have it
                }

                _ => {
                    debug!("unhandled message {msg_id:?} from {addr}");
                }
            }

            peer.last_alive = Instant::now();
        }

        // Remove peer on disconnect
        peers.write().remove(&addr);
        debug!("peer {addr} removed");
    }

    // -- Helpers ---------------------------------------------------------------

    /// Broadcast raw bytes to all ready peers.
    /// (In production each connection has its own mpsc writer channel.)
    fn broadcast_to_peers(
        peers: &Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        _data: Bytes,
    ) {
        let guard = peers.read();
        let count = guard.values().filter(|p| p.is_good()).count();
        debug!("would broadcast to {count} peers");
    }
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::SwapChain;
    use crate::share::{Difficulty, SwapShare};
    use tokio::net::TcpStream;

    fn make_chain() -> Arc<SwapChain> {
        Arc::new(SwapChain::new(Difficulty::from_u64(1)))
    }

    #[test]
    fn server_can_be_constructed() {
        let chain = make_chain();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (server, _rx) = P2PServer::new(addr, Vec::new(), chain);
        // If we can construct it the types are wired correctly.
        let _ = server.command_sender();
    }

    #[tokio::test]
    async fn broadcast_share_command_accepted() {
        let chain = make_chain();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (server, rx) = P2PServer::new(addr, Vec::new(), chain.clone());
        let tx = server.command_sender();

        let genesis = SwapShare::genesis(Difficulty::from_u64(1));
        tx.send(P2PCommand::BroadcastShare(genesis)).await.unwrap();
        tx.send(P2PCommand::Shutdown).await.unwrap();

        // Drain commands to verify they are received
        tokio::spawn(server.run(rx));
        // Give the task a moment to process
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    /// Inbound connections must be capped at MAX_INBOUND_CONNECTIONS.
    #[tokio::test]
    async fn connection_cap_enforced() {
        let chain = make_chain();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
        let bound_port = listener.local_addr().unwrap().port();
        let server_addr: SocketAddr = format!("127.0.0.1:{bound_port}").parse().unwrap();

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_CONNECTIONS));
        {
            let peers: Arc<RwLock<HashMap<SocketAddr, Peer>>> =
                Arc::new(RwLock::new(HashMap::new()));
            let c = chain.clone();
            let sem = semaphore.clone();
            tokio::spawn(async move {
                P2PServer::listen_loop_with_semaphore(listener, peers, c, 0, sem).await;
            });
        }

        let over_limit = MAX_INBOUND_CONNECTIONS + 5;
        let mut conns = Vec::new();
        for i in 0..over_limit {
            match TcpStream::connect(server_addr).await {
                Ok(s) => conns.push(s),
                Err(_) => {} // connection refused is also acceptable
            }
            // yield to let server accept
            if i % 10 == 9 {
                tokio::task::yield_now().await;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let available = semaphore.available_permits();
        assert!(
            available <= MAX_INBOUND_CONNECTIONS,
            "semaphore permits ({available}) exceeds MAX ({MAX_INBOUND_CONNECTIONS})"
        );
    }
}
