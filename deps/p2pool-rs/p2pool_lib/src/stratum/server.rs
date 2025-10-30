// P2Pool for Monero - Stratum TCP server
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only

use super::messages::{
    login_response, job_notification, parse_login, submit_error, submit_ok,
    LoginParams, StratumJob, StratumRequest, SubmitParams,
};
use super::session::{SavedJob, StratumSession};
use crate::block_template::BlockTemplateManager;
use p2pool_config::StratumConfig;
use p2pool_crypto::Hash;
use p2pool_monero::wallet::Wallet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Commands sent to the stratum server from the block-template builder.
#[derive(Clone)]
pub enum StratumCommand {
    /// A new block template is available; notify all connected miners.
    NewJob(Arc<StratumJob>),
    /// Shut down the server.
    Shutdown,
}

/// The Stratum TCP server.
pub struct StratumServer {
    config: StratumConfig,
    block_template: Arc<BlockTemplateManager>,
    /// Broadcast channel: new jobs are sent here, sessions subscribe.
    job_tx: broadcast::Sender<StratumCommand>,
    /// Atomic extra-nonce counter (each session gets a unique extra_nonce).
    extra_nonce: Arc<std::sync::atomic::AtomicU32>,
    /// Per-session RPC ID counter.
    rpc_id_counter: Arc<std::sync::atomic::AtomicU32>,
}

impl StratumServer {
    pub fn new(config: StratumConfig, block_template: Arc<BlockTemplateManager>) -> Self {
        let (job_tx, _) = broadcast::channel(16);
        Self {
            config,
            block_template,
            job_tx,
            extra_nonce: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            rpc_id_counter: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// Notify all connected miners of a new block template.
    pub fn on_new_block(&self, job: StratumJob) {
        let _ = self.job_tx.send(StratumCommand::NewJob(Arc::new(job)));
    }

    /// Run the stratum server event loop.
    pub async fn run(self) {
        let server = Arc::new(self);
        for addr_str in &server.config.listen_addresses {
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    let s = server.clone();
                    tokio::spawn(async move {
                        s.listen_loop(addr).await;
                    });
                }
                Err(e) => warn!("invalid stratum address {addr_str}: {e}"),
            }
        }
        // Block until shutdown (placeholder: real impl would use a channel)
        tokio::signal::ctrl_c().await.ok();
    }

    async fn listen_loop(self: Arc<Self>, addr: SocketAddr) {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => {
                info!("Stratum listening on {addr}");
                l
            }
            Err(e) => {
                tracing::error!("failed to bind stratum on {addr}: {e}");
                return;
            }
        };
        loop {
            match listener.accept().await {
                Ok((stream, remote)) => {
                    let s = self.clone();
                    tokio::spawn(async move {
                        s.handle_miner(stream, remote).await;
                    });
                }
                Err(e) => tracing::error!("stratum accept error: {e}"),
            }
        }
    }

    async fn handle_miner(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) {
        info!("stratum miner connected from {addr}");
        let rpc_id = self
            .rpc_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let extra_nonce = self
            .extra_nonce
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let session: Arc<Mutex<Option<StratumSession>>> = Arc::new(Mutex::new(None));
        let mut job_rx = self.job_tx.subscribe();

        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        loop {
            tokio::select! {
                line = lines.next_line() => {
                    match line {
                        Ok(Some(line)) if !line.is_empty() => {
                            let response = self.handle_line(&session, &line, rpc_id, extra_nonce);
                            if let Some(resp) = response {
                                let msg = format!("{}\n", resp);
                                if writer.write_all(msg.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                        }
                        _ => break,
                    }
                }
                Ok(cmd) = job_rx.recv() => {
                    match cmd {
                        StratumCommand::NewJob(job) => {
                            let has_session = session.lock().unwrap().is_some();
                            if has_session {
                                let notif = format!("{}\n", job_notification(&job));
                                if writer.write_all(notif.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                        }
                        StratumCommand::Shutdown => break,
                    }
                }
            }
        }

        info!("stratum miner {addr} disconnected");
    }

    fn handle_line(
        &self,
        session: &Arc<Mutex<Option<StratumSession>>>,
        line: &str,
        rpc_id: u32,
        extra_nonce: u32,
    ) -> Option<String> {
        let req: StratumRequest = serde_json::from_str(line).ok()?;
        let req_id = req.id.clone().unwrap_or(serde_json::Value::Null);

        match req.method.as_str() {
            "login" => {
                let params: LoginParams =
                    serde_json::from_value(req.params?).ok()?;
                let (address, fixed_diff) = parse_login(&params.login);

                // Validate wallet address
                if Wallet::decode(&address).is_err() {
                    debug!("invalid wallet address from miner: {address}");
                    return Some(submit_error(&req_id, "invalid wallet address"));
                }

                let new_session = StratumSession::new(rpc_id, address, fixed_diff);
                *session.lock().unwrap() = Some(new_session);

                // Build initial job from current block template
                let job = self.make_job(rpc_id, extra_nonce)?;
                Some(login_response(&req_id, &format!("{rpc_id:08x}"), &job))
            }
            "submit" => {
                let params: SubmitParams =
                    serde_json::from_value(req.params?).ok()?;
                let result = self.validate_submit(&session, &params);
                Some(match result {
                    Ok(()) => submit_ok(&req_id),
                    Err(e) => submit_error(&req_id, &e),
                })
            }
            "keepalived" => {
                Some(serde_json::json!({"id": req_id, "jsonrpc": "2.0", "result": {"status": "KEEPALIVED"}}).to_string())
            }
            _ => {
                debug!("unknown stratum method: {}", req.method);
                None
            }
        }
    }

    fn make_job(&self, session_rpc_id: u32, extra_nonce: u32) -> Option<StratumJob> {
        self.block_template.make_stratum_job(session_rpc_id, extra_nonce)
    }

    fn validate_submit(
        &self,
        session: &Arc<Mutex<Option<StratumSession>>>,
        params: &SubmitParams,
    ) -> Result<(), String> {
        let guard = session.lock().unwrap();
        let sess = guard.as_ref().ok_or("not logged in")?;

        let job_id = u32::from_str_radix(&params.job_id, 16)
            .map_err(|_| "invalid job_id".to_string())?;

        let saved_job = sess.find_job(job_id).ok_or("job not found")?;

        // Parse nonce (8 hex chars = 4 bytes LE)
        let nonce_bytes = hex::decode(&params.nonce).map_err(|_| "invalid nonce hex")?;
        if nonce_bytes.len() != 4 {
            return Err("nonce must be 4 bytes".to_string());
        }
        let nonce = u32::from_le_bytes(nonce_bytes.try_into().unwrap());

        // Parse result hash (64 hex chars = 32 bytes)
        let result_bytes = hex::decode(&params.result).map_err(|_| "invalid result hex")?;
        if result_bytes.len() != 32 {
            return Err("result must be 32 bytes".to_string());
        }
        let pow_hash = Hash::from_bytes(&result_bytes).ok_or("invalid result")?;

        // Check PoW meets session difficulty
        if !sess.current_difficulty.check_pow(&pow_hash) {
            return Err("low difficulty share".to_string());
        }

        // TODO: check against actual RandomX result (requires hasher integration)
        // TODO: if meets sidechain difficulty, call sidechain.submit_share(...)
        // TODO: if meets mainchain difficulty, submit to monerod

        debug!(
            "valid share from {} nonce={nonce:#010x} pow={}",
            sess.address, pow_hash
        );
        Ok(())
    }
}
