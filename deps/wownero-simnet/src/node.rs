use std::collections::{HashMap, HashSet};
use std::ops::RangeBounds;
use std::sync::Arc;

use curve25519_dalek::{EdwardsPoint, Scalar};
use tempfile::TempDir;
use tower::{util::MapErr, Service, ServiceExt};
use zeroize::Zeroizing;

use monero_oxide::transaction::{Input, Transaction as ConsensusTransaction};
use wownero_oxide::{
    io::VarInt,
    transaction::{
        Pruned, Timelock as WowneroTimelock, Transaction as WowneroTransaction,
        TransactionPrefix as WowneroTransactionPrefix,
    },
};
use wownero_wallet::{
    interface::{EvaluateUnlocked, InterfaceError, ScannableBlock, TransactionsError},
    Scanner, ViewPair, WalletOutput,
};

use cuprate_blockchain::{
    config::ConfigBuilder,
    cuprate_database::RuntimeError,
    service::{BlockchainReadHandle, BlockchainWriteHandle},
};
use cuprate_consensus::{generate_genesis_block, initialize_blockchain_context};
use cuprate_consensus_context::BlockchainContextService;
use cuprate_types::{
    blockchain::{BlockchainReadRequest, BlockchainResponse, BlockchainWriteRequest},
    Chain, HardFork, VerifiedBlockInformation,
};

use cuprate_consensus_context::BlockchainContext;
use cuprate_types::VerifiedTransactionInformation;

use crate::{
    config::WowSimnetConfig,
    error::SimnetError,
    miner::{commit_block, mine_one_block, mine_one_block_to_pubkeys},
    wallet::WOW_SPENDABLE_AGE,
};

/// A transaction waiting to be included in the next mined block.
#[derive(Clone)]
pub struct PendingTx {
    pub tx: ConsensusTransaction,
    pub consensus_tx_blob: Vec<u8>,
    pub rpc_tx_blob: Vec<u8>,
    pub tx_hash: [u8; 32],
}

fn tx_uses_scaled_decoy_commitments(tx_blob: &[u8]) -> Result<bool, String> {
    let tx = WowneroTransaction::<Pruned>::read(&mut tx_blob.as_ref())
        .map_err(|e| format!("failed to parse Wownero tx blob: {e}"))?;
    Ok(matches!(
        tx,
        WowneroTransaction::V2 {
            proofs: Some(ref proofs),
            ..
        } if proofs.rct_type == wownero_oxide::ringct::RctType::WowneroClsagBulletproofPlus
    ))
}

fn normalize_wallet_decoy_commitment_bytes(
    stored_commitment: [u8; 32],
    tx_blob: Option<&[u8]>,
) -> Result<[u8; 32], String> {
    let Some(tx_blob) = tx_blob else {
        return Ok(stored_commitment);
    };

    if !tx_uses_scaled_decoy_commitments(tx_blob)? {
        return Ok(stored_commitment);
    }

    let point = curve25519_dalek::edwards::CompressedEdwardsY(stored_commitment)
        .decompress()
        .ok_or_else(|| "invalid stored WOW type-8 commitment".to_string())?;
    Ok(point.mul_by_cofactor().compress().to_bytes())
}

fn map_db_err(e: RuntimeError) -> tower::BoxError {
    e.into()
}

type ConsensusReadHandle = MapErr<BlockchainReadHandle, fn(RuntimeError) -> tower::BoxError>;

/// In-process Wownero simulation node.
///
/// Manages a cuprate blockchain database, consensus context, and mempool.
/// Uses WOW consensus parameters: 4-block coinbase lock, ring size 22.
pub struct WowSimnetNode {
    pub(crate) config: WowSimnetConfig,
    pub(crate) read_handle: BlockchainReadHandle,
    pub(crate) write_handle: BlockchainWriteHandle,
    pub(crate) context_svc: BlockchainContextService,
    /// Transactions waiting to be mined into the next block.
    pub(crate) mempool: Vec<PendingTx>,
    /// Cumulative RingCT output count at each block height.
    /// rct_counts[h] = total global RCT outputs committed through block h inclusive.
    /// rct_counts[0] = 0 (genesis is a v1 tx with no RingCT outputs).
    rct_counts: Vec<u64>,
    /// Key images that have been spent in confirmed blocks.
    /// Used to reject double-spend attempts in `submit_tx`.
    spent_key_images: HashSet<[u8; 32]>,
    /// Raw transaction blobs for transactions this node mined itself.
    /// Used to rebuild `ScannableBlock` without relying on Cuprate's unfinished
    /// `BlockchainReadRequest::Transactions` implementation.
    confirmed_txs: HashMap<[u8; 32], Vec<u8>>,
    _env: Arc<cuprate_blockchain::cuprate_database::ConcreteEnv>,
    _tmp: TempDir,
}

impl WowSimnetNode {
    pub async fn start() -> Result<Self, SimnetError> {
        Self::start_with_config(WowSimnetConfig::default()).await
    }

    pub async fn start_with_config(config: WowSimnetConfig) -> Result<Self, SimnetError> {
        let tmp = TempDir::new()?;

        let db_config = ConfigBuilder::new()
            .data_directory(tmp.path().to_owned())
            .build();

        let (mut read_handle, mut write_handle, env) = cuprate_blockchain::service::init(db_config)
            .map_err(|e| SimnetError::Consensus(e.into()))?;

        if read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::ChainHeight)
            .await
            .is_err()
        {
            // WOW simnet genesis: cuprate's generate_genesis_block only supports
            // Monero networks, but the simnet genesis is never validated against
            // real network state. We use Mainnet genesis as a structural template;
            // the block format is identical between Monero and Wownero.
            let genesis = generate_genesis_block(config.network);
            let genesis_reward = genesis
                .miner_transaction()
                .prefix()
                .outputs
                .first()
                .and_then(|o| o.amount)
                .unwrap_or(0);
            let genesis_weight = genesis.miner_transaction().weight();

            write_handle
                .ready()
                .await?
                .call(BlockchainWriteRequest::WriteBlock(
                    VerifiedBlockInformation {
                        block_blob: genesis.serialize(),
                        txs: vec![],
                        block_hash: genesis.hash(),
                        pow_hash: [0u8; 32],
                        height: 0,
                        generated_coins: genesis_reward,
                        weight: genesis_weight,
                        long_term_weight: genesis_weight,
                        cumulative_difficulty: 1,
                        block: genesis,
                    },
                ))
                .await?;
        }

        let consensus_read: ConsensusReadHandle =
            read_handle.clone().map_err(map_db_err as fn(_) -> _);

        let context_svc = initialize_blockchain_context(config.context_config(), consensus_read)
            .await
            .map_err(|e| SimnetError::Consensus(e.into()))?;

        Ok(Self {
            config,
            read_handle,
            write_handle,
            context_svc,
            mempool: Vec::new(),
            rct_counts: vec![0],
            spent_key_images: HashSet::new(),
            confirmed_txs: HashMap::new(),
            _env: env,
            _tmp: tmp,
        })
    }

    /// Convert `PendingTx` entries into `VerifiedTransactionInformation` for block inclusion.
    pub fn pending_to_verified(pending: Vec<PendingTx>) -> Vec<VerifiedTransactionInformation> {
        pending
            .into_iter()
            .map(|p| {
                let tx_weight = p.tx.weight();
                VerifiedTransactionInformation {
                    tx: p.tx,
                    tx_blob: p.consensus_tx_blob,
                    tx_weight,
                    fee: 0,
                    tx_hash: p.tx_hash,
                }
            })
            .collect()
    }

    /// Mine `n` blocks with coinbase outputs paid to a random, un-scannable key.
    /// Any pending mempool transactions are included in each block mined.
    pub async fn mine_blocks(&mut self, n: u64) -> Result<u64, SimnetError> {
        let mut height = 0usize;
        for _ in 0..n {
            let pending = self.drain_mempool();
            self.confirm_pending(&pending);
            let txs = Self::pending_to_verified(pending.clone());
            height =
                mine_one_block(&mut self.write_handle, &mut self.context_svc, None, txs).await?;
            self.record_confirmed(&pending);
            self.push_rct_count().await?;
        }
        Ok(height as u64)
    }

    /// Mine `n` blocks with coinbase outputs scannable by the given wallet.
    ///
    /// Any `Scanner` built from the matching `ViewPair` will detect these outputs.
    /// Any pending mempool transactions are included in each block mined.
    pub async fn mine_to(
        &mut self,
        spend_pub: &EdwardsPoint,
        view_scalar: &Scalar,
        n: u64,
    ) -> Result<u64, SimnetError> {
        let mut height = 0usize;
        for _ in 0..n {
            let pending = self.drain_mempool();
            self.confirm_pending(&pending);
            let txs = Self::pending_to_verified(pending.clone());
            height = mine_one_block(
                &mut self.write_handle,
                &mut self.context_svc,
                Some((spend_pub, view_scalar)),
                txs,
            )
            .await?;
            self.record_confirmed(&pending);
            self.push_rct_count().await?;
        }
        Ok(height as u64)
    }

    /// Mine `n` blocks with coinbase outputs payable to the given wallet address
    /// (public spend key + public view key). The wallet's scanner can detect
    /// these outputs using its private view scalar.
    pub async fn mine_to_pubkeys(
        &mut self,
        spend_pub: &EdwardsPoint,
        view_pub: &EdwardsPoint,
        n: u64,
    ) -> Result<u64, SimnetError> {
        let mut height = 0usize;
        for _ in 0..n {
            let pending = self.drain_mempool();
            self.confirm_pending(&pending);
            let txs = Self::pending_to_verified(pending.clone());
            height = mine_one_block_to_pubkeys(
                &mut self.write_handle,
                &mut self.context_svc,
                spend_pub,
                view_pub,
                txs,
            )
            .await?;
            self.record_confirmed(&pending);
            self.push_rct_count().await?;
        }
        Ok(height as u64)
    }

    /// Push the current total_rct_outputs count onto rct_counts.
    /// Called after every block commit to keep the index up-to-date.
    pub(crate) async fn push_rct_count(&mut self) -> Result<(), SimnetError> {
        let n = self.total_rct_outputs().await?;
        self.rct_counts.push(n);
        Ok(())
    }

    fn record_confirmed(&mut self, pending: &[PendingTx]) {
        for tx in pending {
            self.confirmed_txs
                .insert(tx.tx_hash, tx.rpc_tx_blob.clone());
        }
    }

    /// Read the block at `height` from the DB and wrap it in a `ScannableBlock`.
    pub async fn scannable_block_at(
        &mut self,
        height: usize,
    ) -> Result<ScannableBlock, SimnetError> {
        let BlockchainResponse::Block(block) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::Block { height })
            .await?
        else {
            return Err(SimnetError::Consensus("wrong response to Block".into()));
        };

        // Fetch non-coinbase transactions if any.
        let tx_hashes: Vec<[u8; 32]> = block.transactions.clone();
        let transactions = if tx_hashes.is_empty() {
            vec![]
        } else {
            let tx_records = self.transactions(tx_hashes).await?;
            let mut txs = Vec::with_capacity(tx_records.len());
            for t in tx_records {
                let tx = WowneroTransaction::<Pruned>::read(&mut t.tx_blob.as_slice())
                    .map_err(|e| SimnetError::Consensus(format!("tx deserialize: {e}").into()))?;
                txs.push(tx);
            }
            txs
        };

        let block = {
            let block_blob = block.serialize();
            wownero_oxide::block::Block::read(&mut block_blob.as_slice())
                .map_err(|e| SimnetError::Consensus(format!("block deserialize: {e}").into()))?
        };

        // Genesis (height 0) is a v1 tx -- no RingCT outputs.
        // For block h >= 1: the first RingCT output in that block starts at the
        // cumulative count recorded after block h-1 (i.e. rct_counts[h-1]).
        let output_index = if height == 0 {
            None
        } else {
            self.rct_counts.get(height - 1).copied()
        };

        Ok(ScannableBlock {
            block,
            transactions,
            output_index_for_first_ringct_output: output_index,
        })
    }

    /// Scan the block at `height` for outputs belonging to `scanner`.
    ///
    /// Returns all found outputs, including coinbase outputs still subject to
    /// the 4-block lock (the caller must check maturity if needed).
    pub async fn scan_block_at(
        &mut self,
        height: usize,
        scanner: &mut Scanner,
    ) -> Result<Vec<WalletOutput>, SimnetError> {
        let scannable = self.scannable_block_at(height).await?;
        let timelocked = scanner
            .scan(scannable)
            .map_err(|e| SimnetError::Consensus(format!("scan error: {e}").into()))?;
        Ok(timelocked.ignore_additional_timelock())
    }

    pub async fn height(&mut self) -> Result<u64, SimnetError> {
        let BlockchainResponse::ChainHeight(h, _) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::ChainHeight)
            .await?
        else {
            return Err(SimnetError::Consensus(
                "wrong response to ChainHeight".into(),
            ));
        };
        Ok(h as u64)
    }

    /// Returns (chain_height, top_block_hash).
    pub async fn chain_height(&mut self) -> Result<(u64, [u8; 32]), SimnetError> {
        let BlockchainResponse::ChainHeight(h, hash) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::ChainHeight)
            .await?
        else {
            return Err(SimnetError::Consensus(
                "wrong response to ChainHeight".into(),
            ));
        };
        Ok((h as u64, hash))
    }

    /// Raw block blob (serialized) at height (main chain).
    pub async fn block_blob_at(&mut self, height: usize) -> Result<Vec<u8>, SimnetError> {
        let BlockchainResponse::Block(block) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::Block { height })
            .await?
        else {
            return Err(SimnetError::Consensus("wrong response to Block".into()));
        };
        Ok(block.serialize())
    }

    /// Raw block blob (serialized) by block hash.
    pub async fn block_blob_by_hash(&mut self, hash: [u8; 32]) -> Result<Vec<u8>, SimnetError> {
        let BlockchainResponse::Block(block) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::BlockByHash(hash))
            .await?
        else {
            return Err(SimnetError::Consensus(
                "wrong response to BlockByHash".into(),
            ));
        };
        Ok(block.serialize())
    }

    /// Block hash at height (main chain).
    pub async fn block_hash_at(&mut self, height: usize) -> Result<[u8; 32], SimnetError> {
        let BlockchainResponse::BlockHash(hash) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::BlockHash(height, Chain::Main))
            .await?
        else {
            return Err(SimnetError::Consensus("wrong response to BlockHash".into()));
        };
        Ok(hash)
    }

    /// Extended header for a block at the given height.
    pub async fn block_extended_header(
        &mut self,
        height: usize,
    ) -> Result<cuprate_types::ExtendedBlockHeader, SimnetError> {
        let BlockchainResponse::BlockExtendedHeader(hdr) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::BlockExtendedHeader(height))
            .await?
        else {
            return Err(SimnetError::Consensus(
                "wrong response to BlockExtendedHeader".into(),
            ));
        };
        Ok(hdr)
    }

    /// Total RCT (amount=0) outputs in the blockchain.
    pub async fn total_rct_outputs(&mut self) -> Result<u64, SimnetError> {
        let BlockchainResponse::TotalRctOutputs(n) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::TotalRctOutputs)
            .await?
        else {
            return Err(SimnetError::Consensus(
                "wrong response to TotalRctOutputs".into(),
            ));
        };
        Ok(n)
    }

    /// Fetch RCT outputs by global index. Returns `(global_index, OutputOnChain)` pairs.
    pub async fn rct_outputs_at_indexes(
        &mut self,
        indexes: Vec<u64>,
    ) -> Result<Vec<(u64, cuprate_types::OutputOnChain)>, SimnetError> {
        let outputs_vec: Vec<(u64, u64)> = indexes.iter().map(|&i| (0u64, i)).collect();
        let BlockchainResponse::OutputsVec(resp) = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::OutputsVec {
                outputs: outputs_vec,
                get_txid: true,
            })
            .await?
        else {
            return Err(SimnetError::Consensus(
                "wrong response to OutputsVec".into(),
            ));
        };
        let mut result = Vec::new();
        for (_, outs) in resp {
            for (idx, out) in outs {
                result.push((idx, out));
            }
        }
        Ok(result)
    }

    /// Fetch transactions by hash from the blockchain.
    pub async fn transactions(
        &mut self,
        hashes: Vec<[u8; 32]>,
    ) -> Result<Vec<cuprate_types::TxInBlockchain>, SimnetError> {
        let mut ordered = Vec::with_capacity(hashes.len());
        let mut missing = Vec::new();

        for hash in &hashes {
            if let Some(tx_blob) = self.confirmed_txs.get(hash) {
                ordered.push(cuprate_types::TxInBlockchain {
                    block_height: 0,
                    block_timestamp: 0,
                    confirmations: 0,
                    output_indices: vec![],
                    tx_hash: *hash,
                    tx_blob: tx_blob.clone(),
                    pruned_blob: vec![],
                    prunable_blob: vec![],
                    prunable_hash: [0; 32],
                });
            } else {
                missing.push(*hash);
            }
        }

        if missing.is_empty() {
            return Ok(ordered);
        }

        let hash_set: HashSet<[u8; 32]> = missing.iter().copied().collect();
        let BlockchainResponse::Transactions { txs, missed_txs: _ } = self
            .read_handle
            .ready()
            .await?
            .call(BlockchainReadRequest::Transactions {
                tx_hashes: hash_set,
            })
            .await?
        else {
            return Err(SimnetError::Consensus(
                "wrong response to Transactions".into(),
            ));
        };

        let fetched: HashMap<[u8; 32], cuprate_types::TxInBlockchain> =
            txs.into_iter().map(|tx| (tx.tx_hash, tx)).collect();

        let mut merged = Vec::with_capacity(hashes.len());
        for hash in hashes {
            if let Some(tx_blob) = self.confirmed_txs.get(&hash) {
                merged.push(cuprate_types::TxInBlockchain {
                    block_height: 0,
                    block_timestamp: 0,
                    confirmations: 0,
                    output_indices: vec![],
                    tx_hash: hash,
                    tx_blob: tx_blob.clone(),
                    pruned_blob: vec![],
                    prunable_blob: vec![],
                    prunable_hash: [0; 32],
                });
            } else if let Some(tx) = fetched.get(&hash) {
                merged.push(tx.clone());
            } else {
                return Err(SimnetError::Consensus(
                    format!("missing transaction {hash:02x?}").into(),
                ));
            }
        }
        Ok(merged)
    }

    pub(crate) fn normalized_wallet_decoy_commitment_bytes(
        &self,
        out: &cuprate_types::OutputOnChain,
    ) -> Result<[u8; 32], SimnetError> {
        let tx_blob = out
            .txid
            .and_then(|txid| self.confirmed_txs.get(&txid).map(Vec::as_slice));
        normalize_wallet_decoy_commitment_bytes(out.commitment.to_bytes(), tx_blob)
            .map_err(|e| SimnetError::Consensus(e.into()))
    }

    /// Return the cumulative RingCT output distribution for an inclusive height range.
    pub fn rct_output_distribution_range(&self, from_height: u64, to_height: u64) -> Vec<u64> {
        let last = self.rct_counts.last().copied().unwrap_or(0);
        (from_height..=to_height)
            .map(|height| {
                self.rct_counts
                    .get(height as usize)
                    .copied()
                    .unwrap_or(last)
            })
            .collect()
    }

    /// Extract all key images from a transaction's inputs (skips `Input::Gen`).
    fn extract_key_images(tx: &ConsensusTransaction) -> Vec<[u8; 32]> {
        tx.prefix()
            .inputs
            .iter()
            .filter_map(|input| {
                if let Input::ToKey { key_image, .. } = input {
                    Some(key_image.to_bytes())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Mark all key images in `pending` as spent in the confirmed set.
    /// Called after each block is mined so that subsequent `submit_tx` calls
    /// can detect double-spends against already-confirmed key images.
    fn confirm_pending(&mut self, pending: &[PendingTx]) {
        for ptx in pending {
            for ki in Self::extract_key_images(&ptx.tx) {
                self.spent_key_images.insert(ki);
            }
        }
    }

    /// Return daemon-style spent-status codes for the supplied key images.
    ///
    /// `0` = unspent, `1` = spent on-chain, `2` = spent in the mempool.
    pub fn key_image_spent_statuses(&self, key_images: &[[u8; 32]]) -> Vec<u64> {
        key_images
            .iter()
            .map(|key_image| {
                if self.spent_key_images.contains(key_image) {
                    1
                } else if self
                    .mempool
                    .iter()
                    .flat_map(|pending| Self::extract_key_images(&pending.tx))
                    .any(|pending_key_image| pending_key_image == *key_image)
                {
                    2
                } else {
                    0
                }
            })
            .collect()
    }

    fn consensus_tx_from_rpc_blob(
        tx_blob: &[u8],
    ) -> Result<(ConsensusTransaction, Vec<u8>), SimnetError> {
        let mut reader = tx_blob;
        let version = VarInt::read(&mut reader)
            .map_err(|e| SimnetError::Consensus(format!("invalid tx version: {e}").into()))?;
        if version != 2 {
            let tx = ConsensusTransaction::read(&mut tx_blob.as_ref())
                .map_err(|e| SimnetError::Consensus(format!("invalid tx: {e}").into()))?;
            return Ok((tx, tx_blob.to_vec()));
        }

        WowneroTransactionPrefix::read(&mut reader, version)
            .map_err(|e| SimnetError::Consensus(format!("invalid tx prefix: {e}").into()))?;

        let type_offset = tx_blob.len().saturating_sub(reader.len());
        let mut consensus_blob = tx_blob.to_vec();
        if consensus_blob.get(type_offset) == Some(&8) {
            consensus_blob[type_offset] = 6;
        }

        let tx = ConsensusTransaction::read(&mut consensus_blob.as_slice())
            .map_err(|e| SimnetError::Consensus(format!("invalid tx: {e}").into()))?;
        Ok((tx, consensus_blob))
    }

    /// Submit a raw transaction blob to the mempool. Returns the tx hash.
    ///
    /// Returns [`SimnetError::DoubleSpend`] if any key image in the transaction
    /// has already been spent in a confirmed block or is already in the mempool.
    pub fn submit_tx(&mut self, tx_blob: Vec<u8>) -> Result<[u8; 32], SimnetError> {
        let wow_tx = WowneroTransaction::read(&mut tx_blob.as_slice())
            .map_err(|e| SimnetError::Consensus(format!("invalid tx: {e}").into()))?;
        let (tx, consensus_tx_blob) = Self::consensus_tx_from_rpc_blob(&tx_blob)?;
        let current_height = self.context_svc.blockchain_context().chain_height;

        match wow_tx.prefix().additional_timelock {
            WowneroTimelock::None => {}
            WowneroTimelock::Block(height) if height <= current_height => {}
            WowneroTimelock::Block(height) => {
                return Err(SimnetError::Consensus(
                    format!(
                        "transaction unlock_time {} not yet satisfied at height {}",
                        height, current_height
                    )
                    .into(),
                ));
            }
            WowneroTimelock::Time(time) => {
                return Err(SimnetError::Consensus(
                    format!("time-based unlock_time {} not supported by simnet", time).into(),
                ));
            }
        }

        // Collect key images from the incoming tx.
        let key_images = Self::extract_key_images(&tx);

        // Check against confirmed spent key images.
        for ki in &key_images {
            if self.spent_key_images.contains(ki) {
                return Err(SimnetError::DoubleSpend(hex::encode(ki)));
            }
        }

        // Check against mempool key images (prevent mempool double-spend).
        for pending in &self.mempool {
            for mempool_ki in Self::extract_key_images(&pending.tx) {
                if key_images.contains(&mempool_ki) {
                    return Err(SimnetError::DoubleSpend(hex::encode(mempool_ki)));
                }
            }
        }

        let tx_hash = wow_tx.hash();
        self.mempool.push(PendingTx {
            tx,
            consensus_tx_blob,
            rpc_tx_blob: tx_blob,
            tx_hash,
        });
        Ok(tx_hash)
    }

    /// Drain all pending transactions from the mempool.
    pub fn drain_mempool(&mut self) -> Vec<PendingTx> {
        std::mem::take(&mut self.mempool)
    }

    /// The active hard-fork at the current chain tip.
    pub fn current_hf(&mut self) -> HardFork {
        self.context_svc.blockchain_context().current_hf
    }

    /// Cumulative difficulty of the current chain tip.
    ///
    /// Each simnet block adds exactly 1, so this equals `height()` and is a
    /// direct proxy for chain work -- useful for asserting reorg outcomes.
    pub fn cumulative_difficulty(&mut self) -> u128 {
        self.context_svc.blockchain_context().cumulative_difficulty
    }

    pub fn read_handle(&self) -> BlockchainReadHandle {
        self.read_handle.clone()
    }

    pub fn config(&self) -> &WowSimnetConfig {
        &self.config
    }

    /// Return a snapshot of the current blockchain context (tip hash, height, HF, etc.).
    pub fn blockchain_context(&mut self) -> BlockchainContext {
        self.context_svc.blockchain_context().clone()
    }

    /// Commit a pre-built `VerifiedBlockInformation` to the chain and advance the context.
    /// PoW is NOT checked; set `vbi.pow_hash = [0u8; 32]` for the simnet.
    pub async fn commit(&mut self, vbi: VerifiedBlockInformation) -> Result<u64, SimnetError> {
        let height = commit_block(vbi, &mut self.write_handle, &mut self.context_svc).await? as u64;
        self.push_rct_count().await?;
        Ok(height)
    }

    /// Convenience: build a `Scanner` from raw key bytes.
    pub fn make_scanner(
        spend_pub: EdwardsPoint,
        view_scalar: Zeroizing<Scalar>,
    ) -> Result<Scanner, SimnetError> {
        let vp = ViewPair::new(
            wownero_oxide::ed25519::Point::from(spend_pub),
            Zeroizing::new(wownero_oxide::ed25519::Scalar::from(*view_scalar)),
        )
        .map_err(|e| SimnetError::Consensus(format!("ViewPair error: {e}").into()))?;
        Ok(Scanner::new(vp))
    }

    /// Create a `WowSimnetDecoyRpc` that provides the wallet decoy-selection traits for this node.
    ///
    /// The `WowSimnetDecoyRpc` wraps a clone of the read handle so it does not
    /// require mutable access, matching the `&self` requirement of the wallet
    /// interface traits.
    pub fn decoy_rpc(&self) -> WowSimnetDecoyRpc {
        WowSimnetDecoyRpc {
            read_handle: self.read_handle.clone(),
            confirmed_txs: Arc::new(self.confirmed_txs.clone()),
            rct_counts: Arc::new(self.rct_counts.clone()),
        }
    }
}

// ---- Decoy-selection adapter ------------------------------------------------
//
// `ProvidesDecoys` is the trait used by `OutputWithDecoys::new` to select
// rings for spending. We implement the unvalidated variant directly against
// the cuprate blockchain read handle, bypassing the HTTP server entirely.
//
// WOW simnet-specific simplifications
// ------------------------------------
// * Every non-genesis block contributes exactly ONE RingCT coinbase output.
// * The genesis block contributes zero RingCT outputs.
// * Therefore the cumulative distribution at block `h` equals `h`.
//   (block 0 -> 0, block 1 -> 1, ..., block k -> k)
// * All coinbase outputs carry a 4-block additional timelock (WOW_SPENDABLE_AGE).

/// Implements the wallet decoy-selection traits directly against a cuprate
/// blockchain read handle.
///
/// Obtain one via [`WowSimnetNode::decoy_rpc`].
#[derive(Clone)]
pub struct WowSimnetDecoyRpc {
    read_handle: BlockchainReadHandle,
    confirmed_txs: Arc<HashMap<[u8; 32], Vec<u8>>>,
    /// Snapshot of rct_counts at the time of creation, used to distinguish
    /// coinbase outputs (4-block lock for WOW) from non-coinbase outputs.
    rct_counts: Arc<Vec<u64>>,
}

impl WowSimnetDecoyRpc {
    /// Fetch the latest block number from the blockchain read handle.
    async fn latest_block_number_inner(
        mut read_handle: BlockchainReadHandle,
    ) -> Result<usize, InterfaceError> {
        let resp = read_handle
            .ready()
            .await
            .map_err(|e| InterfaceError::InternalError(e.to_string()))?
            .call(BlockchainReadRequest::ChainHeight)
            .await
            .map_err(|e| InterfaceError::InternalError(e.to_string()))?;

        match resp {
            BlockchainResponse::ChainHeight(h, _) => Ok(h.saturating_sub(1)),
            _ => Err(InterfaceError::InternalError(
                "wrong response to ChainHeight".into(),
            )),
        }
    }

    fn normalized_wallet_decoy_commitment_bytes(
        &self,
        out: &cuprate_types::OutputOnChain,
    ) -> Result<[u8; 32], InterfaceError> {
        let tx_blob = out
            .txid
            .and_then(|txid| self.confirmed_txs.get(&txid).map(Vec::as_slice));
        normalize_wallet_decoy_commitment_bytes(out.commitment.to_bytes(), tx_blob)
            .map_err(InterfaceError::InvalidInterface)
    }
}

// The wallet interface requires `&self` (shared reference), but cuprate's read handle
// uses `&mut self` (poll/call pattern).  We clone the handle per call, which
// is cheap (Arc-backed clone).
impl wownero_wallet::interface::ProvidesBlockchainMeta for WowSimnetDecoyRpc {
    fn latest_block_number(
        &self,
    ) -> impl Send + std::future::Future<Output = Result<usize, InterfaceError>> {
        let rh = self.read_handle.clone();
        async move { Self::latest_block_number_inner(rh).await }
    }
}

impl wownero_wallet::interface::ProvidesUnvalidatedDecoys for WowSimnetDecoyRpc {
    /// Return the cumulative RingCT output count for each block in `range`.
    fn ringct_output_distribution(
        &self,
        range: impl Send + RangeBounds<usize>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u64>, InterfaceError>> {
        let rh = self.read_handle.clone();
        let rct_counts = self.rct_counts.clone();
        async move {
            let latest_block_number = Self::latest_block_number_inner(rh).await?;

            // Resolve the inclusive bounds.
            let from = match range.start_bound() {
                std::ops::Bound::Included(&f) => f,
                std::ops::Bound::Excluded(&f) => f.saturating_add(1),
                std::ops::Bound::Unbounded => 0,
            };
            let to = match range.end_bound() {
                std::ops::Bound::Included(&t) => t,
                std::ops::Bound::Excluded(&t) => t.saturating_sub(1),
                std::ops::Bound::Unbounded => latest_block_number,
            };

            if from > to {
                return Err(InterfaceError::InternalError(format!(
                    "empty range from={from} to={to}"
                )));
            }

            // Use rct_counts for the real cumulative distribution.
            let dist: Vec<u64> = (from..=to)
                .map(|h| {
                    rct_counts
                        .get(h)
                        .copied()
                        .unwrap_or_else(|| rct_counts.last().copied().unwrap_or(0))
                })
                .collect();
            Ok(dist)
        }
    }

    /// Return unlocked output key+commitment pairs, or `None` for each locked output.
    ///
    /// WOW uses a 4-block coinbase lock (`WOW_SPENDABLE_AGE`) instead of Monero's 60.
    fn unlocked_ringct_outputs(
        &self,
        indexes: &[u64],
        evaluate_unlocked: EvaluateUnlocked,
    ) -> impl Send
           + std::future::Future<
        Output = Result<Vec<Option<[wownero_oxide::ed25519::Point; 2]>>, TransactionsError>,
    > {
        let mut rh = self.read_handle.clone();
        let rct_counts = self.rct_counts.clone();
        let indexes = indexes.to_vec();
        async move {
            let mut outputs_req = indexmap::IndexMap::<u64, indexmap::IndexSet<u64>>::new();
            let index_set: indexmap::IndexSet<u64> = indexes.iter().copied().collect();
            outputs_req.insert(0u64, index_set);

            let resp = rh
                .ready()
                .await
                .map_err(|e| InterfaceError::InternalError(e.to_string()))?
                .call(BlockchainReadRequest::Outputs {
                    outputs: outputs_req,
                    get_txid: true,
                })
                .await
                .map_err(|e| InterfaceError::InternalError(e.to_string()))?;

            let BlockchainResponse::Outputs(cache) = resp else {
                return Err(
                    InterfaceError::InternalError("wrong response to Outputs".into()).into(),
                );
            };

            let evaluation_height = match evaluate_unlocked {
                EvaluateUnlocked::Normal => Self::latest_block_number_inner(rh.clone())
                    .await?
                    .saturating_add(1),
                EvaluateUnlocked::FingerprintableDeterministic { block_number } => {
                    block_number.saturating_add(1)
                }
            };

            // Build a set of global indices that are coinbase outputs.
            let coinbase_indices: std::collections::HashSet<u64> =
                (1..rct_counts.len()).map(|h| rct_counts[h - 1]).collect();

            indexes
                .iter()
                .map(|&global_idx| {
                    let out = cache.get_output(0u64, global_idx).ok_or_else(|| {
                        InterfaceError::InternalError(format!(
                            "output index {global_idx} not found"
                        ))
                    })?;
                    let is_coinbase = coinbase_indices.contains(&global_idx);
                    let locked_until = if is_coinbase {
                        out.height + WOW_SPENDABLE_AGE
                    } else {
                        out.height
                    };
                    if locked_until > evaluation_height {
                        return Ok(None);
                    }

                    let Some(key) =
                        wownero_oxide::ed25519::CompressedPoint::from(out.key.to_bytes())
                            .decompress()
                    else {
                        return Ok(None);
                    };
                    let commitment_bytes = self.normalized_wallet_decoy_commitment_bytes(out)?;
                    let commitment =
                        wownero_oxide::ed25519::CompressedPoint::from(commitment_bytes)
                            .decompress()
                            .ok_or_else(|| {
                                InterfaceError::InvalidInterface(format!(
                                    "output {global_idx} has invalid commitment point"
                                ))
                            })?;
                    Ok(Some([key, commitment]))
                })
                .collect()
        }
    }
}
