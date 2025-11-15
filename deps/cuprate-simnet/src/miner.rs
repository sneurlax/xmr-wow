use std::time::{SystemTime, UNIX_EPOCH};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, EdwardsPoint, Scalar};
use rand::rngs::OsRng;

use monero_oxide::{
    block::{Block, BlockHeader},
    ed25519::CompressedPoint,
    primitives::keccak256,
    transaction::{Input, Output, Timelock, Transaction, TransactionPrefix},
};
use monero_oxide::io::VarInt;
use tower::{Service, ServiceExt};

use cuprate_blockchain::service::BlockchainWriteHandle;
use cuprate_consensus_context::{
    BlockChainContextRequest, BlockChainContextResponse, BlockchainContext,
    BlockchainContextService, NewBlockData,
};
use cuprate_consensus_rules::miner_tx::calculate_block_reward;
use cuprate_types::{
    blockchain::BlockchainWriteRequest, HardFork, VerifiedBlockInformation,
    VerifiedTransactionInformation,
};

use crate::error::SimnetError;

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn random_scalar() -> Scalar {
    use rand::RngCore as _;

    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive the stealth-address output key and view tag for a coinbase output.
///
/// Given the wallet's public spend key, private view scalar, and the miner's
/// ephemeral tx scalar `r`:
///
/// ```text
/// tx_pubkey   = r * G                   (goes in extra)
/// ecdh        = r * (view_scalar * G)   (Diffie-Hellman)
/// ecdh8       = ecdh.mul_by_cofactor()
/// derivation  = compress(ecdh8) || VarInt(output_index)
/// view_tag    = keccak256("view_tag" || derivation)[0]
/// shared_key  = Hs(derivation)
/// output_key  = shared_key * G + spend_pub
/// ```
pub fn derive_coinbase_output(
    spend_pub: &EdwardsPoint,
    view_scalar: &Scalar,
    tx_scalar: &Scalar,
    output_index: usize,
) -> (EdwardsPoint, u8) {
    let view_pub = view_scalar * ED25519_BASEPOINT_TABLE;
    let ecdh = tx_scalar * view_pub;

    let ecdh8 = ecdh.mul_by_cofactor();
    let ecdh8_bytes = ecdh8.compress().to_bytes();

    let mut output_derivation = ecdh8_bytes.to_vec();
    VarInt::write(&output_index, &mut output_derivation).expect("vec write cannot fail");

    let view_tag = keccak256([b"view_tag".as_slice(), &output_derivation].concat())[0];

    let shared_key: Scalar = monero_oxide::ed25519::Scalar::hash(&output_derivation).into();
    let output_key = &shared_key * ED25519_BASEPOINT_TABLE + spend_pub;

    (output_key, view_tag)
}

/// Derive the stealth-address output key and view tag using only public keys.
///
/// Used when mining to a wallet address (where we have spend_pub and view_pub
/// but NOT the private view scalar). The miner computes ecdh = r * view_pub
/// which the wallet recovers as view_scalar * tx_pub = view_scalar * r * G = r * view_pub.
pub fn derive_coinbase_output_from_pubkey(
    spend_pub: &EdwardsPoint,
    view_pub: &EdwardsPoint,
    tx_scalar: &Scalar,
    output_index: usize,
) -> (EdwardsPoint, u8) {
    let ecdh = tx_scalar * view_pub;

    let ecdh8 = ecdh.mul_by_cofactor();
    let ecdh8_bytes = ecdh8.compress().to_bytes();

    let mut output_derivation = ecdh8_bytes.to_vec();
    VarInt::write(&output_index, &mut output_derivation).expect("vec write cannot fail");

    let view_tag = keccak256([b"view_tag".as_slice(), &output_derivation].concat())[0];

    let shared_key: Scalar = monero_oxide::ed25519::Scalar::hash(&output_derivation).into();
    let output_key = &shared_key * ED25519_BASEPOINT_TABLE + spend_pub;

    (output_key, view_tag)
}

/// Build a v2 (RingCT-era) coinbase miner transaction targeting a wallet address
/// (spend_pub + view_pub, both public).
pub fn build_miner_tx_to_pubkeys(
    height: usize,
    reward: u64,
    spend_pub: &EdwardsPoint,
    view_pub: &EdwardsPoint,
) -> Transaction {
    let tx_scalar = random_scalar();
    let tx_pub = &tx_scalar * ED25519_BASEPOINT_TABLE;

    let (output_key, view_tag) =
        derive_coinbase_output_from_pubkey(spend_pub, view_pub, &tx_scalar, 0);

    let mut extra = vec![0x01u8];
    extra.extend_from_slice(&tx_pub.compress().to_bytes());

    let prefix = TransactionPrefix {
        additional_timelock: Timelock::Block(height + 60),
        inputs: vec![Input::Gen(height)],
        outputs: vec![Output {
            amount: Some(reward),
            key: CompressedPoint::from(output_key.compress().to_bytes()),
            view_tag: Some(view_tag),
        }],
        extra,
    };

    Transaction::V2 { prefix, proofs: None }
}

/// Build a v2 (RingCT-era) coinbase miner transaction.
///
/// When `wallet` is `Some((spend_pub, view_scalar))` the output key is a proper
/// stealth address that any `monero_wallet::Scanner` holding the matching
/// `ViewPair` can detect.  Pass `None` to mine to a random, un-scannable key.
pub fn build_miner_tx(
    height: usize,
    reward: u64,
    wallet: Option<(&EdwardsPoint, &Scalar)>,
) -> Transaction {
    let tx_scalar = random_scalar();
    let tx_pub = &tx_scalar * ED25519_BASEPOINT_TABLE;

    let (output_key, view_tag) = match wallet {
        Some((spend_pub, view_scalar)) => {
            derive_coinbase_output(spend_pub, view_scalar, &tx_scalar, 0)
        }
        None => {
            let rnd = random_scalar();
            let key = &rnd * ED25519_BASEPOINT_TABLE;
            let tag = keccak256(b"dummy_view_tag")[0];
            (key, tag)
        }
    };

    // Extra: tag 0x01 (tx pubkey) + 32 compressed bytes.
    let mut extra = vec![0x01u8];
    extra.extend_from_slice(&tx_pub.compress().to_bytes());

    let prefix = TransactionPrefix {
        additional_timelock: Timelock::Block(height + 60),
        inputs: vec![Input::Gen(height)],
        outputs: vec![Output {
            // Some(amount) signals "miner tx" to the wallet scanner.
            amount: Some(reward),
            key: CompressedPoint::from(output_key.compress().to_bytes()),
            view_tag: Some(view_tag),
        }],
        extra,
    };

    Transaction::V2 { prefix, proofs: None }
}

// reuse the genesis miner tx for the genesis block
const GENESIS_MINER_TX_HEX: &str =
    "013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1";

pub fn genesis_miner_tx() -> Transaction {
    Transaction::read(
        &mut hex::decode(GENESIS_MINER_TX_HEX).unwrap().as_slice(),
    )
    .unwrap()
}

/// Build the next block from the current chain context without writing to the DB.
///
/// `extra_txs` is a list of transactions to include in the block (from the mempool).
/// Each entry provides the full `Transaction` object, its serialized blob, hash, and fee.
pub fn produce_block(
    ctx: &BlockchainContext,
    wallet: Option<(&EdwardsPoint, &Scalar)>,
    extra_txs: Vec<VerifiedTransactionInformation>,
) -> Result<VerifiedBlockInformation, SimnetError> {
    let height = ctx.chain_height;
    let current_hf = ctx.current_hf;
    let hf_byte = current_hf.as_u8();
    let median_bw = ctx.median_weight_for_block_reward.max(1);

    let tx_hashes: Vec<[u8; 32]> = extra_txs.iter().map(|t| t.tx_hash).collect();
    let tx_total_weight: usize = extra_txs.iter().map(|t| t.tx_weight).sum();

    let estimated_reward =
        calculate_block_reward(100, median_bw, ctx.already_generated_coins, current_hf);
    let miner_tx = build_miner_tx(height, estimated_reward, wallet);
    let miner_weight = miner_tx.weight();
    let total_weight = miner_weight + tx_total_weight;
    let generated_coins =
        calculate_block_reward(total_weight, median_bw, ctx.already_generated_coins, current_hf);

    let block = Block::new(
        BlockHeader {
            hardfork_version: hf_byte,
            hardfork_signal: hf_byte,
            timestamp: unix_now(),
            previous: ctx.top_hash,
            nonce: 0,
        },
        miner_tx,
        tx_hashes,
    )
    .ok_or_else(|| SimnetError::Consensus("Block::new returned None".into()))?;

    let block_blob = block.serialize();
    let block_hash = block.hash();
    let long_term_weight = ctx.next_block_long_term_weight(total_weight);

    Ok(VerifiedBlockInformation {
        block_blob,
        txs: extra_txs,
        block_hash,
        pow_hash: [0u8; 32],
        height,
        generated_coins,
        weight: total_weight,
        long_term_weight,
        cumulative_difficulty: ctx.cumulative_difficulty.saturating_add(1),
        block,
    })
}

/// Build the next block targeting a wallet address (spend_pub + view_pub).
pub fn produce_block_to_pubkeys(
    ctx: &BlockchainContext,
    spend_pub: &EdwardsPoint,
    view_pub: &EdwardsPoint,
    extra_txs: Vec<VerifiedTransactionInformation>,
) -> Result<VerifiedBlockInformation, SimnetError> {
    let height = ctx.chain_height;
    let current_hf = ctx.current_hf;
    let hf_byte = current_hf.as_u8();
    let median_bw = ctx.median_weight_for_block_reward.max(1);

    let tx_hashes: Vec<[u8; 32]> = extra_txs.iter().map(|t| t.tx_hash).collect();
    let tx_total_weight: usize = extra_txs.iter().map(|t| t.tx_weight).sum();

    let estimated_reward =
        calculate_block_reward(100, median_bw, ctx.already_generated_coins, current_hf);
    let miner_tx = build_miner_tx_to_pubkeys(height, estimated_reward, spend_pub, view_pub);
    let miner_weight = miner_tx.weight();
    let total_weight = miner_weight + tx_total_weight;
    let generated_coins =
        calculate_block_reward(total_weight, median_bw, ctx.already_generated_coins, current_hf);

    let block = Block::new(
        BlockHeader {
            hardfork_version: hf_byte,
            hardfork_signal: hf_byte,
            timestamp: unix_now(),
            previous: ctx.top_hash,
            nonce: 0,
        },
        miner_tx,
        tx_hashes,
    )
    .ok_or_else(|| SimnetError::Consensus("Block::new returned None".into()))?;

    let block_blob = block.serialize();
    let block_hash = block.hash();
    let long_term_weight = ctx.next_block_long_term_weight(total_weight);

    Ok(VerifiedBlockInformation {
        block_blob,
        txs: extra_txs,
        block_hash,
        pow_hash: [0u8; 32],
        height,
        generated_coins,
        weight: total_weight,
        long_term_weight,
        cumulative_difficulty: ctx.cumulative_difficulty.saturating_add(1),
        block,
    })
}

/// Write a block to the DB and advance the context service.
pub async fn commit_block(
    vbi: VerifiedBlockInformation,
    write_handle: &mut BlockchainWriteHandle,
    context_svc: &mut BlockchainContextService,
) -> Result<usize, SimnetError> {
    let height = vbi.height;
    let block_hash = vbi.block_hash;
    let timestamp = vbi.block.header.timestamp;
    let weight = vbi.weight;
    let long_term_weight = vbi.long_term_weight;
    let generated_coins = vbi.generated_coins;
    let cumulative_difficulty = vbi.cumulative_difficulty;
    let vote = HardFork::from_vote(vbi.block.header.hardfork_signal);

    write_handle
        .ready()
        .await?
        .call(BlockchainWriteRequest::WriteBlock(vbi))
        .await?;

    let BlockChainContextResponse::Ok = context_svc
        .ready()
        .await?
        .call(BlockChainContextRequest::Update(NewBlockData {
            block_hash,
            height,
            timestamp,
            weight,
            long_term_weight,
            generated_coins,
            vote,
            cumulative_difficulty,
        }))
        .await?
    else {
        return Err(SimnetError::Consensus("context Update returned wrong response".into()));
    };

    Ok(height + 1)
}

pub async fn mine_one_block(
    write_handle: &mut BlockchainWriteHandle,
    context_svc: &mut BlockchainContextService,
    wallet: Option<(&EdwardsPoint, &Scalar)>,
    txs: Vec<VerifiedTransactionInformation>,
) -> Result<usize, SimnetError> {
    let ctx = context_svc.blockchain_context().clone();
    let vbi = produce_block(&ctx, wallet, txs)?;
    commit_block(vbi, write_handle, context_svc).await
}

/// Mine one block targeting a wallet address (spend_pub + view_pub).
pub async fn mine_one_block_to_pubkeys(
    write_handle: &mut BlockchainWriteHandle,
    context_svc: &mut BlockchainContextService,
    spend_pub: &EdwardsPoint,
    view_pub: &EdwardsPoint,
    txs: Vec<VerifiedTransactionInformation>,
) -> Result<usize, SimnetError> {
    let ctx = context_svc.blockchain_context().clone();
    let vbi = produce_block_to_pubkeys(&ctx, spend_pub, view_pub, txs)?;
    commit_block(vbi, write_handle, context_svc).await
}

/// Like `mine_one_block_raw` but accepts an optional wallet coinbase destination.
#[allow(clippy::type_complexity)]
pub async fn mine_one_block_raw_to(
    write_handle: &mut BlockchainWriteHandle,
    context_svc: &mut BlockchainContextService,
    wallet: Option<(&EdwardsPoint, &Scalar)>,
) -> Result<([u8; 32], Vec<u8>, usize, usize, usize, u64, u128, u64), SimnetError> {
    let ctx = context_svc.blockchain_context().clone();
    let vbi = produce_block(&ctx, wallet, vec![])?;

    let ret = (
        vbi.block_hash,
        vbi.block_blob.clone(),
        vbi.height,
        vbi.weight,
        vbi.long_term_weight,
        vbi.block.header.timestamp,
        vbi.cumulative_difficulty,
        vbi.generated_coins,
    );

    commit_block(vbi, write_handle, context_svc).await?;
    Ok(ret)
}

/// Like `mine_one_block` but returns the raw data needed for peer propagation.
/// Mines to a random key with no extra txs (used by network.rs for propagation tests).
#[allow(clippy::type_complexity)]
pub async fn mine_one_block_raw(
    write_handle: &mut BlockchainWriteHandle,
    context_svc: &mut BlockchainContextService,
) -> Result<([u8; 32], Vec<u8>, usize, usize, usize, u64, u128, u64), SimnetError> {
    let ctx = context_svc.blockchain_context().clone();
    let vbi = produce_block(&ctx, None, vec![])?;

    let ret = (
        vbi.block_hash,
        vbi.block_blob.clone(),
        vbi.height,
        vbi.weight,
        vbi.long_term_weight,
        vbi.block.header.timestamp,
        vbi.cumulative_difficulty,
        vbi.generated_coins,
    );

    commit_block(vbi, write_handle, context_svc).await?;
    Ok(ret)
}
