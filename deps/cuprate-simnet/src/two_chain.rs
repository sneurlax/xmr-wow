use tower::{Service, ServiceExt};

use monero_oxide::block::Block;
use monero_oxide_mm::extra::{get_merge_mining_hash, set_merge_mining_hash};
use monero_oxide_mm::merge_mining::MergeMiningProof;
use cuprate_types::blockchain::{BlockchainReadRequest, BlockchainResponse};

/// Convert a `monero_oxide::block::BlockHeader` to a `monero_oxide_mm::block::BlockHeader`
/// by serializing and re-parsing. Both crates share the same wire format.
fn convert_header(h: &monero_oxide::block::BlockHeader) -> monero_oxide_mm::block::BlockHeader {
    let bytes = h.serialize();
    monero_oxide_mm::block::BlockHeader::read(&mut bytes.as_slice())
        .expect("header round-trip failed")
}

/// Convert a `monero_oxide::transaction::Transaction` to a `monero_oxide_mm::transaction::Transaction`
/// by serializing and re-parsing. Both crates share the same wire format.
fn convert_tx(tx: &monero_oxide::transaction::Transaction) -> monero_oxide_mm::transaction::Transaction {
    let bytes = tx.serialize();
    monero_oxide_mm::transaction::Transaction::read(&mut bytes.as_slice())
        .expect("transaction round-trip failed")
}

use crate::{
    child_chain::ChildBlock,
    error::SimnetError,
    miner::produce_block,
    node::SimnetNode,
};

fn ce(msg: impl Into<String>) -> SimnetError {
    SimnetError::Consensus(msg.into().into())
}

pub struct TwoChainSimnet {
    pub parent: SimnetNode,
    /// All committed child blocks, starting with genesis at index 0.
    pub child_blocks: Vec<ChildBlock>,
    /// When `true`, `verify_child_anchored` also calls `MergeMiningProof::verify_pow`.
    /// Default: `false` (tests bypass PoW).
    pub enforce_pow: bool,
}

/// A no-op RandomX verifier that accepts everything.
///
/// Used when `enforce_pow = true` but a real RandomX VM is not available.
/// Returns the all-zero hash, which satisfies any difficulty ≥ 1 under
/// Monero's `hash * difficulty < 2^256` check.
/// Replace with `RxBridge<CuprateRandomX>` for production enforcement.
pub struct AlwaysValidRandomX;

impl monero_oxide_mm::merge_mining::RandomXVerifier for AlwaysValidRandomX {
    type Error = std::convert::Infallible;
    fn calculate_hash(&self, _buf: &[u8]) -> Result<[u8; 32], Self::Error> {
        Ok([0u8; 32])
    }
}

impl TwoChainSimnet {
    pub async fn new() -> Result<Self, SimnetError> {
        let parent = SimnetNode::start().await?;
        Ok(Self { parent, child_blocks: vec![ChildBlock::genesis()], enforce_pow: false })
    }

    /// Like [`new`] but sets `enforce_pow = true` so `verify_child_anchored`
    /// also calls `MergeMiningProof::verify_pow`.  The call path is wired; swap
    /// `AlwaysValidRandomX` for a real VM to enforce actual difficulty.
    pub async fn new_with_pow_enforcement() -> Result<Self, SimnetError> {
        let parent = SimnetNode::start().await?;
        Ok(Self { parent, child_blocks: vec![ChildBlock::genesis()], enforce_pow: true })
    }

    /// Mine one parent block with no child commitment.
    pub async fn mine_parent_only(&mut self) -> Result<u64, SimnetError> {
        let result = crate::miner::mine_one_block(
            &mut self.parent.write_handle,
            &mut self.parent.context_svc,
            None,
            vec![],
        )
        .await?;
        Ok(result as u64)
    }

    /// Build the next ChildBlock, embed its hash in the parent coinbase extra,
    /// mine the parent block, record the ChildBlock. Returns (parent_height, child_height).
    pub async fn mine_with_child(&mut self, payload: Vec<u8>) -> Result<(u64, u64), SimnetError> {
        let tip = self.child_blocks.last().expect("genesis always present");
        let next_child = tip.next(payload);
        let child_hash = next_child.hash();

        let ctx = self.parent.context_svc.blockchain_context().clone();
        let mut vbi = produce_block(&ctx, None, vec![])?;

        // Clone and mutate miner tx extra to embed the child hash.
        let mut miner_tx = vbi.block.miner_transaction().clone();
        let new_extra = set_merge_mining_hash(&miner_tx.prefix().extra, child_hash);
        miner_tx.prefix_mut().extra = new_extra;

        // Reconstruct the block with the modified miner tx (miner_transaction is private).
        let new_block = Block::new(
            vbi.block.header.clone(),
            miner_tx,
            vbi.block.transactions.clone(),
        )
        .ok_or_else(|| ce("Block::new returned None"))?;

        // Capture the block height before consuming vbi.
        let parent_block_height = vbi.height as u64;
        vbi.block = new_block;
        vbi.block_blob = vbi.block.serialize();
        vbi.block_hash = vbi.block.hash();

        let saved_header = convert_header(&vbi.block.header);
        let saved_coinbase = convert_tx(vbi.block.miner_transaction());
        let saved_hash = vbi.block_hash;

        self.parent.commit(vbi).await?;

        let check_proof = MergeMiningProof {
            monero_header: saved_header,
            coinbase_tx: saved_coinbase,
            tx_count: 1,
            coinbase_branch: vec![],
        };
        debug_assert_eq!(
            check_proof.monero_block_hash(),
            saved_hash,
            "MergeMiningProof::monero_block_hash() disagrees with Block::hash()"
        );

        let child_height = next_child.height;
        self.child_blocks.push(next_child);

        Ok((parent_block_height, child_height))
    }

    /// Verify that the parent block at `parent_height` commits to the child block
    /// at `child_height` in its coinbase extra.
    pub async fn verify_child_anchored(
        &self,
        parent_height: u64,
        child_height: u64,
    ) -> Result<(), SimnetError> {
        let BlockchainResponse::Block(block) = self
            .parent
            .read_handle
            .clone()
            .ready()
            .await
            .map_err(|e| ce(e.to_string()))?
            .call(BlockchainReadRequest::Block { height: parent_height as usize })
            .await
            .map_err(|e| ce(e.to_string()))?
        else {
            return Err(ce("unexpected response variant"));
        };

        let child_hash = self
            .child_blocks
            .get(child_height as usize)
            .ok_or_else(|| ce(format!("child height {} out of range", child_height)))?
            .hash();

        let proof = MergeMiningProof {
            monero_header: convert_header(&block.header),
            coinbase_tx: convert_tx(block.miner_transaction()),
            tx_count: 1 + block.transactions.len(),
            coinbase_branch: vec![],
        };

        proof.verify(&child_hash).map_err(|e| ce(e.to_string()))?;

        if self.enforce_pow {
            proof
                .verify_pow(&AlwaysValidRandomX, 1u128)
                .map_err(|e| ce(e.to_string()))?;
            // Future: replace AlwaysValidRandomX with RxBridge<CuprateRandomX>
            // for real difficulty enforcement.
        }

        let embedded = get_merge_mining_hash(
            proof.coinbase_tx.prefix().extra.as_slice()
        ).expect("verify() passed so hash must be present");
        assert_eq!(embedded, child_hash);

        Ok(())
    }

    /// Fetch the parent block at `parent_height` and construct a `MergeMiningProof` for
    /// the child block at `child_height`. Also returns the child block hash.
    pub async fn fetch_proof(
        &mut self,
        parent_height: u64,
        child_height: u64,
    ) -> Result<(MergeMiningProof, [u8; 32]), SimnetError> {
        let BlockchainResponse::Block(block) = self
            .parent
            .read_handle
            .clone()
            .ready()
            .await
            .map_err(|e| ce(e.to_string()))?
            .call(BlockchainReadRequest::Block { height: parent_height as usize })
            .await
            .map_err(|e| ce(e.to_string()))?
        else {
            return Err(ce("unexpected response variant"));
        };

        let child_hash = self
            .child_blocks
            .get(child_height as usize)
            .ok_or_else(|| ce(format!("child height {} out of range", child_height)))?
            .hash();

        let proof = MergeMiningProof {
            monero_header: convert_header(&block.header),
            coinbase_tx: convert_tx(block.miner_transaction()),
            tx_count: 1 + block.transactions.len(),
            coinbase_branch: vec![],
        };

        Ok((proof, child_hash))
    }

    pub fn child_height(&self) -> u64 {
        self.child_blocks.len() as u64 - 1
    }
}
