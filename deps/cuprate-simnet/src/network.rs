use tower::{Service, ServiceExt};

use cuprate_consensus_context::{BlockChainContextRequest, BlockChainContextResponse, NewBlockData};
use cuprate_consensus_rules::HardFork;
use cuprate_types::{blockchain::BlockchainWriteRequest, VerifiedBlockInformation};

use curve25519_dalek::{EdwardsPoint, Scalar};

use crate::{error::SimnetError, miner::{mine_one_block_raw, mine_one_block_raw_to}, node::SimnetNode};

pub struct Simnet {
    pub nodes: Vec<SimnetNode>,
}

impl Simnet {
    pub async fn new(n: usize) -> Result<Self, SimnetError> {
        let mut nodes = Vec::with_capacity(n);
        for _ in 0..n {
            nodes.push(SimnetNode::start().await?);
        }
        Ok(Self { nodes })
    }

    pub async fn mine_on(&mut self, node_idx: usize, blocks: u64) -> Result<(), SimnetError> {
        if node_idx >= self.nodes.len() {
            return Err(SimnetError::InvalidNodeIndex(node_idx));
        }

        for _ in 0..blocks {
            let (block_hash, block_blob, height, weight, long_term_weight, timestamp, cumulative_difficulty, generated_coins) = {
                let src = &mut self.nodes[node_idx];
                mine_one_block_raw(&mut src.write_handle, &mut src.context_svc).await?
            };

            for i in 0..self.nodes.len() {
                if i == node_idx {
                    continue;
                }

                let peer_block = monero_oxide::block::Block::read(&mut block_blob.as_slice())
                    .map_err(|e| SimnetError::Consensus(e.into()))?;

                let peer = &mut self.nodes[i];

                peer.write_handle
                    .ready()
                    .await?
                    .call(BlockchainWriteRequest::WriteBlock(VerifiedBlockInformation {
                        block_blob: block_blob.clone(),
                        txs: vec![],
                        block_hash,
                        pow_hash: [0u8; 32],
                        height,
                        generated_coins,
                        weight,
                        long_term_weight,
                        cumulative_difficulty,
                        block: peer_block,
                    }))
                    .await?;

                let BlockChainContextResponse::Ok = peer
                    .context_svc
                    .ready()
                    .await?
                    .call(BlockChainContextRequest::Update(NewBlockData {
                        block_hash,
                        height,
                        timestamp,
                        weight,
                        long_term_weight,
                        generated_coins,
                        vote: HardFork::V1,
                        cumulative_difficulty,
                    }))
                    .await?
                else {
                    return Err(SimnetError::Consensus("context Update failed during propagation".into()));
                };
            }
        }
        Ok(())
    }

    /// Mine `blocks` blocks on `node_idx` targeting a wallet (for scannable coinbase
    /// outputs), then propagate each block to all other nodes in the network.
    pub async fn mine_on_to(
        &mut self,
        node_idx: usize,
        blocks: u64,
        spend_pub: &EdwardsPoint,
        view_scalar: &Scalar,
    ) -> Result<(), SimnetError> {
        if node_idx >= self.nodes.len() {
            return Err(SimnetError::InvalidNodeIndex(node_idx));
        }

        for _ in 0..blocks {
            let (block_hash, block_blob, height, weight, long_term_weight, timestamp, cumulative_difficulty, generated_coins) = {
                let src = &mut self.nodes[node_idx];
                mine_one_block_raw_to(
                    &mut src.write_handle,
                    &mut src.context_svc,
                    Some((spend_pub, view_scalar)),
                )
                .await?
            };

            for i in 0..self.nodes.len() {
                if i == node_idx {
                    continue;
                }

                let peer_block = monero_oxide::block::Block::read(&mut block_blob.as_slice())
                    .map_err(|e| SimnetError::Consensus(e.into()))?;

                let peer = &mut self.nodes[i];

                peer.write_handle
                    .ready()
                    .await?
                    .call(BlockchainWriteRequest::WriteBlock(VerifiedBlockInformation {
                        block_blob: block_blob.clone(),
                        txs: vec![],
                        block_hash,
                        pow_hash: [0u8; 32],
                        height,
                        generated_coins,
                        weight,
                        long_term_weight,
                        cumulative_difficulty,
                        block: peer_block,
                    }))
                    .await?;

                let BlockChainContextResponse::Ok = peer
                    .context_svc
                    .ready()
                    .await?
                    .call(BlockChainContextRequest::Update(NewBlockData {
                        block_hash,
                        height,
                        timestamp,
                        weight,
                        long_term_weight,
                        generated_coins,
                        vote: HardFork::V1,
                        cumulative_difficulty,
                    }))
                    .await?
                else {
                    return Err(SimnetError::Consensus("context Update failed during propagation".into()));
                };
            }
        }
        Ok(())
    }

    pub fn partition(&mut self, _group_a: &[usize], _group_b: &[usize]) {
        unimplemented!("needs in-memory P2P transport")
    }
}
