// xmr-wow-sharechain: p2pool-compatible swap coordination sharechain

pub mod varint;
pub mod share;
pub mod escrow;
pub mod chain;
pub mod p2p;
pub mod mm_rpc;

// -- Top-level re-exports ------------------------------------------------------

pub use share::{
    Difficulty, EscrowCommitment, EscrowOp, Hash, MergeMinedProof, SwapShare,
};
pub use chain::{ChainError, SwapChain, CONSENSUS_ID};
pub use escrow::{EscrowError, EscrowIndex, EscrowState};
pub use mm_rpc::{merge_mining_router, merge_mining_router_with_connect_info};
