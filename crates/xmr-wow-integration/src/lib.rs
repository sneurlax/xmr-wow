/// Integration test helpers.
///
/// The standalone simnet harness lives at `deps/simnet-testbed/` because its
/// simnet forks pin a different `monero-oxide` revision.
pub mod simnet_testbed {
    //! Docs only. Use the standalone crate directly.
}

use xmr_wow_sharechain::{SwapChain, SwapShare, EscrowOp, Difficulty};

/// Build the genesis share.
pub fn genesis() -> SwapShare {
    SwapShare::genesis(Difficulty::from_u64(1))
}

/// Build a share on the current tip.
pub fn next_share(chain: &SwapChain, ops: Vec<EscrowOp>) -> SwapShare {
    let parent_hash = chain.tip_id().unwrap_or([0u8; 32]);
    let parent_height = chain.tip_height();
    let diff = Difficulty::from_u64(1);
    let parent_cumdiff = chain.get_share(&parent_hash)
        .map(|s| s.cumulative_difficulty)
        .unwrap_or(diff);
    SwapShare {
        parent: parent_hash,
        uncles: vec![],
        height: parent_height + 1,
        difficulty: diff,
        cumulative_difficulty: parent_cumdiff.wrapping_add(diff),
        timestamp: 0,
        nonce: 0,
        escrow_ops: ops,
        escrow_merkle_root: [0u8; 32],
        pow_proof: None,
    }
}

/// Build a chain with `n` empty shares.
pub fn build_chain(n: usize) -> SwapChain {
    let chain = SwapChain::new(Difficulty::from_u64(1));
    let g = genesis();
    chain.add_share(g).unwrap();
    for _ in 1..n {
        let s = next_share(&chain, vec![]);
        chain.add_share(s).unwrap();
    }
    chain
}
