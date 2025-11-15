use wownero_oxide::primitives::keccak256;

/// A lightweight child chain block.
/// In a full implementation this would carry transactions.
/// For the PoC it carries only the chain identity fields needed to produce a
/// deterministic, verifiable hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildBlock {
    pub height: u64,
    pub prev_hash: [u8; 32],
    /// Arbitrary payload (placeholder for real transactions).
    pub payload: Vec<u8>,
}

impl ChildBlock {
    pub fn genesis() -> Self {
        Self { height: 0, prev_hash: [0u8; 32], payload: b"child chain genesis".to_vec() }
    }

    /// The child block's hash: keccak256 of height‖prev_hash‖payload.
    pub fn hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(8 + 32 + self.payload.len());
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.prev_hash);
        buf.extend_from_slice(&self.payload);
        keccak256(buf)
    }

    /// Build the next child block on top of `self`.
    pub fn next(&self, payload: Vec<u8>) -> ChildBlock {
        ChildBlock {
            height: self.height + 1,
            prev_hash: self.hash(),
            payload,
        }
    }
}
