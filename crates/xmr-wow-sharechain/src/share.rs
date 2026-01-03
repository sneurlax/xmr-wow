// xmr-wow-sharechain: SwapShare block format
// The fundamental coordination unit of the swap sharechain.
// NOT a PoolBlock ; it is a lightweight swap-coordination record.

use serde::{Deserialize, Serialize};

/// 128-bit difficulty (same encoding as p2pool's difficulty_type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Difficulty {
    pub lo: u64,
    pub hi: u64,
}

impl Difficulty {
    pub const ZERO: Difficulty = Difficulty { lo: 0, hi: 0 };

    pub fn from_u64(v: u64) -> Self {
        Self { lo: v, hi: 0 }
    }

    pub fn to_u128(self) -> u128 {
        (self.hi as u128) << 64 | self.lo as u128
    }

    pub fn from_u128(v: u128) -> Self {
        Self {
            lo: v as u64,
            hi: (v >> 64) as u64,
        }
    }

    pub fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    /// Add two difficulties with wrapping semantics.
    pub fn wrapping_add(self, rhs: Difficulty) -> Difficulty {
        Difficulty::from_u128(self.to_u128().wrapping_add(rhs.to_u128()))
    }

    /// Check PoW: `hash * difficulty < 2^256`.
    ///
    /// Uses the same 128-bit multiply algorithm as p2pool's DifficultyType::check_pow.
    /// For simplicity when `self.hi != 0`, only an all-zeros hash passes.
    pub fn check_pow(&self, hash: &[u8; 32]) -> bool {
        if self.is_zero() {
            return false;
        }
        if self.hi != 0 {
            return hash == &[0u8; 32];
        }

        let d = self.lo as u128;
        if d <= 1 {
            return true;
        }

        // Interpret hash as four little-endian u64 words.
        let w0 = u64::from_le_bytes(hash[0..8].try_into().unwrap()) as u128;
        let w1 = u64::from_le_bytes(hash[8..16].try_into().unwrap()) as u128;
        let w2 = u64::from_le_bytes(hash[16..24].try_into().unwrap()) as u128;
        let w3 = u64::from_le_bytes(hash[24..32].try_into().unwrap()) as u128;

        let p0 = w0 * d;
        let p1 = w1 * d + (p0 >> 64);
        let p2 = w2 * d + (p1 >> 64);
        let p3 = w3 * d + (p2 >> 64);
        // Product fits in 256 bits iff the overflow word is zero.
        (p3 >> 64) == 0
    }
}

impl PartialOrd for Difficulty {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Difficulty {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hi.cmp(&other.hi).then(self.lo.cmp(&other.lo))
    }
}

/// A 32-byte hash value.
pub type Hash = [u8; 32];

/// An operation recorded in a swap share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscrowOp {
    /// A new atomic swap escrow is being opened.
    Open(EscrowCommitment),
    /// Alice reveals k_b to claim the escrow funds.
    Claim { swap_id: Hash, k_b: [u8; 32] },
    /// Bob claims a refund after the timelock expires.
    /// `sig` is stored as hex so serde can handle the 64-byte array.
    Refund {
        swap_id: Hash,
        #[serde(with = "sig_hex")]
        sig: [u8; 64],
    },
}

/// Serde helper: serialize/deserialize a 64-byte signature as a hex string.
mod sig_hex {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes = hex::decode(&hex_str).map_err(D::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("sig must be exactly 64 bytes"))
    }
}

/// Full escrow commitment embedded in an `EscrowOp::Open` operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowCommitment {
    pub swap_id:         Hash,
    pub alice_sc_pubkey: [u8; 32],
    pub bob_sc_pubkey:   [u8; 32],
    /// Alice's commitment to k_b (hash or point).
    pub k_b_expected:    [u8; 32],
    pub k_b_prime:       [u8; 32],
    pub claim_timelock:  u64,
    pub refund_timelock: u64,
    /// Amount in atomic units.
    pub amount:          u64,
}

/// A Monero merge-mining proof attached once a Monero block commits to this share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeMinedProof {
    /// Raw Monero block blob (hex-encodable, binary stored as Vec<u8>).
    pub monero_block_blob: Vec<u8>,
    /// Merkle branch from the share's aux-hash up to the coinbase merkle root.
    pub merkle_proof:      Vec<Hash>,
    /// Merkle path flags (bitmask indicating left/right at each level).
    pub merkle_path:       u32,
    /// RandomX seed hash used for PoW verification.
    pub seed_hash:         Hash,
}

/// A swap sharechain block.
///
/// Mirrors the p2pool sidechain block structure but carries swap-escrow
/// payloads instead of Monero miner payouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapShare {
    // -- Chain structure (mirrors p2pool sidechain fields) -----------------
    pub parent:                Hash,
    pub uncles:                Vec<Hash>,
    pub height:                u64,
    pub difficulty:            Difficulty,
    pub cumulative_difficulty:  Difficulty,
    pub timestamp:             u64,
    pub nonce:                 u32,

    // -- Swap payload ------------------------------------------------------
    /// Ordered list of escrow state transitions included in this share.
    pub escrow_ops:         Vec<EscrowOp>,
    /// Merkle root over the current active escrow set (used as aux_hash for p2pool).
    pub escrow_merkle_root: Hash,

    // -- Merge mining link -------------------------------------------------
    /// Set once a Monero block includes this share's `escrow_merkle_root`.
    pub pow_proof: Option<MergeMinedProof>,
}

impl SwapShare {
    /// Canonical share ID: `keccak256(parent || height_le || escrow_merkle_root)`.
    pub fn id(&self) -> Hash {
        use tiny_keccak::{Hasher, Keccak};
        let mut h = Keccak::v256();
        h.update(&self.parent);
        h.update(&self.height.to_le_bytes());
        h.update(&self.escrow_merkle_root);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    }

    /// PoW hash: `keccak256(id || nonce_le)`.
    ///
    /// Allows nonce grinding: a miner increments `nonce` until
    /// `difficulty.check_pow(&share.pow_hash())` returns true.
    pub fn pow_hash(&self) -> [u8; 32] {
        use tiny_keccak::{Hasher, Keccak};
        let mut h = Keccak::v256();
        h.update(&self.id());
        h.update(&self.nonce.to_le_bytes());
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    }

    /// Full dedup key: `id || nonce_le` (36 bytes).
    pub fn full_id(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..32].copy_from_slice(&self.id());
        out[32..].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Serialize to JSON bytes.
    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("SwapShare serialize")
    }

    /// Deserialize from JSON bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Build a genesis share (height 0, no parent).
    pub fn genesis(difficulty: Difficulty) -> Self {
        Self {
            parent:               [0u8; 32],
            uncles:               Vec::new(),
            height:               0,
            difficulty,
            cumulative_difficulty: difficulty,
            timestamp:            0,
            nonce:                0,
            escrow_ops:          Vec::new(),
            escrow_merkle_root:  [0u8; 32],
            pow_proof:           None,
        }
    }
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_share() -> SwapShare {
        SwapShare {
            parent:               [1u8; 32],
            uncles:               vec![[2u8; 32]],
            height:               42,
            difficulty:           Difficulty::from_u64(1000),
            cumulative_difficulty: Difficulty::from_u64(42_000),
            timestamp:            1_700_000_000,
            nonce:                7,
            escrow_ops:          Vec::new(),
            escrow_merkle_root:  [3u8; 32],
            pow_proof:           None,
        }
    }

    #[test]
    fn share_id_is_deterministic() {
        let s = sample_share();
        assert_eq!(s.id(), s.id(), "share ID must be deterministic");
        // Mutating escrow_merkle_root must change the ID
        let mut s2 = s.clone();
        s2.escrow_merkle_root = [4u8; 32];
        assert_ne!(s.id(), s2.id());
    }

    #[test]
    fn share_serializes_roundtrip() {
        let s = sample_share();
        let bytes = s.serialize();
        let s2 = SwapShare::deserialize(&bytes).expect("deserialize");
        assert_eq!(s.height, s2.height);
        assert_eq!(s.nonce, s2.nonce);
        assert_eq!(s.parent, s2.parent);
        assert_eq!(s.difficulty.lo, s2.difficulty.lo);
        assert_eq!(s.escrow_merkle_root, s2.escrow_merkle_root);
        // IDs must agree after roundtrip
        assert_eq!(s.id(), s2.id());
    }

    #[test]
    fn escrow_op_serializes() {
        let commitment = EscrowCommitment {
            swap_id:         [0xABu8; 32],
            alice_sc_pubkey: [1u8; 32],
            bob_sc_pubkey:   [2u8; 32],
            k_b_expected:    [3u8; 32],
            k_b_prime:       [4u8; 32],
            claim_timelock:  100,
            refund_timelock: 200,
            amount:          1_000_000_000,
        };
        let ops: Vec<EscrowOp> = vec![
            EscrowOp::Open(commitment),
            EscrowOp::Claim { swap_id: [5u8; 32], k_b: [6u8; 32] },
            EscrowOp::Refund { swap_id: [7u8; 32], sig: [8u8; 64] },
        ];
        let bytes = serde_json::to_vec(&ops).unwrap();
        let ops2: Vec<EscrowOp> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ops2.len(), 3);
        match &ops2[0] {
            EscrowOp::Open(c) => assert_eq!(c.amount, 1_000_000_000),
            _ => panic!("expected Open"),
        }
        match &ops2[1] {
            EscrowOp::Claim { swap_id, k_b } => {
                assert_eq!(swap_id, &[5u8; 32]);
                assert_eq!(k_b, &[6u8; 32]);
            }
            _ => panic!("expected Claim"),
        }
        match &ops2[2] {
            EscrowOp::Refund { swap_id, sig } => {
                assert_eq!(swap_id, &[7u8; 32]);
                assert_eq!(sig.as_ref(), &[8u8; 64]);
            }
            _ => panic!("expected Refund"),
        }
    }

    #[test]
    fn difficulty_check_pow_trivial() {
        // difficulty 1 -> everything passes
        let d = Difficulty::from_u64(1);
        assert!(d.check_pow(&[0u8; 32]));
        assert!(d.check_pow(&[0xFF; 32]));
        // difficulty 0 -> everything fails
        let z = Difficulty::ZERO;
        assert!(!z.check_pow(&[0u8; 32]));
    }

    #[test]
    fn full_id_length() {
        let s = sample_share();
        assert_eq!(s.full_id().len(), 36);
        // Different nonces produce different full_ids even with same id()
        let mut s2 = s.clone();
        s2.nonce = s.nonce + 1;
        assert_ne!(s.full_id(), s2.full_id());
    }
}
