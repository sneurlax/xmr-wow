// xmr-wow-sharechain: P2P handshake implementation
//
// Ported from deps/p2pool-rs/p2pool_lib/src/p2p/handshake.rs with ONE change:
//   - `consensus_id` parameter replaced by the constant `CONSENSUS_ID`
//     imported from `crate::chain`.
//
// Protocol (identical to p2pool):
//   1. Both peers send HANDSHAKE_CHALLENGE on connect: [challenge: 8B][peer_id: 8B]
//   2. Receiver picks SALT (8B random), computes H = keccak256(challenge || consensus_id || salt)
//      and sends HANDSHAKE_SOLUTION: [H: 32B][salt: 8B]
//   3. The connection initiator's H must satisfy PoW: DifficultyType(10000).check_pow(H)
//
// Using our local CONSENSUS_ID b"xmr-wow-swap-v1" makes this chain incompatible
// with the main p2pool network while remaining wire-format compatible.

pub use crate::chain::CONSENSUS_ID;

use crate::p2p::messages::{CHALLENGE_DIFFICULTY, CHALLENGE_SIZE};
use crate::share::Difficulty;
use rand::Rng;
use tiny_keccak::{Hasher, Keccak};

// --- Core functions -----------------------------------------------------------

/// Compute the handshake solution hash:
///   `H = keccak256(challenge || consensus_id || salt)`
pub fn compute_solution(
    challenge: &[u8; CHALLENGE_SIZE],
    consensus_id: &[u8],
    salt: &[u8; CHALLENGE_SIZE],
) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(challenge);
    h.update(consensus_id);
    h.update(salt);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Check whether `solution` meets the handshake PoW difficulty (10 000).
///
/// Uses the same multiplication-based check as p2pool's DifficultyType::check_pow.
pub fn solution_meets_pow(solution: &[u8; 32]) -> bool {
    let diff = Difficulty::from_u64(CHALLENGE_DIFFICULTY);
    diff.check_pow(solution)
}

/// Generate a valid handshake solution by brute-forcing random salts.
///
/// If `is_initiator` is false the PoW check is skipped (responder side).
/// On average this requires ~10 000 iterations (~1 ms on a modern CPU).
///
/// Returns `(salt, solution_hash)`.
pub fn generate_solution(
    challenge: &[u8; CHALLENGE_SIZE],
    is_initiator: bool,
) -> ([u8; CHALLENGE_SIZE], [u8; 32]) {
    let mut rng = rand::thread_rng();
    loop {
        let salt: [u8; CHALLENGE_SIZE] = rng.gen();
        let solution = compute_solution(challenge, CONSENSUS_ID, &salt);
        if !is_initiator || solution_meets_pow(&solution) {
            return (salt, solution);
        }
    }
}

/// Verify an incoming HANDSHAKE_SOLUTION message.
///
/// - Checks `H == keccak256(challenge || CONSENSUS_ID || salt)`.
/// - If `peer_is_initiator`, also checks that H meets difficulty 10 000.
pub fn verify_solution(
    challenge: &[u8; CHALLENGE_SIZE],
    solution: &[u8; 32],
    salt: &[u8; CHALLENGE_SIZE],
    peer_is_initiator: bool,
) -> bool {
    let expected = compute_solution(challenge, CONSENSUS_ID, salt);
    if expected != *solution {
        return false;
    }
    if peer_is_initiator && !solution_meets_pow(solution) {
        return false;
    }
    true
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solution_verifies_responder() {
        let challenge = [1u8; CHALLENGE_SIZE];
        let (salt, solution) = generate_solution(&challenge, false);
        // Responder does not need PoW ; should verify regardless
        assert!(verify_solution(&challenge, &solution, &salt, false));
    }

    #[test]
    fn initiator_solution_meets_pow() {
        let challenge = [2u8; CHALLENGE_SIZE];
        let (salt, solution) = generate_solution(&challenge, true);
        assert!(solution_meets_pow(&solution));
        assert!(verify_solution(&challenge, &solution, &salt, true));
    }

    #[test]
    fn wrong_salt_fails() {
        let challenge = [3u8; CHALLENGE_SIZE];
        let (salt, solution) = generate_solution(&challenge, false);
        let mut bad_salt = salt;
        bad_salt[0] ^= 0xFF;
        assert!(!verify_solution(&challenge, &solution, &bad_salt, false));
    }

    #[test]
    fn wrong_challenge_fails() {
        let challenge = [4u8; CHALLENGE_SIZE];
        let (salt, solution) = generate_solution(&challenge, false);
        let bad_challenge = [5u8; CHALLENGE_SIZE];
        assert!(!verify_solution(&bad_challenge, &solution, &salt, false));
    }

    #[test]
    fn consensus_id_is_correct() {
        assert_eq!(CONSENSUS_ID, b"xmr-wow-swap-v1");
    }

    #[test]
    fn compute_solution_is_deterministic() {
        let challenge = [0xAAu8; CHALLENGE_SIZE];
        let salt      = [0xBBu8; CHALLENGE_SIZE];
        let h1 = compute_solution(&challenge, CONSENSUS_ID, &salt);
        let h2 = compute_solution(&challenge, CONSENSUS_ID, &salt);
        assert_eq!(h1, h2);
    }
}
