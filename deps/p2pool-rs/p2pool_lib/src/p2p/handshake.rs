// P2Pool for Monero - P2P handshake implementation
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// Handshake protocol (from p2p_server.h):
//
// 1. Both peers send HANDSHAKE_CHALLENGE immediately on connect:
//      [challenge: 8B random] [peer_id: 8B]
// 2. On receiving a challenge, each peer:
//    a. Chooses 8 random bytes as SALT.
//    b. Computes H = keccak256(CHALLENGE || CONSENSUS_ID || SALT)
//    c. Sends HANDSHAKE_SOLUTION: [H: 32B] [SALT: 8B]
// 3. The connection initiator's H must satisfy PoW: H meets difficulty 10000
//    (i.e., the highest 64-bit word of H, interpreted as a number, is small enough).
// 4. On receiving HANDSHAKE_SOLUTION, each peer verifies the solution hash
//    and, if the peer is the initiator, also checks the PoW difficulty.
//
// After a successful handshake both peers send LISTEN_PORT.

use p2pool_crypto::{keccak256_parts, DifficultyType, Hash};
use rand::Rng;

use super::messages::CHALLENGE_DIFFICULTY;
use super::messages::CHALLENGE_SIZE;

/// Compute the handshake solution hash.
///
///   H = keccak256(challenge || consensus_id || salt)
pub fn compute_solution(
    challenge: &[u8; CHALLENGE_SIZE],
    consensus_id: &[u8],
    salt: &[u8; CHALLENGE_SIZE],
) -> Hash {
    keccak256_parts(&[challenge.as_slice(), consensus_id, salt.as_slice()])
}

/// Check whether `solution` meets the handshake PoW difficulty.
///
/// The check is: DifficultyType(CHALLENGE_DIFFICULTY).check_pow(solution)
pub fn solution_meets_pow(solution: &Hash) -> bool {
    let diff = DifficultyType::from_u64(CHALLENGE_DIFFICULTY);
    diff.check_pow(solution)
}

/// Generate a valid handshake solution, brute-forcing the salt until the
/// PoW condition is met (only required for the connection initiator).
///
/// On average this takes ~10,000 iterations (~1 ms on a modern CPU).
pub fn generate_solution(
    challenge: &[u8; CHALLENGE_SIZE],
    consensus_id: &[u8],
    is_initiator: bool,
) -> ([u8; CHALLENGE_SIZE], Hash) {
    let mut rng = rand::thread_rng();
    loop {
        let salt: [u8; CHALLENGE_SIZE] = rng.gen();
        let solution = compute_solution(challenge, consensus_id, &salt);
        if !is_initiator || solution_meets_pow(&solution) {
            return (salt, solution);
        }
    }
}

/// Verify an incoming HANDSHAKE_SOLUTION message.
///
/// Checks that H == keccak256(challenge || consensus_id || salt) and,
/// if `peer_is_initiator`, that H meets the PoW difficulty.
pub fn verify_solution(
    challenge: &[u8; CHALLENGE_SIZE],
    consensus_id: &[u8],
    solution: &Hash,
    salt: &[u8; CHALLENGE_SIZE],
    peer_is_initiator: bool,
) -> bool {
    let expected = compute_solution(challenge, consensus_id, salt);
    if expected != *solution {
        return false;
    }
    if peer_is_initiator && !solution_meets_pow(solution) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solution_verifies() {
        let challenge = [1u8; CHALLENGE_SIZE];
        let consensus_id = b"test consensus";
        let (salt, solution) = generate_solution(&challenge, consensus_id, false);
        assert!(verify_solution(&challenge, consensus_id, &solution, &salt, false));
    }

    #[test]
    fn initiator_solution_meets_pow() {
        let challenge = [2u8; CHALLENGE_SIZE];
        let consensus_id = b"test consensus";
        let (salt, solution) = generate_solution(&challenge, consensus_id, true);
        assert!(solution_meets_pow(&solution));
        assert!(verify_solution(&challenge, consensus_id, &solution, &salt, true));
    }

    #[test]
    fn wrong_consensus_id_fails() {
        let challenge = [3u8; CHALLENGE_SIZE];
        let (salt, solution) = generate_solution(&challenge, b"correct", false);
        assert!(!verify_solution(&challenge, b"wrong", &solution, &salt, false));
    }
}
