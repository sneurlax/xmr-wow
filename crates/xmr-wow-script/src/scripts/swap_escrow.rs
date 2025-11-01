//! Canonical atomic swap escrow script.
//!
//! This is the ONLY script format used in the v1 XMR<->WOW atomic swap
//! protocol. All sidechain swap outputs must use this script.
//!
//! # Protocol overview
//!
//! The swap escrow locks sidechain coins (the WOW side of the swap) under
//! a two-path script:
//!
//! **Claim path (Alice):** Alice learns `k_b` (Bob's Chain-A key contribution)
//! during the swap. She proves she has it by showing `k_b * G == K_b`.
//! The claim must happen before `claim_deadline` to incentivize timely settlement.
//! As a side effect, `RevealSecret` emits an event so the node can forward
//! `K_b_prime` to Alice's Monero chain watcher (helping her claim on-chain XMR).
//!
//! **Refund path (Bob):** After `refund_height`, Bob can reclaim his funds
//! by signing with his sidechain key. This protects Bob if Alice goes offline.
//!
//! # Timing constraints
//!
//! ```text
//! refund_height > claim_deadline  (Bob can only refund after claim window closes)
//! ```
//!
//! Typical values: claim_deadline = T+144, refund_height = T+288 (Bitcoin-like).
//!
//! # Witness format
//!
//! ## Claim path witness
//! ```text
//! [k_b: 32 bytes]   ; Bob's private key contribution (truthy -> selects IF branch)
//! ```
//!
//! ## Refund path witness
//! ```text
//! [message: 32 bytes]   ; message Bob signed (typically tx_hash)  deepest
//! [sig: 64 bytes]       ; Bob's Ed25519 signature over message     middle
//! [0x00: 1 byte]        ; falsy flag -> selects ELSE branch         top
//! ```
//!
//! The script uses `Dup` before `If` so the top item is duplicated before
//! `If` consumes it:
//! - Claim: k_b is Dup'd, If pops copy (truthy -> IF), original k_b stays for CheckKeyPairVerify.
//! - Refund: 0x00 is Dup'd, If pops copy (falsy -> ELSE), Drop removes original flag.
//!
//! # Integration surface for the node (RevealSecret callback)
//!
//! When the claim path executes successfully, `ExecutionResult::revealed_secrets`
//! contains one entry:
//!   - `commitment` = K_b_prime (Bob's Wownero chain key contribution)
//!   - `recipient`  = alice_sc_pubkey
//!
//! The node MUST:
//! 1. Store this reveal in its database
//! 2. Broadcast it to the Wownero chain watcher service
//! 3. Include it in the spending transaction receipt for Alice's client

use crate::opcode::Opcode;

/// Build the canonical swap escrow script.
///
/// # Arguments
/// - `k_b_point`: K_b = k_b*G ; Bob's Chain-A public key contribution (32 bytes)
/// - `k_b_prime`: K_b' ; Bob's Wownero chain key contribution to reveal to Alice (32 bytes)
/// - `alice_sc_pubkey`: Alice's sidechain public key (receives the K_b' reveal) (32 bytes)
/// - `bob_sc_pubkey`: Bob's sidechain public key (for refund signature check) (32 bytes)
/// - `claim_deadline`: Block height upper bound for Alice's claim (exclusive)
/// - `refund_height`: Block height lower bound for Bob's refund (inclusive)
#[allow(non_snake_case)]
pub fn build_swap_escrow_script(
    k_b_point: &[u8; 32],
    k_b_prime: &[u8; 32],
    alice_sc_pubkey: &[u8; 32],
    bob_sc_pubkey: &[u8; 32],
    claim_deadline: u64,
    refund_height: u64,
) -> Vec<Opcode> {
    // Stack traces:
    //
    // CLAIM (witness = [k_b]):
    //   init:               [k_b]
    //   Dup:                [k_b, k_b]
    //   If (pops copy):     [k_b]          -> truthy -> IF branch
    //   CheckLockTimeExpiry: [k_b]         (aborts if past deadline)
    //   Push(K_b):          [k_b, K_b]
    //   CheckKeyPairVerify: []             (pops both; aborts if k_b*G != K_b)
    //   Push(alice_pk):     [alice_pk]
    //   Push(K_b'):         [alice_pk, K_b']
    //   RevealSecret:       []             (pops both; emits reveal event)
    //   Push(1):            [0x01]         -> truthy -> valid 
    //
    // REFUND (witness = [message, sig, 0x00]):
    //   init:               [message, sig, 0x00]
    //   Dup:                [message, sig, 0x00, 0x00]
    //   If (pops 0x00):     [message, sig, 0x00]  -> falsy -> ELSE branch
    //   Drop:               [message, sig]
    //   CheckLockTimeVerify: [message, sig]        (aborts if too early)
    //   Push(bob_pk):       [message, sig, bob_pk]
    //   Swap:               [message, bob_pk, sig]  (sig on top for CheckSig)
    //   CheckSigVerify:     []                      (aborts if sig invalid)
    //   Push(1):            [0x01]          -> truthy -> valid 

    vec![
        Opcode::Dup,
        Opcode::If,

        // -- Claim path ---------------------------------------------------
        Opcode::CheckLockTimeExpiry(claim_deadline),
        Opcode::Push(k_b_point.to_vec()),
        Opcode::CheckKeyPairVerify,
        Opcode::Push(alice_sc_pubkey.to_vec()),
        Opcode::Push(k_b_prime.to_vec()),
        Opcode::RevealSecret,
        Opcode::Push(vec![0x01]),

        // -- Refund path --------------------------------------------------
        Opcode::Else,

        Opcode::Drop,
        Opcode::CheckLockTimeVerify(refund_height),
        Opcode::Push(bob_sc_pubkey.to_vec()),
        Opcode::Swap,
        Opcode::CheckSigVerify,
        Opcode::Push(vec![0x01]),

        Opcode::EndIf,
    ]
}

/// Witness items for the claim path.
///
/// `k_b`: Bob's private key contribution (32 bytes, non-zero).
/// k_b is truthy, so it selects the IF branch after Dup.
pub fn claim_witness(k_b: &[u8; 32]) -> Vec<Vec<u8>> {
    vec![k_b.to_vec()]
}

/// Witness items for the refund path.
///
/// Ordering: message (deepest), sig, flag (top = 0x00 falsy).
/// The 0x00 flag selects the ELSE branch.
pub fn refund_witness(sig: &[u8; 64], message: &[u8; 32]) -> Vec<Vec<u8>> {
    vec![
        message.to_vec(), // deepest (w[0])
        sig.to_vec(),     // middle  (w[1])
        vec![0x00],       // top     (w[2]) ; falsy, selects ELSE
    ]
}

pub use crate::opcode::{deserialize_script, serialize_script};
