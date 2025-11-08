//! View key exchange and lock verification.
//!
//! Each party shares the view key (view_scalar) so the counterparty can
//! independently verify that funds were locked to the joint address with
//! the correct amount. The spend key remains split -- only the view key
//! is shared.
//!
//! Flow:
//! 1. Alice and Bob exchange view_scalar during key exchange phase
//! 2. After Alice locks XMR, Bob uses (joint_spend_point, view_scalar)
//!    to scan the XMR chain and verify Alice's lock amount
//! 3. After Bob locks WOW, Alice uses (joint_spend_point, view_scalar)
//!    to scan the WOW chain and verify Bob's lock amount

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

use crate::{CryptoNoteWallet, ScanResult, WalletError};

/// Verify that the counterparty locked the expected amount to the joint address.
///
/// Returns the ScanResult if verification succeeds, or an error if:
/// - No outputs found at the joint address
/// - The locked amount does not match the expected amount
pub async fn verify_lock<W: CryptoNoteWallet>(
    wallet: &W,
    joint_spend_point: &EdwardsPoint,
    view_scalar: &Scalar,
    expected_amount: u64,
    from_height: u64,
) -> Result<ScanResult, WalletError> {
    let results = wallet.scan(joint_spend_point, view_scalar, from_height).await?;

    if results.is_empty() {
        return Err(WalletError::NoOutputsFound);
    }

    // Sum all outputs at the joint address
    let total: u64 = results.iter().map(|r| r.amount).sum();

    if total < expected_amount {
        return Err(WalletError::InsufficientFunds {
            need: expected_amount,
            have: total,
        });
    }

    // Return the first (or largest) output as the primary lock result
    Ok(results
        .into_iter()
        .max_by_key(|r| r.amount)
        .expect("results is non-empty"))
}
