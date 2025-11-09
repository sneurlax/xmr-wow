//! XMR-WOW atomic swap CLI.
//!
//! Commands cover setup, lock coordination, claim flow, refunds, and wallet
//! helpers. Swap messages use `xmrwow1:<base64>`, and all signing stays local.

use clap::{Parser, Subcommand};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use xmr_wow_client::{
    SwapState, SwapRole, SwapParams, SwapStore,
    ProtocolMessage, encode_message, decode_message,
    derive_key, encrypt_secret, decrypt_secret,
    validate_timelocks, restore_secret_into_state,
};
use xmr_wow_crypto::{keccak256, KeyContribution, encode_address, derive_view_key, Network, mnemonic_to_scalar, scalar_to_mnemonic, SeedCoin};
use xmr_wow_wallet::{CryptoNoteWallet, XmrWallet, WowWallet, TxHash};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;

#[derive(Parser)]
#[command(name = "xmr-wow", about = "XMR\u{2194}WOW atomic swap client")]
struct Cli {
    /// Password for encrypting secret keys (prompted if not provided)
    #[arg(long)]
    password: Option<String>,

    /// Path to the swap database file
    #[arg(long, default_value = "xmr-wow-swaps.db")]
    db: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Alice: initiate a new swap (Alice locks XMR, receives WOW)
    InitAlice {
        /// Amount of XMR to swap (atomic units)
        #[arg(long)]
        amount_xmr: u64,
        /// Amount of WOW to receive (atomic units)
        #[arg(long)]
        amount_wow: u64,
        /// XMR lock period in blocks
        #[arg(long, default_value = "1000")]
        xmr_lock_blocks: u64,
        /// WOW lock period in blocks
        #[arg(long, default_value = "500")]
        wow_lock_blocks: u64,
    },
    /// Bob: respond to Alice's swap initiation
    InitBob {
        /// Alice's xmrwow1: initiation message
        #[arg(long)]
        message: String,
    },
    /// Import counterparty's response message to advance swap state
    Import {
        /// Swap ID (hex) to import the response into
        #[arg(long)]
        swap_id: String,
        /// Counterparty's xmrwow1: response message
        #[arg(long)]
        message: String,
    },
    /// Show the status of a swap
    Show {
        /// Swap ID (hex)
        swap_id: String,
    },
    /// List all tracked swaps
    List {
        /// Show all swaps including orphaned temp-ID entries
        #[arg(long)]
        all: bool,
    },
    /// Alice: verify Bob's WOW lock and lock XMR (second lock)
    LockXmr {
        #[arg(long)]
        swap_id: String,
        #[arg(long)]
        xmr_daemon: String,
        #[arg(long)]
        wow_daemon: String,
        /// Sender's private spend key (64 hex chars)
        #[arg(long)]
        spend_key: Option<String>,
        /// Sender's private view key (64 hex chars)
        #[arg(long)]
        view_key: Option<String>,
        /// 25-word mnemonic seed (alternative to --spend-key/--view-key)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Block height to start scanning from (avoids full rescan)
        #[arg(long, default_value = "0")]
        scan_from: u64,
    },
    /// Bob: lock WOW to the joint address (first lock)
    LockWow {
        #[arg(long)]
        swap_id: String,
        #[arg(long)]
        wow_daemon: String,
        /// Sender's private spend key (64 hex chars)
        #[arg(long)]
        spend_key: Option<String>,
        /// Sender's private view key (64 hex chars)
        #[arg(long)]
        view_key: Option<String>,
        /// 25-word mnemonic seed (alternative to --spend-key/--view-key)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Block height to start scanning from (avoids full rescan)
        #[arg(long, default_value = "0")]
        scan_from: u64,
    },
    /// Exchange adaptor pre-signatures after both parties lock
    ExchangePreSig {
        #[arg(long)]
        swap_id: String,
        /// Counterparty's xmrwow1: adaptor pre-sig message
        #[arg(long)]
        message: String,
    },
    /// Alice: claim WOW using Bob's completed adaptor signature
    ClaimWow {
        #[arg(long)]
        swap_id: String,
        #[arg(long)]
        wow_daemon: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        destination: String,
        #[arg(long, default_value = "0")]
        scan_from: u64,
    },
    /// Bob: claim XMR using Alice's completed adaptor signature
    ClaimXmr {
        #[arg(long)]
        swap_id: String,
        #[arg(long)]
        xmr_daemon: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        destination: String,
        #[arg(long, default_value = "0")]
        scan_from: u64,
    },
    /// Generate a ClaimProof from an adaptor pre-sig and private spend key
    GenerateClaimProof {
        /// The xmrwow1: adaptor pre-sig message
        #[arg(long)]
        presig: String,
        /// The private spend key (hex)
        #[arg(long)]
        spend_key: String,
    },
    /// Refund locked funds after timelock expires
    Refund {
        #[arg(long)]
        swap_id: String,
        #[arg(long)]
        xmr_daemon: Option<String>,
        #[arg(long)]
        wow_daemon: Option<String>,
    },
    /// Resume a swap from stored state
    Resume {
        #[arg(long)]
        swap_id: String,
    },
    /// Generate a random wallet keypair and print the CryptoNote address
    GenerateWallet {
        /// Network: xmr-stagenet, xmr-mainnet, or wow-mainnet
        #[arg(long)]
        network: String,
        /// Import from existing 25-word mnemonic instead of generating random
        #[arg(long)]
        mnemonic: Option<String>,
    },
    /// Emit the local refund secret for the counterparty.
    /// Only send it after both lock transactions are confirmed.
    GenerateRefundCooperate {
        /// Swap ID (hex)
        #[arg(long)]
        swap_id: String,
    },
    /// Build and store a timelocked refund transaction.
    BuildRefund {
        /// Swap ID (hex)
        #[arg(long)]
        swap_id: String,
        /// RefundCooperate message from counterparty (xmrwow1:... encoded)
        #[arg(long)]
        cooperate_msg: String,
        /// Refund destination address (your personal wallet address)
        #[arg(long)]
        destination: String,
        /// XMR daemon URL (for Alice's XMR refund)
        #[arg(long)]
        xmr_daemon: Option<String>,
        /// WOW daemon URL (for Bob's WOW refund)
        #[arg(long)]
        wow_daemon: Option<String>,
        /// Block height to start scanning from
        #[arg(long, default_value = "0")]
        scan_from: u64,
    },
    /// Broadcast the stored refund transaction after expiry.
    BroadcastRefund {
        /// Swap ID (hex)
        #[arg(long)]
        swap_id: String,
        /// XMR daemon URL (for Alice's XMR refund)
        #[arg(long)]
        xmr_daemon: Option<String>,
        /// WOW daemon URL (for Bob's WOW refund)
        #[arg(long)]
        wow_daemon: Option<String>,
    },
    /// Debug: scan a wallet for outputs without running a swap
    ScanTest {
        /// Network: xmr-stagenet or wow-mainnet
        #[arg(long)]
        network: String,
        #[arg(long)]
        daemon: String,
        #[arg(long)]
        spend_key: Option<String>,
        #[arg(long)]
        view_key: Option<String>,
        #[arg(long)]
        mnemonic: Option<String>,
        #[arg(long, default_value = "0")]
        scan_from: u64,
    },
}

/// Return the CLI password or prompt for one.
fn get_password(cli_password: Option<&str>) -> anyhow::Result<String> {
    match cli_password {
        Some(pw) => Ok(pw.to_string()),
        None => Ok(rpassword::prompt_password("Enter swap password: ")?),
    }
}

/// Parse a hex swap id.
fn parse_swap_id(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        anyhow::bail!("swap_id must be 64 hex chars (32 bytes), got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a 64-char hex string into a curve25519-dalek Scalar.
///
/// Uses `from_canonical_bytes` to reject non-canonical inputs (>= group order l).
/// Does NOT use `from_bytes_mod_order` which would silently reduce the key.
fn parse_scalar_hex(hex_str: &str) -> anyhow::Result<Scalar> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        anyhow::bail!("key must be 64 hex chars (32 bytes), got {} chars", hex_str.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let scalar = Scalar::from_canonical_bytes(arr)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("invalid scalar (not canonical -- value >= group order)"))?;
    Ok(scalar)
}

/// Resolve sender spend+view keys from either --mnemonic or --spend-key/--view-key.
fn resolve_sender_keys(
    mnemonic: &Option<String>,
    spend_key: &Option<String>,
    view_key: &Option<String>,
    coin: SeedCoin,
) -> anyhow::Result<(Scalar, Scalar)> {
    match mnemonic {
        Some(words) => {
            let spend = mnemonic_to_scalar(words, coin)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let view = derive_view_key(&spend);
            Ok((spend, view))
        }
        None => {
            let sk = spend_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("provide --mnemonic or --spend-key + --view-key"))?;
            let vk = view_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("provide --view-key with --spend-key"))?;
            Ok((parse_scalar_hex(sk)?, parse_scalar_hex(vk)?))
        }
    }
}

/// Extract the phase name from a SwapState for display.
fn phase_name(state: &SwapState) -> &'static str {
    match state {
        SwapState::KeyGeneration { .. } => "KeyGeneration",
        SwapState::DleqExchange { .. } => "DleqExchange",
        SwapState::JointAddress { .. } => "JointAddress",
        SwapState::XmrLocked { .. } => "XmrLocked",
        SwapState::WowLocked { .. } => "WowLocked",
        SwapState::Complete { .. } => "Complete",
        SwapState::Refunded { .. } => "Refunded",
    }
}

/// Extract the role from a SwapState for display.
fn role_name(state: &SwapState) -> &'static str {
    match state {
        SwapState::KeyGeneration { role, .. }
        | SwapState::DleqExchange { role, .. }
        | SwapState::JointAddress { role, .. }
        | SwapState::XmrLocked { role, .. }
        | SwapState::WowLocked { role, .. }
        | SwapState::Complete { role, .. }
        | SwapState::Refunded { role, .. } => match role {
            SwapRole::Alice => "Alice",
            SwapRole::Bob => "Bob",
        },
    }
}

/// Poll for transaction confirmation with exponential backoff.
///
/// Blocks until the transaction reaches `required` confirmations or
/// `max_retries` attempts are exhausted. The poll interval starts at
/// `initial_poll_secs` and doubles each attempt, capped at 120 seconds.
async fn wait_for_confirmation(
    wallet: &dyn CryptoNoteWallet,
    tx_hash: &TxHash,
    required: u64,
    initial_poll_secs: u64,
) -> anyhow::Result<()> {
    let max_retries: u32 = 30;
    let max_interval_secs: u64 = 120; // 2 min cap
    let mut interval_secs = initial_poll_secs;
    let mut attempts: u32 = 0;

    loop {
        match wallet.poll_confirmation(tx_hash, required).await {
            Ok(status) if status.confirmed => {
                println!("Confirmed at height {}", status.block_height.unwrap_or(0));
                return Ok(());
            }
            Ok(status) => {
                println!("Waiting... {} of {} confirmations (attempt {}/{})",
                    status.confirmations, required, attempts + 1, max_retries);
                attempts += 1;
                if attempts >= max_retries {
                    anyhow::bail!(
                        "confirmation timeout after {} attempts (~{} minutes). \
                         Transaction {} may still confirm later. \
                         Re-run with the same swap_id to resume polling.",
                        max_retries,
                        (max_retries as u64 * interval_secs) / 60,
                        hex::encode(tx_hash)
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
                interval_secs = (interval_secs * 2).min(max_interval_secs);
            }
            Err(e) => {
                attempts += 1;
                eprintln!("Poll error (attempt {}/{}): {}", attempts, max_retries, e);
                if attempts >= max_retries {
                    anyhow::bail!(
                        "confirmation polling failed after {} attempts: {}. \
                         Check that the daemon is running. \
                         Re-run with the same swap_id to resume.",
                        max_retries, e
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
                interval_secs = (interval_secs * 2).min(max_interval_secs);
            }
        }
    }
}

/// Load swap state from the store, decrypt the secret, and restore it.
///
/// Returns (state_with_secret, secret_bytes, encrypted_blob).
fn load_and_decrypt_state(
    store: &SwapStore,
    swap_id: &[u8; 32],
    enc_key: &[u8; 32],
) -> anyhow::Result<(SwapState, [u8; 32], Vec<u8>)> {
    let (state_json, encrypted_secret) = store
        .load_with_secret(swap_id)?
        .ok_or_else(|| anyhow::anyhow!("swap {} not found", hex::encode(swap_id)))?;

    let encrypted_blob = encrypted_secret
        .ok_or_else(|| anyhow::anyhow!("no encrypted secret found for swap {}", hex::encode(swap_id)))?;

    let secret_bytes = decrypt_secret(enc_key, &encrypted_blob)
        .map_err(|e| anyhow::anyhow!("failed to decrypt secret: {}", e))?;

    let state: SwapState = serde_json::from_str(&state_json)?;
    let state = restore_secret_into_state(state, secret_bytes)?;

    Ok((state, secret_bytes, encrypted_blob))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let store = SwapStore::open(&cli.db)?;

    match cli.cmd {
        Command::InitAlice {
            amount_xmr,
            amount_wow,
            xmr_lock_blocks,
            wow_lock_blocks,
        } => {
            // Validate amounts (ERR-02)
            if amount_xmr == 0 {
                anyhow::bail!("--amount-xmr must be greater than 0");
            }
            if amount_wow == 0 {
                anyhow::bail!("--amount-wow must be greater than 0");
            }

            // Validate timelock sanity cap (ERR-02)
            if xmr_lock_blocks > 10000 {
                anyhow::bail!("--xmr-lock-blocks {} exceeds maximum 10000 (would lock funds for months)", xmr_lock_blocks);
            }
            if wow_lock_blocks > 10000 {
                anyhow::bail!("--wow-lock-blocks {} exceeds maximum 10000 (would lock funds for months)", wow_lock_blocks);
            }

            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            // Validate timelock ordering (using 0 for current heights since
            // we store absolute lock blocks as relative offsets for now)
            let (xmr_refund_height, wow_refund_height) =
                validate_timelocks(0, 0, xmr_lock_blocks, wow_lock_blocks)?;

            let params = SwapParams {
                amount_xmr,
                amount_wow,
                xmr_refund_height,
                wow_refund_height,
                alice_refund_address: None,
                bob_refund_address: None,
            };

            // Generate key contribution
            let (state, secret_bytes) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

            // Encrypt secret BEFORE any output (Pitfall 1)
            let encrypted = encrypt_secret(&enc_key, &secret_bytes);

            // Extract pubkey and proof for the protocol message
            let (my_pubkey, my_proof) = match &state {
                SwapState::KeyGeneration { my_pubkey, my_proof, .. } => (*my_pubkey, my_proof.clone()),
                _ => unreachable!(),
            };

            // Temp swap_id = Keccak256(alice_pubkey) until we know Bob's pubkey
            let temp_id = keccak256(&my_pubkey);

            // Persist encrypted state + secret
            let state_json = serde_json::to_string(&state)?;
            store.save_with_secret(&temp_id, &state_json, Some(&encrypted))?;

            // Build and encode the Init message
            let msg = ProtocolMessage::Init {
                pubkey: my_pubkey,
                proof: my_proof,
                amount_xmr,
                amount_wow,
                xmr_refund_height,
                wow_refund_height,
            };
            let encoded = encode_message(&msg);

            println!("Swap initialized as Alice.");
            println!("Temp swap ID: {}", hex::encode(temp_id));
            println!();
            println!("Send this message to Bob:");
            println!("{}", encoded);
        }

        Command::InitBob { message } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            // Decode Alice's init message
            let init_msg: ProtocolMessage = decode_message(&message)?;
            let (alice_pubkey, alice_proof, amount_xmr, amount_wow, xmr_refund_height, wow_refund_height) =
                match init_msg {
                    ProtocolMessage::Init {
                        pubkey,
                        proof,
                        amount_xmr,
                        amount_wow,
                        xmr_refund_height,
                        wow_refund_height,
                    } => (pubkey, proof, amount_xmr, amount_wow, xmr_refund_height, wow_refund_height),
                    _ => anyhow::bail!("Expected Init message from Alice"),
                };

            let params = SwapParams {
                amount_xmr,
                amount_wow,
                xmr_refund_height,
                wow_refund_height,
                alice_refund_address: None,
                bob_refund_address: None,
            };

            // Generate Bob's key contribution
            let (state, secret_bytes) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);

            // Encrypt secret BEFORE any output (Pitfall 1)
            let encrypted = encrypt_secret(&enc_key, &secret_bytes);

            // Extract Bob's pubkey and proof
            let (my_pubkey, my_proof) = match &state {
                SwapState::KeyGeneration { my_pubkey, my_proof, .. } => (*my_pubkey, my_proof.clone()),
                _ => unreachable!(),
            };

            // Receive Alice's counterparty key and verify DLEQ proof
            let state = state.receive_counterparty_key(alice_pubkey, &alice_proof)?;

            // Derive joint addresses (Bob computes locally per D-04)
            let state = state.derive_joint_addresses()?;

            // Extract swap_id and addresses from JointAddress state
            let (swap_id, xmr_address, wow_address) = match &state {
                SwapState::JointAddress { addresses, .. } => {
                    (addresses.swap_id, addresses.xmr_address.clone(), addresses.wow_address.clone())
                }
                _ => unreachable!(),
            };

            // Persist state + encrypted secret
            let state_json = serde_json::to_string(&state)?;
            store.save_with_secret(&swap_id, &state_json, Some(&encrypted))?;

            // Build and encode Bob's response
            let response = ProtocolMessage::Response {
                pubkey: my_pubkey,
                proof: my_proof,
            };
            let encoded = encode_message(&response);

            println!("Swap initialized as Bob.");
            println!("Swap ID: {}", hex::encode(swap_id));
            println!("XMR joint address: {}", xmr_address);
            println!("WOW joint address: {}", wow_address);
            println!();
            println!("Send this response to Alice:");
            println!("{}", encoded);
        }

        Command::Import { swap_id, message } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let temp_id = parse_swap_id(&swap_id)?;

            // Load Alice's existing state + encrypted secret
            let (state_json, encrypted_secret) = store
                .load_with_secret(&temp_id)?
                .ok_or_else(|| anyhow::anyhow!("swap {} not found", swap_id))?;

            let encrypted_blob = encrypted_secret
                .ok_or_else(|| anyhow::anyhow!("no encrypted secret found for swap {}", swap_id))?;

            // Decrypt the secret
            let secret_bytes = decrypt_secret(&enc_key, &encrypted_blob)
                .map_err(|e| anyhow::anyhow!("failed to decrypt secret: {}", e))?;

            // Deserialize and restore secret into state
            let state: SwapState = serde_json::from_str(&state_json)?;
            let state = restore_secret_into_state(state, secret_bytes)?;

            // Decode Bob's response
            let response_msg: ProtocolMessage = decode_message(&message)?;
            let (bob_pubkey, bob_proof) = match response_msg {
                ProtocolMessage::Response { pubkey, proof } => (pubkey, proof),
                _ => anyhow::bail!("Expected Response message from Bob"),
            };

            // Verify and advance state
            let state = state.receive_counterparty_key(bob_pubkey, &bob_proof)?;
            let state = state.derive_joint_addresses()?;

            let (real_swap_id, xmr_address, wow_address) = match &state {
                SwapState::JointAddress { addresses, .. } => {
                    (addresses.swap_id, addresses.xmr_address.clone(), addresses.wow_address.clone())
                }
                _ => unreachable!(),
            };

            // Re-encrypt secret, save under real swap_id, delete temp entry
            let encrypted = encrypt_secret(&enc_key, &secret_bytes);
            let state_json = serde_json::to_string(&state)?;
            store.save_with_secret(&real_swap_id, &state_json, Some(&encrypted))?;
            if temp_id != real_swap_id {
                store.delete(&temp_id)?;
            }

            println!("Imported Bob's response successfully.");
            println!("Swap ID: {}", hex::encode(real_swap_id));
            println!("XMR joint address: {}", xmr_address);
            println!("WOW joint address: {}", wow_address);
        }

        Command::Show { swap_id } => {
            let id = parse_swap_id(&swap_id)?;
            match store.load(&id)? {
                Some(state_json) => {
                    let state: SwapState = serde_json::from_str(&state_json)?;
                    println!("Swap ID: {}", swap_id);
                    println!("Phase:   {}", phase_name(&state));
                    println!("Role:    {}", role_name(&state));

                    // Print addresses if available
                    match &state {
                        SwapState::JointAddress { addresses, params, .. }
                        | SwapState::XmrLocked { addresses, params, .. }
                        | SwapState::WowLocked { addresses, params, .. } => {
                            println!("XMR address: {}", addresses.xmr_address);
                            println!("WOW address: {}", addresses.wow_address);
                            println!("Amount XMR:  {}", params.amount_xmr);
                            println!("Amount WOW:  {}", params.amount_wow);
                        }
                        SwapState::KeyGeneration { params, .. }
                        | SwapState::DleqExchange { params, .. } => {
                            println!("Amount XMR:  {}", params.amount_xmr);
                            println!("Amount WOW:  {}", params.amount_wow);
                        }
                        SwapState::Complete { addresses, .. }
                        | SwapState::Refunded { addresses, .. } => {
                            println!("XMR address: {}", addresses.xmr_address);
                            println!("WOW address: {}", addresses.wow_address);
                        }
                    }
                }
                None => {
                    println!("Swap {} not found.", swap_id);
                }
            }
        }

        Command::List { all } => {
            let swaps = store.list_all()?;
            if swaps.is_empty() {
                println!("No swaps found.");
            } else {
                println!("{:<66}  {:<15}  {}", "SWAP ID", "PHASE", "ROLE");
                println!("{}", "-".repeat(90));
                for (id, state_json) in swaps {
                    let id_hex = hex::encode(id);
                    match serde_json::from_str::<SwapState>(&state_json) {
                        Ok(SwapState::KeyGeneration { .. }) if !all => continue,
                        Ok(state) => {
                            println!("{:<66}  {:<15}  {}", id_hex, phase_name(&state), role_name(&state));
                        }
                        Err(_) if !all => continue,
                        Err(_) => {
                            println!("{:<66}  {:<15}  {}", id_hex, "???", "???");
                        }
                    }
                }
            }
        }

        Command::LockXmr { swap_id, xmr_daemon, wow_daemon, spend_key, view_key, mnemonic, scan_from } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Verify state is WowLocked (primary) or JointAddress (fallback) and role is Alice
            let (role, params, my_pubkey, counterparty_pubkey) = match &state {
                SwapState::WowLocked { role, params, my_pubkey, counterparty_pubkey, .. } => {
                    (*role, params.clone(), *my_pubkey, *counterparty_pubkey)
                }
                SwapState::JointAddress { role, params, my_pubkey, counterparty_pubkey, .. } => {
                    (*role, params.clone(), *my_pubkey, *counterparty_pubkey)
                }
                other => anyhow::bail!("expected WowLocked or JointAddress state, got {}", phase_name(other)),
            };
            if role != SwapRole::Alice {
                anyhow::bail!("lock-xmr is for Alice only (you are Bob)");
            }

            // Compute joint spend point and view scalar
            let (joint_spend, view_scalar) = SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            // Verify Bob's WOW lock on-chain
            let wow_wallet_verify = WowWallet::new(&wow_daemon);
            let wow_height: u64 = {
                let resp: serde_json::Value = reqwest::Client::new()
                    .post(&format!("{}/json_rpc", wow_daemon))
                    .json(&serde_json::json!({"jsonrpc":"2.0","id":"0","method":"get_block_count"}))
                    .send().await?.json().await?;
                resp["result"]["count"].as_u64().unwrap_or(0)
            };
            let verify_from = wow_height.saturating_sub(500);
            println!("Verifying Bob's WOW lock (scanning {} blocks from {})...", wow_height - verify_from, verify_from);
            let scan_result = xmr_wow_wallet::verify_lock(
                &wow_wallet_verify,
                &joint_spend,
                &view_scalar,
                params.amount_wow,
                verify_from,
            ).await?;
            println!("Verified: Bob locked {} WOW at height {}", scan_result.amount, scan_result.block_height);

            // Lock XMR to the joint address
            let (sender_spend, sender_view) = resolve_sender_keys(&mnemonic, &spend_key, &view_key, SeedCoin::Monero)?;
            let xmr_wallet = XmrWallet::with_sender_keys(&xmr_daemon, sender_spend, sender_view)
                .with_scan_from(scan_from);
            println!("Locking {} XMR atomic units to joint address...", params.amount_xmr);
            let tx_hash = xmr_wallet.lock(&joint_spend, &view_scalar, params.amount_xmr).await?;
            println!("XMR lock tx: {}", hex::encode(tx_hash));

            // Wait for confirmation (FLOW-08)
            println!("Waiting for confirmation...");
            wait_for_confirmation(&xmr_wallet, &tx_hash, 1, 10).await?;

            // Transition state
            let state = state.record_xmr_lock(tx_hash)?;

            // Extract the adaptor pre-sig for sending to Bob
            let my_adaptor_pre_sig = match &state {
                SwapState::XmrLocked { my_adaptor_pre_sig, .. } => my_adaptor_pre_sig.clone(),
                _ => unreachable!(),
            };

            // Print protocol message FIRST (user always has it even if save fails)
            let pre_sig_msg = ProtocolMessage::AdaptorPreSig { pre_sig: my_adaptor_pre_sig };
            println!("XMR locked successfully.");
            println!();
            println!("Send this adaptor pre-signature to Bob:");
            println!("{}", encode_message(&pre_sig_msg));

            // Then save state
            let swap_id_bytes = state.swap_id()
                .ok_or_else(|| anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)"))?;
            let encrypted = encrypt_secret(&enc_key, &secret_bytes);
            let state_json = serde_json::to_string(&state)?;
            store.save_with_secret(&swap_id_bytes, &state_json, Some(&encrypted))?;
        }

        Command::LockWow { swap_id, wow_daemon, spend_key, view_key, mnemonic, scan_from } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Verify state is JointAddress and role is Bob (first lock)
            let (role, params, my_pubkey, counterparty_pubkey) = match &state {
                SwapState::JointAddress { role, params, my_pubkey, counterparty_pubkey, .. } => {
                    (*role, params.clone(), *my_pubkey, *counterparty_pubkey)
                }
                other => anyhow::bail!("expected JointAddress state, got {}", phase_name(other)),
            };
            if role != SwapRole::Bob {
                anyhow::bail!("lock-wow is for Bob only (you are Alice)");
            }

            // Compute joint keys
            let (joint_spend, view_scalar) = SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            // Lock WOW to the joint address (first lock -- no prior lock to verify)
            let (sender_spend, sender_view) = resolve_sender_keys(&mnemonic, &spend_key, &view_key, SeedCoin::Wownero)?;
            let wow_wallet = WowWallet::with_sender_keys(&wow_daemon, sender_spend, sender_view)
                .with_scan_from(scan_from);
            println!("Locking {} WOW atomic units to joint address...", params.amount_wow);
            let wow_tx_hash = wow_wallet.lock(&joint_spend, &view_scalar, params.amount_wow).await?;
            println!("WOW lock tx: {}", hex::encode(wow_tx_hash));

            // Wait for confirmation (FLOW-08)
            println!("Waiting for WOW confirmation...");
            wait_for_confirmation(&wow_wallet, &wow_tx_hash, 1, 10).await?;

            // Transition from JointAddress to WowLocked
            let state = state.record_wow_lock(wow_tx_hash)?;

            // Extract Bob's adaptor pre-sig
            let my_adaptor_pre_sig = match &state {
                SwapState::WowLocked { my_adaptor_pre_sig, .. } => my_adaptor_pre_sig.clone(),
                _ => unreachable!(),
            };

            // Print protocol message FIRST (user always has it even if save fails)
            let pre_sig_msg = ProtocolMessage::AdaptorPreSig { pre_sig: my_adaptor_pre_sig };
            println!("WOW locked successfully.");
            println!();
            println!("Send this adaptor pre-signature to Alice:");
            println!("{}", encode_message(&pre_sig_msg));

            // Then save state
            let swap_id_bytes = state.swap_id()
                .ok_or_else(|| anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)"))?;
            let encrypted = encrypt_secret(&enc_key, &secret_bytes);
            let state_json = serde_json::to_string(&state)?;
            store.save_with_secret(&swap_id_bytes, &state_json, Some(&encrypted))?;
        }

        Command::ExchangePreSig { swap_id, message } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Decode counterparty's adaptor pre-sig
            let msg: ProtocolMessage = decode_message(&message)?;
            let pre_sig = match msg {
                ProtocolMessage::AdaptorPreSig { pre_sig } => pre_sig,
                _ => anyhow::bail!("Expected AdaptorPreSig message"),
            };

            // Validate and store
            let state = state.receive_counterparty_pre_sig(pre_sig)?;

            // Save updated state
            let swap_id_bytes = state.swap_id()
                .ok_or_else(|| anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)"))?;
            let encrypted = encrypt_secret(&enc_key, &secret_bytes);
            let state_json = serde_json::to_string(&state)?;
            store.save_with_secret(&swap_id_bytes, &state_json, Some(&encrypted))?;

            println!("Counterparty pre-signature verified and stored.");
        }

        Command::ClaimWow { swap_id, wow_daemon, message, destination, scan_from } => {
            // ADAPTOR SIG ATOMICITY: Alice claims WOW
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Verify state is WowLocked or XmrLocked (with counterparty pre-sig) and role is Alice
            let (role, my_pubkey, counterparty_pubkey, my_adaptor_pre_sig) = match &state {
                SwapState::WowLocked { role, my_pubkey, counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig, .. } |
                SwapState::XmrLocked { role, my_pubkey, counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig, .. } => {
                    if *role != SwapRole::Alice {
                        anyhow::bail!("claim-wow is for Alice only (you are Bob)");
                    }
                    if counterparty_pre_sig.is_none() {
                        anyhow::bail!("counterparty pre-sig not stored yet (run exchange-pre-sig first)");
                    }
                    (*role, *my_pubkey, *counterparty_pubkey, my_adaptor_pre_sig.clone())
                }
                other => anyhow::bail!("expected WowLocked or XmrLocked state, got {}", phase_name(other)),
            };

            // Decode Bob's ClaimProof (his completed adaptor sig)
            let claim_msg: ProtocolMessage = decode_message(&message)?;
            let bob_completed_sig = match claim_msg {
                ProtocolMessage::ClaimProof { completed_sig } => completed_sig,
                _ => anyhow::bail!("Expected ClaimProof message from Bob"),
            };

            // Extract Bob's secret via adaptor sig atomicity
            let (complete_state, bob_secret) = state.complete_with_adaptor_claim(&bob_completed_sig)?;
            println!("Extracted Bob's secret from his completed adaptor signature.");

            // Compute combined spend key: a + b
            let my_scalar = Scalar::from_canonical_bytes(secret_bytes)
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("invalid secret scalar"))?;
            let combined = my_scalar + bob_secret;

            // Compute view scalar for the joint address
            let (_, view_scalar) = SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            // Sweep WOW from joint address to Alice's destination
            let wow_wallet = WowWallet::new(&wow_daemon).with_scan_from(scan_from);
            println!("Sweeping WOW from joint address to {}...", destination);
            let sweep_tx = wow_wallet.sweep(&combined, &view_scalar, &destination).await?;
            println!("WOW sweep tx: {}", hex::encode(sweep_tx));

            // Wait for confirmation (FLOW-08)
            println!("Waiting for WOW sweep confirmation...");
            wait_for_confirmation(&wow_wallet, &sweep_tx, 1, 10).await?;

            // Alice must now reveal her secret to Bob by completing her pre-sig
            let alice_completed = my_adaptor_pre_sig.complete(&my_scalar)
                .map_err(|e| anyhow::anyhow!("failed to complete own pre-sig: {}", e))?;
            let claim_proof = ProtocolMessage::ClaimProof { completed_sig: alice_completed };

            // Print protocol message FIRST (user always has it even if save fails)
            println!("WOW claimed successfully.");
            println!();
            println!("Send this claim proof to Bob so he can claim XMR:");
            println!("{}", encode_message(&claim_proof));

            // Then save Complete state
            let swap_id_bytes = complete_state.swap_id()
                .ok_or_else(|| anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)"))?;
            let state_json = serde_json::to_string(&complete_state)?;
            // No need to store encrypted secret for Complete state
            store.save_with_secret(&swap_id_bytes, &state_json, None)?;
        }

        Command::ClaimXmr { swap_id, xmr_daemon, message, destination, scan_from } => {
            // ADAPTOR SIG ATOMICITY: Bob claims XMR
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Verify state is WowLocked and role is Bob with counterparty_pre_sig
            let (role, my_pubkey, counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig) = match &state {
                SwapState::WowLocked { role, my_pubkey, counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig, .. } => {
                    if *role != SwapRole::Bob {
                        anyhow::bail!("claim-xmr is for Bob only (you are Alice)");
                    }
                    if counterparty_pre_sig.is_none() {
                        anyhow::bail!("counterparty pre-sig not stored yet (run exchange-pre-sig first)");
                    }
                    (*role, *my_pubkey, *counterparty_pubkey, my_adaptor_pre_sig.clone(),
                     counterparty_pre_sig.clone()
                         .ok_or_else(|| anyhow::anyhow!("counterparty pre-sig not yet received (run exchange-pre-sig first)"))?)

                }
                other => anyhow::bail!("expected WowLocked state, got {}", phase_name(other)),
            };

            let my_scalar = Scalar::from_canonical_bytes(secret_bytes)
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("invalid secret scalar"))?;

            // FIRST: Bob must reveal his secret to Alice by completing his pre-sig.
            // Print the ClaimProof for Bob to send to Alice.
            let bob_completed = my_adaptor_pre_sig.complete(&my_scalar)
                .map_err(|e| anyhow::anyhow!("failed to complete own pre-sig: {}", e))?;
            let bob_claim_proof = ProtocolMessage::ClaimProof { completed_sig: bob_completed };

            println!("Your claim proof (send to Alice FIRST):");
            println!("{}", encode_message(&bob_claim_proof));
            println!();

            // Decode Alice's ClaimProof (her completed adaptor sig)
            let claim_msg: ProtocolMessage = decode_message(&message)?;
            let alice_completed_sig = match claim_msg {
                ProtocolMessage::ClaimProof { completed_sig } => completed_sig,
                _ => anyhow::bail!("Expected ClaimProof message from Alice"),
            };

            // Extract Alice's secret via adaptor sig atomicity
            let alice_secret = counterparty_pre_sig.extract_secret(&alice_completed_sig)
                .map_err(|e| anyhow::anyhow!("secret extraction failed: {}", e))?;

            // Verify: alice_secret * G == counterparty_pubkey (Alice's pubkey)
            let alice_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                .map_err(|e| anyhow::anyhow!("invalid counterparty pubkey: {}", e))?;
            if (alice_secret * G).compress() != alice_point.compress() {
                anyhow::bail!("extracted secret does not match Alice's pubkey");
            }
            println!("Extracted Alice's secret from her completed adaptor signature.");

            // Compute combined spend key: a + b
            let combined = alice_secret + my_scalar;

            // Compute view scalar
            let (_, view_scalar) = SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            // Sweep XMR from joint address to Bob's destination
            let xmr_wallet = XmrWallet::new(&xmr_daemon).with_scan_from(scan_from);
            println!("Sweeping XMR from joint address to {}...", destination);
            let sweep_tx = xmr_wallet.sweep(&combined, &view_scalar, &destination).await?;
            println!("XMR sweep tx: {}", hex::encode(sweep_tx));

            // Wait for confirmation (FLOW-08)
            println!("Waiting for XMR sweep confirmation...");
            wait_for_confirmation(&xmr_wallet, &sweep_tx, 1, 10).await?;

            // Transition to Complete
            let k_b_revealed = alice_secret.to_bytes();
            let complete_state = SwapState::Complete {
                role,
                addresses: match &state {
                    SwapState::WowLocked { addresses, .. } => addresses.clone(),
                    _ => unreachable!(),
                },
                k_b_revealed,
            };

            // Save Complete state
            let swap_id_bytes = complete_state.swap_id()
                .ok_or_else(|| anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)"))?;
            let state_json = serde_json::to_string(&complete_state)?;
            store.save_with_secret(&swap_id_bytes, &state_json, None)?;

            println!("XMR claimed. Swap complete.");
        }

        Command::GenerateClaimProof { presig, spend_key } => {
            let presig_msg: ProtocolMessage = decode_message(&presig)?;
            let pre_sig = match presig_msg {
                ProtocolMessage::AdaptorPreSig { pre_sig } => pre_sig,
                _ => anyhow::bail!("Expected AdaptorPreSig message"),
            };
            let key_bytes = hex::decode(&spend_key)?;
            let key_arr: [u8; 32] = key_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("spend key must be 32 bytes"))?;
            let scalar = Scalar::from_canonical_bytes(key_arr)
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("invalid scalar"))?;

            let completed = pre_sig.complete(&scalar)
                .map_err(|e| anyhow::anyhow!("failed to complete pre-sig: {}", e))?;
            let claim_proof = ProtocolMessage::ClaimProof { completed_sig: completed };
            println!("{}", encode_message(&claim_proof));
        }

        Command::Refund { swap_id, xmr_daemon, wow_daemon } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, _secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Determine which chain to refund based on role and state
            let (role, params, addresses) = match &state {
                SwapState::XmrLocked { role, params, addresses, .. } => (*role, params.clone(), addresses.clone()),
                SwapState::WowLocked { role, params, addresses, .. } => (*role, params.clone(), addresses.clone()),
                other => anyhow::bail!("cannot refund from {} state", phase_name(other)),
            };

            match role {
                SwapRole::Alice => {
                    // Alice refunds XMR after xmr_refund_height
                    let xmr_daemon_url = xmr_daemon
                        .ok_or_else(|| anyhow::anyhow!("--xmr-daemon required for Alice refund"))?;
                    let xmr_wallet = XmrWallet::new(&xmr_daemon_url);

                    let current_height = xmr_wallet.get_current_height().await?;
                    if current_height < params.xmr_refund_height {
                        let remaining = params.xmr_refund_height - current_height;
                        anyhow::bail!(
                            "XMR timelock not expired. Current height: {}, refund height: {}, {} blocks remaining.",
                            current_height, params.xmr_refund_height, remaining
                        );
                    }

                    println!("XMR timelock expired (height {} >= {}).", current_height, params.xmr_refund_height);
                    println!();

                    // Check if a pre-signed refund tx exists
                    let has_refund_tx = match &state {
                        SwapState::XmrLocked { xmr_refund_tx, .. } => xmr_refund_tx.is_some(),
                        _ => false,
                    };
                    if has_refund_tx {
                        println!("Pre-signed refund tx found. Use `broadcast-refund --swap-id {}` to broadcast.", swap_id);
                    } else {
                        println!("REFUND STATUS: Timelock has expired.");
                        println!("Funds locked to the joint address require the combined key (a+b) to sweep.");
                        println!("Alice's XMR is at the joint address:");
                        println!("  {}", addresses.xmr_address);
                        println!();
                        println!("To construct a refund tx, exchange secrets with your counterparty using");
                        println!("`generate-refund-cooperate` and `build-refund`.");
                    }
                    println!();
                    println!("Marking swap as Refunded.");

                    // Transition to Refunded
                    let refunded = state.complete_with_refund(None)?;
                    let state_json = serde_json::to_string(&refunded)?;
                    store.save_with_secret(&id, &state_json, None)?;
                    println!("Swap marked as Refunded.");
                }
                SwapRole::Bob => {
                    // Bob refunds WOW after wow_refund_height
                    let wow_daemon_url = wow_daemon
                        .ok_or_else(|| anyhow::anyhow!("--wow-daemon required for Bob refund"))?;
                    let wow_wallet = WowWallet::new(&wow_daemon_url);

                    let current_height = wow_wallet.get_current_height().await?;
                    if current_height < params.wow_refund_height {
                        let remaining = params.wow_refund_height - current_height;
                        anyhow::bail!(
                            "WOW timelock not expired. Current height: {}, refund height: {}, {} blocks remaining.",
                            current_height, params.wow_refund_height, remaining
                        );
                    }

                    println!("WOW timelock expired (height {} >= {}).", current_height, params.wow_refund_height);
                    println!();

                    // Check if a pre-signed refund tx exists
                    let has_refund_tx = match &state {
                        SwapState::WowLocked { wow_refund_tx, .. } => wow_refund_tx.is_some(),
                        _ => false,
                    };
                    if has_refund_tx {
                        println!("Pre-signed refund tx found. Use `broadcast-refund --swap-id {}` to broadcast.", swap_id);
                    } else {
                        println!("REFUND STATUS: Timelock has expired.");
                        println!("Funds locked to the joint address require the combined key (a+b) to sweep.");
                        println!("Bob's WOW is at the joint address:");
                        println!("  {}", addresses.wow_address);
                        println!();
                        println!("To construct a refund tx, exchange secrets with your counterparty using");
                        println!("`generate-refund-cooperate` and `build-refund`.");
                    }
                    println!();
                    println!("Marking swap as Refunded.");

                    // Transition to Refunded
                    let refunded = state.complete_with_refund(None)?;
                    let state_json = serde_json::to_string(&refunded)?;
                    store.save_with_secret(&id, &state_json, None)?;
                    println!("Swap marked as Refunded.");
                }
            }
        }

        Command::GenerateRefundCooperate { swap_id } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Determine the lock tx hash based on role and state
            let lock_tx_hash = match &state {
                SwapState::WowLocked { role, wow_lock_tx, .. } => {
                    match role {
                        SwapRole::Bob => *wow_lock_tx,
                        SwapRole::Alice => anyhow::bail!("Alice should use XmrLocked state for refund cooperation"),
                    }
                }
                SwapState::XmrLocked { role, xmr_lock_tx, wow_lock_tx, .. } => {
                    match role {
                        SwapRole::Alice => *xmr_lock_tx,
                        SwapRole::Bob => *wow_lock_tx,
                    }
                }
                other => anyhow::bail!("cannot generate refund cooperate from {} state", phase_name(other)),
            };

            let msg = ProtocolMessage::RefundCooperate {
                secret_scalar: secret_bytes,
                lock_tx_hash,
            };
            let encoded = encode_message(&msg);

            println!("RefundCooperate message generated.");
            println!("WARNING: This reveals your secret scalar. Only share AFTER lock tx is confirmed.");
            println!();
            println!("Send this to your counterparty:");
            println!("{}", encoded);
        }

        Command::BuildRefund { swap_id, cooperate_msg, destination, xmr_daemon, wow_daemon, scan_from } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Decode the RefundCooperate message
            let cooperate: ProtocolMessage = decode_message(&cooperate_msg)?;
            let (counterparty_secret_bytes, _lock_tx_hash) = match cooperate {
                ProtocolMessage::RefundCooperate { secret_scalar, lock_tx_hash } => (secret_scalar, lock_tx_hash),
                _ => anyhow::bail!("Expected RefundCooperate message"),
            };

            // Parse and verify the counterparty's secret scalar
            let counterparty_scalar = Scalar::from_canonical_bytes(counterparty_secret_bytes)
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("invalid counterparty secret scalar (not canonical)"))?;

            // Extract role, params, pubkeys, and verify counterparty scalar matches their pubkey
            let (role, params, my_pubkey, counterparty_pubkey) = match &state {
                SwapState::WowLocked { role, params, my_pubkey, counterparty_pubkey, .. } => {
                    (*role, params.clone(), *my_pubkey, *counterparty_pubkey)
                }
                SwapState::XmrLocked { role, params, my_pubkey, counterparty_pubkey, .. } => {
                    (*role, params.clone(), *my_pubkey, *counterparty_pubkey)
                }
                other => anyhow::bail!("cannot build refund from {} state", phase_name(other)),
            };

            // Verify: counterparty_scalar * G == counterparty_pubkey
            let counterparty_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                .map_err(|e| anyhow::anyhow!("invalid counterparty pubkey: {}", e))?;
            let computed_point = counterparty_scalar * G;
            if computed_point.compress() != counterparty_point.compress() {
                anyhow::bail!("counterparty's secret scalar does not match their pubkey");
            }
            println!("Counterparty secret verified against their pubkey.");

            // Combine secrets: my_scalar + counterparty_scalar
            let my_scalar = Scalar::from_canonical_bytes(secret_bytes)
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("invalid secret scalar"))?;
            let combined = my_scalar + counterparty_scalar;

            // Compute view scalar
            let (_, view_scalar) = SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            // Build the timelocked refund tx based on role
            match role {
                SwapRole::Bob => {
                    // Bob refunds WOW
                    let wow_daemon_url = wow_daemon
                        .ok_or_else(|| anyhow::anyhow!("--wow-daemon required for Bob's WOW refund"))?;
                    let wow_wallet = WowWallet::new(&wow_daemon_url).with_scan_from(scan_from);

                    println!("Constructing timelocked WOW refund tx (unlock at block {})...", params.wow_refund_height);
                    let (tx_hash, tx_bytes) = wow_wallet.sweep_timelocked(
                        &combined,
                        &view_scalar,
                        &destination,
                        params.wow_refund_height,
                    ).await?;

                    // Update state with refund tx bytes and refund address
                    let updated_state = match state {
                        SwapState::WowLocked {
                            role, mut params, addresses, wow_lock_tx, my_pubkey,
                            counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig,
                            adaptor_point, secret_bytes, ..
                        } => {
                            params.bob_refund_address = Some(destination.clone());
                            SwapState::WowLocked {
                                role, params, addresses, wow_lock_tx, my_pubkey,
                                counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig,
                                adaptor_point, wow_refund_tx: Some(tx_bytes), secret_bytes,
                            }
                        }
                        SwapState::XmrLocked {
                            role, mut params, addresses, wow_lock_tx, xmr_lock_tx, my_pubkey,
                            counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig,
                            adaptor_point, xmr_refund_tx, secret_bytes, ..
                        } => {
                            // Bob in XmrLocked: store refund info but XmrLocked only has xmr_refund_tx field
                            // Use complete_with_refund path instead -- for now store in xmr_refund_tx
                            params.bob_refund_address = Some(destination.clone());
                            SwapState::XmrLocked {
                                role, params, addresses, wow_lock_tx, xmr_lock_tx, my_pubkey,
                                counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig,
                                adaptor_point, xmr_refund_tx, secret_bytes,
                            }
                        }
                        _ => unreachable!(),
                    };

                    // Save updated state
                    let swap_id_bytes = updated_state.swap_id()
                        .ok_or_else(|| anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)"))?;
                    let encrypted = encrypt_secret(&enc_key, &secret_bytes);
                    let state_json = serde_json::to_string(&updated_state)?;
                    store.save_with_secret(&swap_id_bytes, &state_json, Some(&encrypted))?;

                    println!("Refund tx constructed (hash: {}).", hex::encode(tx_hash));
                    println!("Timelocked until block {}.", params.wow_refund_height);
                    println!("Run `broadcast-refund --swap-id {}` after block {} to broadcast.", swap_id, params.wow_refund_height);
                }
                SwapRole::Alice => {
                    // Alice refunds XMR
                    let xmr_daemon_url = xmr_daemon
                        .ok_or_else(|| anyhow::anyhow!("--xmr-daemon required for Alice's XMR refund"))?;
                    let xmr_wallet = XmrWallet::new(&xmr_daemon_url).with_scan_from(scan_from);

                    println!("Constructing timelocked XMR refund tx (unlock at block {})...", params.xmr_refund_height);
                    let (tx_hash, tx_bytes) = xmr_wallet.sweep_timelocked(
                        &combined,
                        &view_scalar,
                        &destination,
                        params.xmr_refund_height,
                    ).await?;

                    // Update state with refund tx bytes and refund address
                    let updated_state = match state {
                        SwapState::XmrLocked {
                            role, mut params, addresses, wow_lock_tx, xmr_lock_tx, my_pubkey,
                            counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig,
                            adaptor_point, secret_bytes, ..
                        } => {
                            params.alice_refund_address = Some(destination.clone());
                            SwapState::XmrLocked {
                                role, params, addresses, wow_lock_tx, xmr_lock_tx, my_pubkey,
                                counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig,
                                adaptor_point, xmr_refund_tx: Some(tx_bytes), secret_bytes,
                            }
                        }
                        SwapState::WowLocked {
                            role, mut params, addresses, wow_lock_tx, my_pubkey,
                            counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig,
                            adaptor_point, wow_refund_tx, secret_bytes, ..
                        } => {
                            // Alice in WowLocked: store refund info but WowLocked only has wow_refund_tx field
                            params.alice_refund_address = Some(destination.clone());
                            SwapState::WowLocked {
                                role, params, addresses, wow_lock_tx, my_pubkey,
                                counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig,
                                adaptor_point, wow_refund_tx, secret_bytes,
                            }
                        }
                        _ => unreachable!(),
                    };

                    // Save updated state
                    let swap_id_bytes = updated_state.swap_id()
                        .ok_or_else(|| anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)"))?;
                    let encrypted = encrypt_secret(&enc_key, &secret_bytes);
                    let state_json = serde_json::to_string(&updated_state)?;
                    store.save_with_secret(&swap_id_bytes, &state_json, Some(&encrypted))?;

                    println!("Refund tx constructed (hash: {}).", hex::encode(tx_hash));
                    println!("Timelocked until block {}.", params.xmr_refund_height);
                    println!("Run `broadcast-refund --swap-id {}` after block {} to broadcast.", swap_id, params.xmr_refund_height);
                }
            }
        }

        Command::BroadcastRefund { swap_id, xmr_daemon, wow_daemon } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, _secret_bytes, _) = load_and_decrypt_state(&store, &id, &enc_key)?;

            // Extract role, params, and refund tx bytes
            let (role, params, refund_tx_bytes) = match &state {
                SwapState::WowLocked { role, params, wow_refund_tx, .. } => {
                    let tx = wow_refund_tx.as_ref()
                        .ok_or_else(|| anyhow::anyhow!("No refund tx found. Run build-refund first."))?;
                    (*role, params.clone(), tx.clone())
                }
                SwapState::XmrLocked { role, params, xmr_refund_tx, .. } => {
                    let tx = xmr_refund_tx.as_ref()
                        .ok_or_else(|| anyhow::anyhow!("No refund tx found. Run build-refund first."))?;
                    (*role, params.clone(), tx.clone())
                }
                other => anyhow::bail!("cannot broadcast refund from {} state", phase_name(other)),
            };

            // Client-side timelock check (D-03: belt and suspenders)
            match role {
                SwapRole::Bob => {
                    let wow_daemon_url = wow_daemon
                        .ok_or_else(|| anyhow::anyhow!("--wow-daemon required for Bob's WOW refund broadcast"))?;
                    let wow_wallet = WowWallet::new(&wow_daemon_url);

                    let current_height = wow_wallet.get_current_height().await?;
                    if current_height < params.wow_refund_height {
                        let remaining = params.wow_refund_height - current_height;
                        anyhow::bail!(
                            "Timelock not expired. Current: {}, target: {}, {} blocks remaining (~{} min).",
                            current_height, params.wow_refund_height, remaining, remaining * 2
                        );
                    }

                    println!("Timelock expired (height {} >= {}). Broadcasting refund tx...", current_height, params.wow_refund_height);
                    let tx_hash = wow_wallet.broadcast_raw_tx(&refund_tx_bytes).await?;

                    println!("Refund broadcast. Tx hash: {}", hex::encode(tx_hash));
                    println!("Waiting for confirmation...");
                    wait_for_confirmation(&wow_wallet, &tx_hash, 1, 10).await?;

                    // Transition to Refunded
                    let refunded = state.complete_with_refund(Some(tx_hash))?;
                    let state_json = serde_json::to_string(&refunded)?;
                    store.save_with_secret(&id, &state_json, None)?;

                    println!("Refund broadcast successful. Tx hash: {}", hex::encode(tx_hash));
                    println!("Funds returned to refund address. Swap marked as Refunded.");
                }
                SwapRole::Alice => {
                    let xmr_daemon_url = xmr_daemon
                        .ok_or_else(|| anyhow::anyhow!("--xmr-daemon required for Alice's XMR refund broadcast"))?;
                    let xmr_wallet = XmrWallet::new(&xmr_daemon_url);

                    let current_height = xmr_wallet.get_current_height().await?;
                    if current_height < params.xmr_refund_height {
                        let remaining = params.xmr_refund_height - current_height;
                        anyhow::bail!(
                            "Timelock not expired. Current: {}, target: {}, {} blocks remaining (~{} min).",
                            current_height, params.xmr_refund_height, remaining, remaining * 2
                        );
                    }

                    println!("Timelock expired (height {} >= {}). Broadcasting refund tx...", current_height, params.xmr_refund_height);
                    let tx_hash = xmr_wallet.broadcast_raw_tx(&refund_tx_bytes).await?;

                    println!("Refund broadcast. Tx hash: {}", hex::encode(tx_hash));
                    println!("Waiting for confirmation...");
                    wait_for_confirmation(&xmr_wallet, &tx_hash, 1, 10).await?;

                    // Transition to Refunded
                    let refunded = state.complete_with_refund(Some(tx_hash))?;
                    let state_json = serde_json::to_string(&refunded)?;
                    store.save_with_secret(&id, &state_json, None)?;

                    println!("Refund broadcast successful. Tx hash: {}", hex::encode(tx_hash));
                    println!("Funds returned to refund address. Swap marked as Refunded.");
                }
            }
        }

        Command::Resume { swap_id } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store.get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;

            // Load state and decrypt secret to verify password
            let (state_json, encrypted_secret) = store
                .load_with_secret(&id)?
                .ok_or_else(|| anyhow::anyhow!("swap {} not found", swap_id))?;

            let state: SwapState = serde_json::from_str(&state_json)?;

            // For terminal states (Complete, Refunded), no secret to verify
            match &state {
                SwapState::Complete { .. } | SwapState::Refunded { .. } => {
                    // No secret needed for terminal states
                }
                _ => {
                    // Verify password by decrypting the secret
                    let encrypted_blob = encrypted_secret
                        .ok_or_else(|| anyhow::anyhow!("no encrypted secret found for swap {}", swap_id))?;
                    let secret_bytes = decrypt_secret(&enc_key, &encrypted_blob)
                        .map_err(|_| anyhow::anyhow!("Wrong password"))?;

                    // Verify secret matches stored pubkey (scalar * G == pubkey)
                    let scalar = Scalar::from_canonical_bytes(secret_bytes)
                        .into_option()
                        .ok_or_else(|| anyhow::anyhow!("invalid secret scalar"))?;
                    let computed = (scalar * G).compress().to_bytes();

                    let my_pubkey = match &state {
                        SwapState::KeyGeneration { my_pubkey, .. }
                        | SwapState::DleqExchange { my_pubkey, .. }
                        | SwapState::JointAddress { my_pubkey, .. }
                        | SwapState::XmrLocked { my_pubkey, .. }
                        | SwapState::WowLocked { my_pubkey, .. } => *my_pubkey,
                        _ => unreachable!(),
                    };

                    if computed != my_pubkey {
                        anyhow::bail!("Wrong password");
                    }
                }
            }

            // Print swap status
            println!("=== Swap Resume ===");
            println!("Swap ID: {}", swap_id);
            println!("Role:    {}", role_name(&state));
            println!("Phase:   {}", phase_name(&state));

            // Print addresses and timelock info if available
            match &state {
                SwapState::JointAddress { addresses, params, .. }
                | SwapState::XmrLocked { addresses, params, .. }
                | SwapState::WowLocked { addresses, params, .. } => {
                    println!("XMR address: {}", addresses.xmr_address);
                    println!("WOW address: {}", addresses.wow_address);
                    println!("Amount XMR:  {}", params.amount_xmr);
                    println!("Amount WOW:  {}", params.amount_wow);
                    println!("XMR refund height: {}", params.xmr_refund_height);
                    println!("WOW refund height: {}", params.wow_refund_height);
                }
                SwapState::Complete { addresses, .. }
                | SwapState::Refunded { addresses, .. } => {
                    println!("XMR address: {}", addresses.xmr_address);
                    println!("WOW address: {}", addresses.wow_address);
                }
                SwapState::KeyGeneration { params, .. }
                | SwapState::DleqExchange { params, .. } => {
                    println!("Amount XMR:  {}", params.amount_xmr);
                    println!("Amount WOW:  {}", params.amount_wow);
                }
            }

            // Print next action guidance
            println!();
            println!("--- Next Action ---");
            match &state {
                SwapState::KeyGeneration { role, .. } => match role {
                    SwapRole::Alice => println!("Send the init message to Bob and wait for his response, then run import."),
                    SwapRole::Bob => println!("Send the response message to Alice."),
                },
                SwapState::DleqExchange { role, .. } => match role {
                    SwapRole::Alice => println!("Run import with Bob's response message."),
                    SwapRole::Bob => println!("Run import with Alice's init message."),
                },
                SwapState::JointAddress { role, .. } => match role {
                    SwapRole::Alice => println!("Wait for Bob to run lock-wow, then run lock-xmr --swap-id {}.", swap_id),
                    SwapRole::Bob => println!("Run lock-wow --swap-id {} to lock WOW first.", swap_id),
                },
                SwapState::XmrLocked { role, counterparty_pre_sig, .. } => match role {
                    SwapRole::Alice => {
                        if counterparty_pre_sig.is_none() {
                            println!("Send your pre-sig to Bob and run exchange-pre-sig with Bob's pre-sig.");
                        } else {
                            println!("Wait for Bob to lock WOW.");
                        }
                    }
                    SwapRole::Bob => println!("Run lock-wow --swap-id {} to lock WOW.", swap_id),
                },
                SwapState::WowLocked { role, counterparty_pre_sig, .. } => match role {
                    SwapRole::Alice => {
                        if counterparty_pre_sig.is_none() {
                            println!("Run exchange-pre-sig to import counterparty's adaptor pre-signature.");
                        } else {
                            println!("Wait for Bob's claim proof, then run claim-wow.");
                        }
                    }
                    SwapRole::Bob => {
                        if counterparty_pre_sig.is_none() {
                            println!("Run exchange-pre-sig to import counterparty's adaptor pre-signature.");
                        } else {
                            println!("Run claim-xmr to send your claim proof and claim XMR.");
                        }
                    }
                },
                SwapState::Complete { .. } => {
                    println!("Swap completed successfully. No further action needed.");
                }
                SwapState::Refunded { .. } => {
                    println!("Swap was refunded. No further action needed.");
                }
            }
        }

        Command::GenerateWallet { network, mnemonic } => {
            let (net, seed_coin) = match network.as_str() {
                "xmr-stagenet" => (Network::MoneroStagenet, SeedCoin::Monero),
                "xmr-mainnet" => (Network::MoneroMainnet, SeedCoin::Monero),
                "wow-mainnet" => (Network::Wownero, SeedCoin::Wownero),
                other => anyhow::bail!(
                    "unsupported network '{}'. Use: xmr-stagenet, xmr-mainnet, or wow-mainnet",
                    other
                ),
            };

            let spend_scalar = match mnemonic {
                Some(words) => mnemonic_to_scalar(&words, seed_coin)
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                None => Scalar::random(&mut OsRng),
            };
            let view_scalar = derive_view_key(&spend_scalar);
            let spend_pubkey = spend_scalar * G;
            let view_pubkey = view_scalar * G;
            let address = encode_address(&spend_pubkey, &view_pubkey, net);

            eprintln!("WARNING: These are private keys. Store them securely and never share them.");
            eprintln!();
            println!("Network:             {}", network);
            println!("Spend key (private): {}", hex::encode(spend_scalar.to_bytes()));
            println!("View key (private):  {}", hex::encode(view_scalar.to_bytes()));
            println!("Seed:                {}", scalar_to_mnemonic(&spend_scalar));
            println!("Address:             {}", address);
        }

        Command::ScanTest { network, daemon, spend_key, view_key, mnemonic, scan_from } => {
            let seed_coin = if network.contains("wow") { SeedCoin::Wownero } else { SeedCoin::Monero };
            let (spend_scalar, view_scalar) = resolve_sender_keys(&mnemonic, &spend_key, &view_key, seed_coin)?;
            let spend_point = spend_scalar * G;
            let view_point = view_scalar * G;

            let address = if network.contains("wow") {
                encode_address(&spend_point, &view_point, Network::Wownero)
            } else {
                encode_address(&spend_point, &view_point, Network::MoneroStagenet)
            };
            println!("Scanning {} for address {}", network, address);
            println!("Spend pubkey: {}", hex::encode(spend_point.compress().to_bytes()));
            println!("View privkey: {}", hex::encode(view_scalar.to_bytes()));
            println!("Scan from: {} to tip", scan_from);

            if network.contains("wow") {
                let wallet = WowWallet::with_sender_keys(&daemon, spend_scalar, view_scalar)
                    .with_scan_from(scan_from);
                let results = wallet.scan(&spend_point, &view_scalar, scan_from).await?;
                println!("Found {} outputs", results.len());
                for r in &results {
                    println!("  height={} amount={} tx={}", r.block_height, r.amount, hex::encode(r.tx_hash));
                }
            } else {
                let wallet = XmrWallet::with_sender_keys(&daemon, spend_scalar, view_scalar)
                    .with_scan_from(scan_from);
                let results = wallet.scan(&spend_point, &view_scalar, scan_from).await?;
                println!("Found {} outputs", results.len());
                for r in &results {
                    println!("  height={} amount={} tx={}", r.block_height, r.amount, hex::encode(r.tx_hash));
                }
            }
        }
    }

    Ok(())
}
