//! XMR-WOW atomic swap CLI.
//! Legacy refund commands are hidden and fail closed. Signing stays local.

use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use zeroize::Zeroizing;
use xmr_wow_client::{
    build_observed_refund_timing, decode_message, decrypt_secret, derive_key, encode_message,
    encrypt_secret, guarantee_decision, restore_secret_into_state, GuaranteeDecision,
    GuaranteeMode, ProtocolMessage, RefundCheckpointName, SwapParams, SwapRole, SwapState,
    SwapStore,
};
use xmr_wow_client::coord_message::{wrap_protocol_message, unwrap_protocol_message};
use xmr_wow_crypto::{
    derive_view_key, encode_address, keccak256, mnemonic_to_scalar, scalar_to_mnemonic,
    KeyContribution, Network, SeedCoin,
};
use xmr_wow_wallet::{CryptoNoteWallet, TxHash, WowWallet, XmrWallet};

/// Transport mode for swap coordination messages.
#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum TransportMode {
    /// Encode messages as `xmrwow1:` strings for manual exchange (default).
    #[default]
    #[value(name = "out-of-band")]
    OutOfBand,
    /// Relay messages via the WOW sharechain node. Requires --node-url.
    #[value(name = "sharechain")]
    Sharechain,
}

#[derive(Parser)]
#[command(name = "xmr-wow", about = "XMR\u{2194}WOW atomic swap client")]
struct Cli {
    /// Password for encrypting secret keys (prompted if not provided)
    #[arg(long)]
    password: Option<String>,

    /// Path to the swap database file
    #[arg(long, default_value = "xmr-wow-swaps.db")]
    db: String,

    /// Allow proof-harness validation flows to bypass unsupported refund checkpoints.
    #[arg(long, global = true, hide = true)]
    proof_harness: bool,

    /// Transport mode for swap coordination messages
    #[arg(long, default_value = "out-of-band")]
    transport: TransportMode,

    /// Sharechain node URL (required when --transport sharechain)
    #[arg(long)]
    node_url: Option<String>,

    #[command(subcommand)]
    cmd: Command,
}

/// Build a SwapMessenger for the selected transport, failing fast if --node-url is missing.
fn make_messenger(
    mode: &TransportMode,
    node_url: Option<&str>,
    store: Arc<Mutex<SwapStore>>,
) -> anyhow::Result<Box<dyn xmr_wow_client::swap_messenger::SwapMessenger + Send + Sync>> {
    match mode {
        TransportMode::OutOfBand => Ok(Box::new(xmr_wow_client::swap_messenger::OobMessenger)),
        TransportMode::Sharechain => {
            let url = node_url.ok_or_else(|| {
                anyhow::anyhow!(
                    "--node-url is required when --transport sharechain is selected"
                )
            })?;
            Ok(Box::new(xmr_wow_client::swap_messenger::SharechainMessenger {
                node_url: url.to_string(),
                store,
            }))
        }
    }
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
        /// XMR daemon URL for recording observed base height
        #[arg(long)]
        xmr_daemon: String,
        /// WOW daemon URL for recording observed base height
        #[arg(long)]
        wow_daemon: String,
        /// XMR lock period in blocks
        #[arg(long, default_value = "1000")]
        xmr_lock_blocks: u64,
        /// WOW lock period in blocks
        #[arg(long, default_value = "500")]
        wow_lock_blocks: u64,
        /// Alice refund destination for her XMR if the swap fails
        #[arg(long)]
        alice_refund_address: String,
    },
    /// Bob: respond to Alice's swap initiation
    InitBob {
        /// Counterparty's xmrwow1: initiation message (optional when --transport sharechain)
        #[arg(long)]
        message: Option<String>,
        /// Bob refund destination for his WOW if the swap fails
        #[arg(long)]
        bob_refund_address: String,
        /// Coordination channel ID from Alice (required when --transport sharechain without --message)
        #[arg(long)]
        swap_id: Option<String>,
    },
    /// Import counterparty's response message to advance swap state
    Import {
        /// Swap ID (hex) to import the response into
        #[arg(long)]
        swap_id: String,
        /// Counterparty's xmrwow1: response message (optional when --transport sharechain)
        #[arg(long)]
        message: Option<String>,
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
    /// Query swap state by replaying sharechain coordination messages
    Status {
        /// Swap ID (hex)
        #[arg(long)]
        swap_id: String,
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
        /// Counterparty's xmrwow1: adaptor pre-sig message (optional when --transport sharechain)
        #[arg(long)]
        message: Option<String>,
    },
    /// Alice: claim WOW using Bob's completed adaptor signature
    ClaimWow {
        #[arg(long)]
        swap_id: String,
        #[arg(long)]
        wow_daemon: String,
        /// Bob's claim proof (optional when --transport sharechain)
        #[arg(long)]
        message: Option<String>,
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
        /// Alice's claim proof (optional when --transport sharechain)
        #[arg(long)]
        message: Option<String>,
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
    /// Legacy refund command kept only for fail-closed compatibility.
    #[command(hide = true)]
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
    /// Legacy refund command kept only for fail-closed compatibility.
    #[command(hide = true)]
    GenerateRefundCooperate {
        /// Swap ID (hex)
        #[arg(long)]
        swap_id: String,
    },
    /// Legacy refund command kept only for fail-closed compatibility.
    #[command(hide = true)]
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
    /// Legacy refund command kept only for fail-closed compatibility.
    #[command(hide = true)]
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
        /// Print private key material (view private key) to stdout. Do not use on shared systems.
        #[arg(long)]
        verbose: bool,
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
        anyhow::bail!(
            "swap_id must be 64 hex chars (32 bytes), got {}",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a 64-char hex string into a Scalar, rejecting non-canonical inputs.
/// Uses `from_canonical_bytes`: not `from_bytes_mod_order`: to avoid silently reducing the key.
fn parse_scalar_hex(hex_str: &str) -> anyhow::Result<Scalar> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "key must be 64 hex chars (32 bytes), got {} chars",
            hex_str.len()
        );
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
            let spend = mnemonic_to_scalar(words, coin).map_err(|e| anyhow::anyhow!("{}", e))?;
            let view = derive_view_key(&spend);
            Ok((spend, view))
        }
        None => {
            let sk = spend_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("provide --mnemonic or --spend-key + --view-key"))?;
            let vk = view_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("provide --view-key with --spend-key"))?;
            Ok((parse_scalar_hex(sk)?, parse_scalar_hex(vk)?))
        }
    }
}

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

fn params_for_state(state: &SwapState) -> Option<&SwapParams> {
    match state {
        SwapState::KeyGeneration { params, .. }
        | SwapState::DleqExchange { params, .. }
        | SwapState::JointAddress { params, .. }
        | SwapState::XmrLocked { params, .. }
        | SwapState::WowLocked { params, .. } => Some(params),
        SwapState::Complete { .. } | SwapState::Refunded { .. } => None,
    }
}

fn validate_persisted_timing(state: &SwapState) -> anyhow::Result<()> {
    if let Some(params) = params_for_state(state) {
        params
            .validate_observed_refund_timing()
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    Ok(())
}

fn guarantee_failure(command: &str, decision: GuaranteeDecision) -> anyhow::Error {
    anyhow::anyhow!(
        "`{}` is {}. {}",
        command,
        decision.status.label(),
        decision.reason
    )
}

fn print_refund_timing(params: &SwapParams) {
    match &params.refund_timing {
        Some(refund_timing) => {
            println!("Refund timing basis: recorded");
            println!("XMR base height:     {}", refund_timing.xmr_base_height);
            println!("WOW base height:     {}", refund_timing.wow_base_height);
            println!("XMR lock blocks:     {}", refund_timing.xmr_lock_blocks);
            println!("WOW lock blocks:     {}", refund_timing.wow_lock_blocks);
            println!("XMR refund height:   {}", params.xmr_refund_height);
            println!("WOW refund height:   {}", params.wow_refund_height);
        }
        None => {
            println!("Refund timing basis: missing");
            println!("XMR refund height:   {}", params.xmr_refund_height);
            println!("WOW refund height:   {}", params.wow_refund_height);
        }
    }
}

fn require_checkpoint_ready(
    state: &SwapState,
    name: RefundCheckpointName,
    command: &str,
    proof_harness: bool,
) -> anyhow::Result<()> {
    match state.require_checkpoint_ready(name) {
        Ok(()) => Ok(()),
        Err(_err) if proof_harness && state.proof_harness_checkpoint_allowed(name) => {
            println!(
                "proof-harness override: proceeding with `{}` despite {} validation status.",
                command,
                name.display()
            );
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!("`{}` blocked. {}", command, err)),
    }
}

fn print_refund_checkpoints(state: &SwapState) {
    if let Some(checkpoint) = state.before_wow_lock_checkpoint() {
        println!("Checkpoint {}:", checkpoint.name.label());
        println!("  Status:             {}", checkpoint.status.label());
        println!("  Chain:              {:?}", checkpoint.chain);
        println!(
            "  Refund address:     {}",
            checkpoint.refund_address.as_deref().unwrap_or("<missing>")
        );
        println!("  Refund height:      {}", checkpoint.refund_height);
        println!("  Artifact present:   {}", checkpoint.artifact_present);
        println!("  Artifact validated: {}", checkpoint.artifact_validated);
        println!("  Reason:             {}", checkpoint.reason);
    }

    if let Some(checkpoint) = state.before_xmr_lock_checkpoint() {
        println!("Checkpoint {}:", checkpoint.name.label());
        println!("  Status:             {}", checkpoint.status.label());
        println!("  Chain:              {:?}", checkpoint.chain);
        println!(
            "  Refund address:     {}",
            checkpoint.refund_address.as_deref().unwrap_or("<missing>")
        );
        println!("  Refund height:      {}", checkpoint.refund_height);
        println!("  Artifact present:   {}", checkpoint.artifact_present);
        println!("  Artifact validated: {}", checkpoint.artifact_validated);
        println!("  Reason:             {}", checkpoint.reason);
    }
}

/// Poll for confirmation with exponential backoff, doubling the interval each attempt up to 120 s.
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
                println!(
                    "Waiting... {} of {} confirmations (attempt {}/{})",
                    status.confirmations,
                    required,
                    attempts + 1,
                    max_retries
                );
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
                        max_retries,
                        e
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
                interval_secs = (interval_secs * 2).min(max_interval_secs);
            }
        }
    }
}

/// Infer swap state from sharechain coord messages; returns (count, last_type, label).
fn derive_swap_state(raw_messages: &[Vec<u8>]) -> (usize, String, String) {
    let count = raw_messages.len();
    if count == 0 {
        return (0, "unknown".to_string(), "No messages".to_string());
    }

    let mut last_type = "unknown".to_string();
    for raw in raw_messages {
        match serde_json::from_slice::<xmr_wow_client::CoordMessage>(raw) {
            Ok(coord) => match xmr_wow_client::unwrap_protocol_message(&coord) {
                Ok(xmr_wow_client::ProtocolMessage::Init { .. }) => {
                    last_type = "Init".to_string();
                }
                Ok(xmr_wow_client::ProtocolMessage::Response { .. }) => {
                    last_type = "Response".to_string();
                }
                Ok(xmr_wow_client::ProtocolMessage::AdaptorPreSig { .. }) => {
                    last_type = "AdaptorPreSig".to_string();
                }
                Ok(xmr_wow_client::ProtocolMessage::ClaimProof { .. }) => {
                    last_type = "ClaimProof".to_string();
                }
                Ok(xmr_wow_client::ProtocolMessage::RefundCooperate { .. }) => {
                    last_type = "RefundCooperate".to_string();
                }
                Err(_) => {
                    last_type = "unreadable".to_string();
                }
            },
            Err(_) => {
                last_type = "unreadable".to_string();
            }
        }
    }

    let inferred = match last_type.as_str() {
        "Init" => "Awaiting Bob response",
        "Response" => "Awaiting lock transactions",
        "AdaptorPreSig" => "Awaiting claim proof",
        "ClaimProof" => "Complete (claim seen)",
        "RefundCooperate" => "Refund cooperation in progress",
        _ => "Unknown",
    };

    (count, last_type, inferred.to_string())
}

/// Load, decrypt, and restore swap state from the store.
fn load_and_decrypt_state(
    store: &SwapStore,
    swap_id: &[u8; 32],
    enc_key: &[u8; 32],
) -> anyhow::Result<(SwapState, Zeroizing<[u8; 32]>, Vec<u8>)> {
    let (state_json, encrypted_secret) = store
        .load_with_secret(swap_id)?
        .ok_or_else(|| anyhow::anyhow!("swap {} not found", hex::encode(swap_id)))?;

    let encrypted_blob = encrypted_secret.ok_or_else(|| {
        anyhow::anyhow!(
            "no encrypted secret found for swap {}",
            hex::encode(swap_id)
        )
    })?;

    let secret_bytes = decrypt_secret(enc_key, &encrypted_blob)
        .map_err(|e| anyhow::anyhow!("failed to decrypt secret: {}", e))?;

    let state: SwapState = serde_json::from_str(&state_json)?;
    let state = restore_secret_into_state(state, *secret_bytes)?;

    Ok((state, secret_bytes, encrypted_blob))
}

/// Resolves an incoming protocol message from `--message` or sharechain auto-poll.
/// Explicit `--message` wins. With sharechain transport and no `--message`, poll
/// the coord channel; with out-of-band and no `--message`, error.
async fn resolve_incoming_message(
    message: Option<String>,
    transport: &TransportMode,
    messenger: &(dyn xmr_wow_client::swap_messenger::SwapMessenger + Send + Sync),
    coord_id: &[u8; 32],
) -> anyhow::Result<ProtocolMessage> {
    match (message, transport) {
        (Some(s), _) => {
            // Explicit --message wins regardless of transport
            Ok(decode_message(&s)?)
        }
        (None, TransportMode::Sharechain) => {
            let coord = messenger
                .receive(coord_id)
                .await
                .map_err(|e| anyhow::anyhow!("sharechain receive failed: {}", e))?
                .ok_or_else(|| anyhow::anyhow!(
                    "No message from counterparty yet under coord ID {}. \
                     Re-run when counterparty has published.",
                    hex::encode(coord_id)
                ))?;
            let proto = unwrap_protocol_message(&coord)
                .map_err(|e| anyhow::anyhow!("unwrap failed: {}", e))?;
            Ok(proto)
        }
        (None, TransportMode::OutOfBand) => {
            anyhow::bail!("Provide --message when using out-of-band transport");
        }
    }
}

/// Sends `msg` over sharechain or prints it as an `xmrwow1:` string for OOB.
async fn dispatch_outgoing_message(
    transport: &TransportMode,
    messenger: &(dyn xmr_wow_client::swap_messenger::SwapMessenger + Send + Sync),
    coord_id: &[u8; 32],
    msg: &ProtocolMessage,
    label: &str,
) -> anyhow::Result<()> {
    match transport {
        TransportMode::Sharechain => {
            let coord = wrap_protocol_message(*coord_id, msg)
                .map_err(|e| anyhow::anyhow!("wrap failed: {}", e))?;
            messenger.send(coord).await
                .map_err(|e| anyhow::anyhow!("sharechain send failed: {}", e))?;
            println!("Published {} to sharechain.", label);
        }
        TransportMode::OutOfBand => {
            println!("Send this {} to counterparty:", label);
            println!("{}", encode_message(msg));
        }
    }
    Ok(())
}

/// Coord channel ID is always `keccak256(alice_pubkey)`, regardless of role.
fn derive_coord_id(role: SwapRole, my_pubkey: &[u8; 32], counterparty_pubkey: &[u8; 32]) -> [u8; 32] {
    match role {
        SwapRole::Alice => keccak256(my_pubkey),
        SwapRole::Bob => keccak256(counterparty_pubkey),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let store = SwapStore::open(&cli.db)?;
    let store_shared = Arc::new(Mutex::new(store));
    // Fail fast on bad transport config before entering command handlers.
    let messenger = make_messenger(&cli.transport, cli.node_url.as_deref(), store_shared.clone())?;

    match cli.cmd {
        Command::InitAlice {
            amount_xmr,
            amount_wow,
            xmr_daemon,
            wow_daemon,
            xmr_lock_blocks,
            wow_lock_blocks,
            alice_refund_address,
        } => {
            if amount_xmr == 0 {
                anyhow::bail!("--amount-xmr must be greater than 0");
            }
            if amount_wow == 0 {
                anyhow::bail!("--amount-wow must be greater than 0");
            }

            if xmr_lock_blocks > 10000 {
                anyhow::bail!(
                    "--xmr-lock-blocks {} exceeds maximum 10000 (would lock funds for months)",
                    xmr_lock_blocks
                );
            }
            if wow_lock_blocks > 10000 {
                anyhow::bail!(
                    "--wow-lock-blocks {} exceeds maximum 10000 (would lock funds for months)",
                    wow_lock_blocks
                );
            }

            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let xmr_height = XmrWallet::new(&xmr_daemon).get_current_height().await?;
            let wow_height = WowWallet::new(&wow_daemon).get_current_height().await?;
            let (refund_timing, xmr_refund_height, wow_refund_height) =
                build_observed_refund_timing(
                    xmr_height,
                    wow_height,
                    xmr_lock_blocks,
                    wow_lock_blocks,
                )?;

            let params = SwapParams {
                amount_xmr,
                amount_wow,
                xmr_refund_height,
                wow_refund_height,
                refund_timing: Some(refund_timing.clone()),
                alice_refund_address: Some(alice_refund_address.clone()),
                bob_refund_address: None,
            };

            let (state, secret_bytes) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

            // Encrypt before any output so the secret is safe even if printing panics.
            let encrypted = encrypt_secret(&enc_key, &secret_bytes);

            let (my_pubkey, my_proof) = match &state {
                SwapState::KeyGeneration {
                    my_pubkey,
                    my_proof,
                    ..
                } => (*my_pubkey, my_proof.clone()),
                _ => unreachable!(),
            };

            // Temp ID is Keccak256(alice_pubkey); replaced with the real swap_id after Import.
            let temp_id = keccak256(&my_pubkey);

            let state_json = serde_json::to_string(&state)?;
            store_shared.lock().unwrap().save_with_secret(&temp_id, &state_json, Some(&encrypted))?;

            let msg = ProtocolMessage::Init {
                pubkey: my_pubkey,
                proof: my_proof,
                amount_xmr,
                amount_wow,
                xmr_refund_height,
                wow_refund_height,
                refund_timing: Some(refund_timing.clone()),
                alice_refund_address: Some(alice_refund_address.clone()),
            };

            match &cli.transport {
                TransportMode::Sharechain => {
                    let coord = wrap_protocol_message(temp_id, &msg)
                        .map_err(|e| anyhow::anyhow!("wrap failed: {}", e))?;
                    messenger.send(coord).await
                        .map_err(|e| anyhow::anyhow!("sharechain send failed: {}", e))?;
                    // Advance past Alice's own Init so subsequent receives return Bob's Response.
                    {
                        let store = store_shared.lock().unwrap();
                        store.set_cursor(&temp_id, 1)?;
                    }
                    println!("Swap initialized as Alice.");
                    println!("Swap coord ID: {}", hex::encode(temp_id));
                    println!("Published Init to sharechain.");
                    println!("Give the coord ID to Bob so he can run init-bob --swap-id {}.", hex::encode(temp_id));
                }
                TransportMode::OutOfBand => {
                    println!("Swap initialized as Alice.");
                    println!("Temp swap ID: {}", hex::encode(temp_id));
                    println!(
                        "Recorded XMR base height: {}",
                        refund_timing.xmr_base_height
                    );
                    println!(
                        "Recorded WOW base height: {}",
                        refund_timing.wow_base_height
                    );
                    println!();
                    println!("Send this message to Bob:");
                    println!("{}", encode_message(&msg));
                }
            }
        }

        Command::InitBob {
            message,
            bob_refund_address,
            swap_id: swap_id_arg,
        } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            // Determine coord_id for sharechain polling
            let coord_id: Option<[u8; 32]> = match (&message, &cli.transport) {
                (None, TransportMode::Sharechain) => {
                    let hex_str = swap_id_arg.as_ref().ok_or_else(|| anyhow::anyhow!(
                        "--swap-id <hex> is required when using --transport sharechain without --message. \
                         Alice prints her coord ID during init-alice."
                    ))?;
                    Some(parse_swap_id(hex_str)?)
                }
                _ => None,
            };

            let init_msg: ProtocolMessage = match (message, &cli.transport) {
                (Some(s), _) => decode_message(&s)?,
                (None, TransportMode::Sharechain) => {
                    let cid = coord_id.unwrap(); // safe: set above
                    let coord = messenger
                        .receive(&cid)
                        .await
                        .map_err(|e| anyhow::anyhow!("sharechain receive failed: {}", e))?
                        .ok_or_else(|| anyhow::anyhow!(
                            "No message from counterparty yet under coord ID {}. \
                             Re-run when counterparty has published.",
                            hex::encode(cid)
                        ))?;
                    unwrap_protocol_message(&coord)
                        .map_err(|e| anyhow::anyhow!("unwrap failed: {}", e))?
                }
                (None, TransportMode::OutOfBand) => {
                    anyhow::bail!("Provide --message when using out-of-band transport");
                }
            };
            let (
                alice_pubkey,
                alice_proof,
                amount_xmr,
                amount_wow,
                xmr_refund_height,
                wow_refund_height,
                refund_timing,
                alice_refund_address,
            ) = match init_msg {
                ProtocolMessage::Init {
                    pubkey,
                    proof,
                    amount_xmr,
                    amount_wow,
                    xmr_refund_height,
                    wow_refund_height,
                    refund_timing,
                    alice_refund_address,
                } => (
                    pubkey,
                    proof,
                    amount_xmr,
                    amount_wow,
                    xmr_refund_height,
                    wow_refund_height,
                    refund_timing,
                    alice_refund_address,
                ),
                _ => anyhow::bail!("Expected Init message from Alice"),
            };

            let refund_timing = refund_timing.ok_or_else(|| {
                anyhow::anyhow!(
                    "legacy init transcripts without refund_timing are unsupported"
                )
            })?;
            let alice_refund_address = alice_refund_address.ok_or_else(|| {
                anyhow::anyhow!(
                    "legacy init transcripts without alice_refund_address are unsupported"
                )
            })?;

            let params = SwapParams {
                amount_xmr,
                amount_wow,
                xmr_refund_height,
                wow_refund_height,
                refund_timing: Some(refund_timing.clone()),
                alice_refund_address: Some(alice_refund_address.clone()),
                bob_refund_address: Some(bob_refund_address.clone()),
            };
            params
                .validate_observed_refund_timing()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let (state, secret_bytes) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);

            // Encrypt before any output so the secret is safe even if printing panics.
            let encrypted = encrypt_secret(&enc_key, &secret_bytes);

            let (my_pubkey, my_proof) = match &state {
                SwapState::KeyGeneration {
                    my_pubkey,
                    my_proof,
                    ..
                } => (*my_pubkey, my_proof.clone()),
                _ => unreachable!(),
            };

            let state = state.receive_counterparty_key(alice_pubkey, &alice_proof)?;
            let state = state.derive_joint_addresses()?;

            let (swap_id, xmr_address, wow_address) = match &state {
                SwapState::JointAddress { addresses, .. } => (
                    addresses.swap_id,
                    addresses.xmr_address.clone(),
                    addresses.wow_address.clone(),
                ),
                _ => unreachable!(),
            };

            let state_json = serde_json::to_string(&state)?;
            store_shared.lock().unwrap().save_with_secret(&swap_id, &state_json, Some(&encrypted))?;

            let response = ProtocolMessage::Response {
                pubkey: my_pubkey,
                proof: my_proof,
                bob_refund_address: Some(bob_refund_address.clone()),
            };

            println!("Swap initialized as Bob.");
            println!("Swap ID: {}", hex::encode(swap_id));
            println!("XMR joint address: {}", xmr_address);
            println!("WOW joint address: {}", wow_address);
            println!(
                "Recorded XMR base height: {}",
                refund_timing.xmr_base_height
            );
            println!(
                "Recorded WOW base height: {}",
                refund_timing.wow_base_height
            );
            println!();

            match &cli.transport {
                TransportMode::Sharechain => {
                    // Prefer explicit --swap-id; otherwise derive coord_id from alice_pubkey
                    // (covers the mixed case: --message with --transport sharechain).
                    let cid = coord_id.unwrap_or_else(|| keccak256(&alice_pubkey));
                    let coord = wrap_protocol_message(cid, &response)
                        .map_err(|e| anyhow::anyhow!("wrap failed: {}", e))?;
                    messenger.send(coord).await
                        .map_err(|e| anyhow::anyhow!("sharechain send failed: {}", e))?;
                    // Bob's Response sits at index 1 (Alice's Init at 0); advance past it.
                    {
                        let store = store_shared.lock().unwrap();
                        store.set_cursor(&cid, 2)?;
                    }
                    println!("Published Response to sharechain.");
                }
                TransportMode::OutOfBand => {
                    println!("Send this response to Alice:");
                    println!("{}", encode_message(&response));
                }
            }
        }

        Command::Import { swap_id, message } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let temp_id = parse_swap_id(&swap_id)?;

            let (state_json, encrypted_secret) = store_shared.lock().unwrap()
                .load_with_secret(&temp_id)?
                .ok_or_else(|| anyhow::anyhow!("swap {} not found", swap_id))?;

            let encrypted_blob = encrypted_secret
                .ok_or_else(|| anyhow::anyhow!("no encrypted secret found for swap {}", swap_id))?;

            let secret_bytes = decrypt_secret(&enc_key, &encrypted_blob)
                .map_err(|e| anyhow::anyhow!("failed to decrypt secret: {}", e))?;

            let state: SwapState = serde_json::from_str(&state_json)?;
            let state = restore_secret_into_state(state, *secret_bytes)?;

            let response_msg = resolve_incoming_message(
                message,
                &cli.transport,
                &*messenger,
                &temp_id,
            ).await?;
            let (bob_pubkey, bob_proof, bob_refund_address) = match response_msg {
                ProtocolMessage::Response {
                    pubkey,
                    proof,
                    bob_refund_address,
                } => (pubkey, proof, bob_refund_address),
                _ => anyhow::bail!("Expected Response message from Bob"),
            };
            let bob_refund_address = bob_refund_address.ok_or_else(|| {
                anyhow::anyhow!(
                    "legacy response messages without bob_refund_address are unsupported"
                )
            })?;

            let state = state.receive_counterparty_key(bob_pubkey, &bob_proof)?;
            let state = state.derive_joint_addresses()?;
            let state = match state {
                SwapState::JointAddress {
                    role,
                    mut params,
                    addresses,
                    my_pubkey,
                    counterparty_pubkey,
                    before_wow_lock_checkpoint,
                    secret_bytes,
                } => {
                    params.bob_refund_address = Some(bob_refund_address.clone());
                    SwapState::JointAddress {
                        role,
                        params,
                        addresses,
                        my_pubkey,
                        counterparty_pubkey,
                        before_wow_lock_checkpoint,
                        secret_bytes,
                    }
                    .refresh_refund_readiness()?
                }
                other => other,
            };

            let (real_swap_id, xmr_address, wow_address) = match &state {
                SwapState::JointAddress { addresses, .. } => (
                    addresses.swap_id,
                    addresses.xmr_address.clone(),
                    addresses.wow_address.clone(),
                ),
                _ => unreachable!(),
            };

            let encrypted = encrypt_secret(&enc_key, &*secret_bytes);
            let state_json = serde_json::to_string(&state)?;
            {
                let store = store_shared.lock().unwrap();
                store.save_with_secret(&real_swap_id, &state_json, Some(&encrypted))?;
                if temp_id != real_swap_id {
                    store.delete(&temp_id)?;
                }
            }

            println!("Imported Bob's response successfully.");
            println!("Swap ID: {}", hex::encode(real_swap_id));
            println!("XMR joint address: {}", xmr_address);
            println!("WOW joint address: {}", wow_address);
        }

        Command::Show { swap_id } => {
            let id = parse_swap_id(&swap_id)?;
            match store_shared.lock().unwrap().load(&id)? {
                Some(state_json) => {
                    let state: SwapState = serde_json::from_str(&state_json)?;
                    let state = state.refresh_refund_readiness()?;
                    validate_persisted_timing(&state)?;
                    println!("Swap ID: {}", swap_id);
                    println!("Phase:   {}", phase_name(&state));
                    println!("Role:    {}", role_name(&state));

                    match &state {
                        SwapState::JointAddress {
                            addresses, params, ..
                        }
                        | SwapState::XmrLocked {
                            addresses, params, ..
                        }
                        | SwapState::WowLocked {
                            addresses, params, ..
                        } => {
                            println!("XMR address: {}", addresses.xmr_address);
                            println!("WOW address: {}", addresses.wow_address);
                            println!("Amount XMR:  {}", params.amount_xmr);
                            println!("Amount WOW:  {}", params.amount_wow);
                            print_refund_timing(params);
                        }
                        SwapState::KeyGeneration { params, .. }
                        | SwapState::DleqExchange { params, .. } => {
                            println!("Amount XMR:  {}", params.amount_xmr);
                            println!("Amount WOW:  {}", params.amount_wow);
                            print_refund_timing(params);
                        }
                        SwapState::Complete { addresses, .. }
                        | SwapState::Refunded { addresses, .. } => {
                            println!("XMR address: {}", addresses.xmr_address);
                            println!("WOW address: {}", addresses.wow_address);
                        }
                    }

                    print_refund_checkpoints(&state);
                    println!();
                    println!("--- Next Safe Action ---");
                    println!("{}", state.next_safe_action());
                }
                None => {
                    println!("Swap {} not found.", swap_id);
                }
            }
        }

        Command::List { all } => {
            let swaps = store_shared.lock().unwrap().list_all()?;
            if swaps.is_empty() {
                println!("No swaps found.");
            } else {
                println!("{:<66}  {:<15}  ROLE", "SWAP ID", "PHASE");
                println!("{}", "-".repeat(90));
                for (id, state_json) in swaps {
                    let id_hex = hex::encode(id);
                    match serde_json::from_str::<SwapState>(&state_json) {
                        Ok(SwapState::KeyGeneration { .. }) if !all => continue,
                        Ok(state) => {
                            println!(
                                "{:<66}  {:<15}  {}",
                                id_hex,
                                phase_name(&state),
                                role_name(&state)
                            );
                        }
                        Err(_) if !all => continue,
                        Err(_) => {
                            println!("{:<66}  {:<15}  ???", id_hex, "???");
                        }
                    }
                }
            }
        }

        Command::Status { swap_id } => {
            let id_bytes = hex::decode(&swap_id)
                .map_err(|e| anyhow::anyhow!("invalid swap_id hex: {}", e))?;
            let id: [u8; 32] = id_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("swap_id must be exactly 64 hex characters (32 bytes)"))?;

            let url = cli.node_url.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "--node-url is required for `status` (uses sharechain replay). For local state, use `show`."
                )
            })?;

            let client = xmr_wow_client::node_client::NodeClient::new(url);
            let raw_messages = client.replay_coord_messages(&id).await?;

            let (count, last_type, inferred) = derive_swap_state(&raw_messages);

            if count == 0 {
                println!("No coordination messages found for swap {}.", swap_id);
            } else {
                println!("Swap ID:        {}", swap_id);
                println!("Messages seen:  {}", count);
                println!("Last message:   {}", last_type);
                println!("Inferred state: {}", inferred);
            }
        }

        Command::LockXmr {
            swap_id,
            xmr_daemon,
            wow_daemon,
            spend_key,
            view_key,
            mnemonic,
            scan_from,
        } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;
            let state = state.refresh_refund_readiness()?;
            validate_persisted_timing(&state)?;

            let (role, params, my_pubkey, counterparty_pubkey) = match &state {
                SwapState::WowLocked {
                    role,
                    params,
                    my_pubkey,
                    counterparty_pubkey,
                    ..
                } => (*role, params.clone(), *my_pubkey, *counterparty_pubkey),
                SwapState::JointAddress {
                    role,
                    params,
                    my_pubkey,
                    counterparty_pubkey,
                    ..
                } => (*role, params.clone(), *my_pubkey, *counterparty_pubkey),
                other => anyhow::bail!(
                    "expected WowLocked or JointAddress state, got {}",
                    phase_name(other)
                ),
            };
            if role != SwapRole::Alice {
                anyhow::bail!("lock-xmr is for Alice only (you are Bob)");
            }
            require_checkpoint_ready(
                &state,
                RefundCheckpointName::BeforeXmrLock,
                "lock-xmr",
                cli.proof_harness,
            )?;

            let (joint_spend, view_scalar) =
                SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            let wow_wallet_verify = WowWallet::new(&wow_daemon);
            let wow_height: u64 =
                {
                    let resp: serde_json::Value = reqwest::Client::new()
                    .post(format!("{}/json_rpc", wow_daemon))
                    .json(&serde_json::json!({"jsonrpc":"2.0","id":"0","method":"get_block_count"}))
                    .send().await?.json().await?;
                    resp["result"]["count"].as_u64().unwrap_or(0)
                };
            let verify_from = wow_height.saturating_sub(500);
            println!(
                "Verifying Bob's WOW lock (scanning {} blocks from {})...",
                wow_height - verify_from,
                verify_from
            );
            let scan_result = xmr_wow_wallet::verify_lock(
                &wow_wallet_verify,
                &joint_spend,
                &view_scalar,
                params.amount_wow,
                verify_from,
            )
            .await?;
            println!(
                "Verified: Bob locked {} WOW at height {}",
                scan_result.amount, scan_result.block_height
            );

            let (sender_spend, sender_view) =
                resolve_sender_keys(&mnemonic, &spend_key, &view_key, SeedCoin::Monero)?;
            let xmr_wallet = XmrWallet::with_sender_keys(&xmr_daemon, sender_spend, sender_view)
                .with_scan_from(scan_from);
            println!(
                "Locking {} XMR atomic units to joint address...",
                params.amount_xmr
            );
            let tx_hash = xmr_wallet
                .lock(&joint_spend, &view_scalar, params.amount_xmr)
                .await?;
            println!("XMR lock tx: {}", hex::encode(tx_hash));

            println!("Waiting for confirmation...");
            wait_for_confirmation(&xmr_wallet, &tx_hash, 1, 10).await?;

            let state = state.record_xmr_lock(tx_hash)?;

            let my_adaptor_pre_sig = match &state {
                SwapState::XmrLocked {
                    my_adaptor_pre_sig, ..
                } => my_adaptor_pre_sig.clone(),
                _ => unreachable!(),
            };

            let coord_id = derive_coord_id(role, &my_pubkey, &counterparty_pubkey);
            let pre_sig_msg = ProtocolMessage::AdaptorPreSig {
                pre_sig: my_adaptor_pre_sig,
            };
            println!("XMR locked successfully.");
            dispatch_outgoing_message(
                &cli.transport, &*messenger, &coord_id, &pre_sig_msg, "adaptor pre-signature"
            ).await?;

            let swap_id_bytes = state.swap_id().ok_or_else(|| {
                anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)")
            })?;
            let encrypted = encrypt_secret(&enc_key, &*secret_bytes);
            let state_json = serde_json::to_string(&state)?;
            store_shared.lock().unwrap().save_with_secret(&swap_id_bytes, &state_json, Some(&encrypted))?;
        }

        Command::LockWow {
            swap_id,
            wow_daemon,
            spend_key,
            view_key,
            mnemonic,
            scan_from,
        } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;
            validate_persisted_timing(&state)?;

            let (role, params, my_pubkey, counterparty_pubkey) = match &state {
                SwapState::JointAddress {
                    role,
                    params,
                    my_pubkey,
                    counterparty_pubkey,
                    ..
                } => (*role, params.clone(), *my_pubkey, *counterparty_pubkey),
                other => anyhow::bail!("expected JointAddress state, got {}", phase_name(other)),
            };
            if role != SwapRole::Bob {
                anyhow::bail!("lock-wow is for Bob only (you are Alice)");
            }
            require_checkpoint_ready(
                &state,
                RefundCheckpointName::BeforeWowLock,
                "lock-wow",
                cli.proof_harness,
            )?;

            let (joint_spend, view_scalar) =
                SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            let (sender_spend, sender_view) =
                resolve_sender_keys(&mnemonic, &spend_key, &view_key, SeedCoin::Wownero)?;
            let wow_wallet = WowWallet::with_sender_keys(&wow_daemon, sender_spend, sender_view)
                .with_scan_from(scan_from);
            println!(
                "Locking {} WOW atomic units to joint address...",
                params.amount_wow
            );
            let wow_tx_hash = wow_wallet
                .lock(&joint_spend, &view_scalar, params.amount_wow)
                .await?;
            println!("WOW lock tx: {}", hex::encode(wow_tx_hash));

            println!("Waiting for WOW confirmation...");
            wait_for_confirmation(&wow_wallet, &wow_tx_hash, 1, 10).await?;

            let state = state.record_wow_lock(wow_tx_hash)?;

            let my_adaptor_pre_sig = match &state {
                SwapState::WowLocked {
                    my_adaptor_pre_sig, ..
                } => my_adaptor_pre_sig.clone(),
                _ => unreachable!(),
            };

            let coord_id = derive_coord_id(role, &my_pubkey, &counterparty_pubkey);
            let pre_sig_msg = ProtocolMessage::AdaptorPreSig {
                pre_sig: my_adaptor_pre_sig,
            };
            println!("WOW locked successfully.");
            dispatch_outgoing_message(
                &cli.transport, &*messenger, &coord_id, &pre_sig_msg, "adaptor pre-signature"
            ).await?;

            let swap_id_bytes = state.swap_id().ok_or_else(|| {
                anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)")
            })?;
            let encrypted = encrypt_secret(&enc_key, &*secret_bytes);
            let state_json = serde_json::to_string(&state)?;
            store_shared.lock().unwrap().save_with_secret(&swap_id_bytes, &state_json, Some(&encrypted))?;
        }

        Command::ExchangePreSig { swap_id, message } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;

            let (role, my_pubkey, counterparty_pubkey) = match &state {
                SwapState::XmrLocked { role, my_pubkey, counterparty_pubkey, .. } |
                SwapState::WowLocked { role, my_pubkey, counterparty_pubkey, .. } => {
                    (*role, *my_pubkey, *counterparty_pubkey)
                }
                other => anyhow::bail!("expected XmrLocked or WowLocked state for exchange-pre-sig, got {}", phase_name(other)),
            };
            let coord_id = derive_coord_id(role, &my_pubkey, &counterparty_pubkey);

            let msg = resolve_incoming_message(
                message,
                &cli.transport,
                &*messenger,
                &coord_id,
            ).await?;
            let pre_sig = match msg {
                ProtocolMessage::AdaptorPreSig { pre_sig } => pre_sig,
                _ => anyhow::bail!("Expected AdaptorPreSig message"),
            };

            let state = state.receive_counterparty_pre_sig(pre_sig)?;

            let swap_id_bytes = state.swap_id().ok_or_else(|| {
                anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)")
            })?;
            let encrypted = encrypt_secret(&enc_key, &*secret_bytes);
            let state_json = serde_json::to_string(&state)?;
            store_shared.lock().unwrap().save_with_secret(&swap_id_bytes, &state_json, Some(&encrypted))?;

            println!("Counterparty pre-signature verified and stored.");
        }

        Command::ClaimWow {
            swap_id,
            wow_daemon,
            message,
            destination,
            scan_from,
        } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;

            let (role, my_pubkey, counterparty_pubkey, my_adaptor_pre_sig) = match &state {
                SwapState::WowLocked {
                    role,
                    my_pubkey,
                    counterparty_pubkey,
                    my_adaptor_pre_sig,
                    counterparty_pre_sig,
                    ..
                }
                | SwapState::XmrLocked {
                    role,
                    my_pubkey,
                    counterparty_pubkey,
                    my_adaptor_pre_sig,
                    counterparty_pre_sig,
                    ..
                } => {
                    if *role != SwapRole::Alice {
                        anyhow::bail!("claim-wow is for Alice only (you are Bob)");
                    }
                    if counterparty_pre_sig.is_none() {
                        anyhow::bail!(
                            "counterparty pre-sig not stored yet (run exchange-pre-sig first)"
                        );
                    }
                    (
                        *role,
                        *my_pubkey,
                        *counterparty_pubkey,
                        my_adaptor_pre_sig.clone(),
                    )
                }
                other => anyhow::bail!(
                    "expected WowLocked or XmrLocked state, got {}",
                    phase_name(other)
                ),
            };

            let coord_id = derive_coord_id(role, &my_pubkey, &counterparty_pubkey);

            let claim_msg = resolve_incoming_message(
                message, &cli.transport, &*messenger, &coord_id,
            ).await?;
            let bob_completed_sig = match claim_msg {
                ProtocolMessage::ClaimProof { completed_sig } => completed_sig,
                _ => anyhow::bail!("Expected ClaimProof message from Bob"),
            };

            let (complete_state, bob_secret) =
                state.complete_with_adaptor_claim(&bob_completed_sig)?;
            println!("Extracted Bob's secret from his completed adaptor signature.");

            let my_scalar = Scalar::from_canonical_bytes(*secret_bytes)
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("invalid secret scalar"))?;
            let combined = my_scalar + bob_secret;

            let (_, view_scalar) =
                SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            let wow_wallet = WowWallet::new(&wow_daemon).with_scan_from(scan_from);
            println!("Sweeping WOW from joint address to {}...", destination);
            let sweep_tx = wow_wallet
                .sweep(&combined, &view_scalar, &destination)
                .await?;
            println!("WOW sweep tx: {}", hex::encode(sweep_tx));

            println!("Waiting for WOW sweep confirmation...");
            wait_for_confirmation(&wow_wallet, &sweep_tx, 1, 10).await?;

            // Alice reveals her secret by completing her own pre-sig, enabling Bob to claim XMR.
            let alice_completed = my_adaptor_pre_sig
                .complete(&my_scalar)
                .map_err(|e| anyhow::anyhow!("failed to complete own pre-sig: {}", e))?;
            let claim_proof = ProtocolMessage::ClaimProof {
                completed_sig: alice_completed,
            };

            println!("WOW claimed successfully.");
            dispatch_outgoing_message(
                &cli.transport, &*messenger, &coord_id, &claim_proof, "claim proof"
            ).await?;

            let swap_id_bytes = complete_state.swap_id().ok_or_else(|| {
                anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)")
            })?;
            let state_json = serde_json::to_string(&complete_state)?;
            store_shared.lock().unwrap().save_with_secret(&swap_id_bytes, &state_json, None)?;
        }

        Command::ClaimXmr {
            swap_id,
            xmr_daemon,
            message,
            destination,
            scan_from,
        } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;

            let (role, my_pubkey, counterparty_pubkey, my_adaptor_pre_sig, counterparty_pre_sig) =
                match &state {
                    SwapState::WowLocked {
                        role,
                        my_pubkey,
                        counterparty_pubkey,
                        my_adaptor_pre_sig,
                        counterparty_pre_sig,
                        ..
                    } => {
                        if *role != SwapRole::Bob {
                            anyhow::bail!("claim-xmr is for Bob only (you are Alice)");
                        }
                        if counterparty_pre_sig.is_none() {
                            anyhow::bail!(
                                "counterparty pre-sig not stored yet (run exchange-pre-sig first)"
                            );
                        }
                        (*role, *my_pubkey, *counterparty_pubkey, my_adaptor_pre_sig.clone(),
                     counterparty_pre_sig.clone()
                         .ok_or_else(|| anyhow::anyhow!("counterparty pre-sig not yet received (run exchange-pre-sig first)"))?)
                    }
                    other => anyhow::bail!("expected WowLocked state, got {}", phase_name(other)),
                };

            let coord_id = derive_coord_id(role, &my_pubkey, &counterparty_pubkey);

            let my_scalar = Scalar::from_canonical_bytes(*secret_bytes)
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("invalid secret scalar"))?;

            // Bob reveals his secret first, enabling Alice to sweep WOW.
            let bob_completed = my_adaptor_pre_sig
                .complete(&my_scalar)
                .map_err(|e| anyhow::anyhow!("failed to complete own pre-sig: {}", e))?;
            let bob_claim_proof = ProtocolMessage::ClaimProof {
                completed_sig: bob_completed,
            };

            dispatch_outgoing_message(
                &cli.transport, &*messenger, &coord_id, &bob_claim_proof, "claim proof"
            ).await?;
            println!();

            let claim_msg = resolve_incoming_message(
                message, &cli.transport, &*messenger, &coord_id,
            ).await?;
            let alice_completed_sig = match claim_msg {
                ProtocolMessage::ClaimProof { completed_sig } => completed_sig,
                _ => anyhow::bail!("Expected ClaimProof message from Alice"),
            };

            let alice_secret = counterparty_pre_sig
                .extract_secret(&alice_completed_sig)
                .map_err(|e| anyhow::anyhow!("secret extraction failed: {}", e))?;

            // Verify: alice_secret * G == counterparty_pubkey (Alice's pubkey)
            let alice_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                .map_err(|e| anyhow::anyhow!("invalid counterparty pubkey: {}", e))?;
            if (alice_secret * G).compress() != alice_point.compress() {
                anyhow::bail!("extracted secret does not match Alice's pubkey");
            }
            println!("Extracted Alice's secret from her completed adaptor signature.");

            let combined = alice_secret + my_scalar;

            let (_, view_scalar) =
                SwapState::compute_joint_keys(&my_pubkey, &counterparty_pubkey, role)?;

            let xmr_wallet = XmrWallet::new(&xmr_daemon).with_scan_from(scan_from);
            println!("Sweeping XMR from joint address to {}...", destination);
            let sweep_tx = xmr_wallet
                .sweep(&combined, &view_scalar, &destination)
                .await?;
            println!("XMR sweep tx: {}", hex::encode(sweep_tx));

            println!("Waiting for XMR sweep confirmation...");
            wait_for_confirmation(&xmr_wallet, &sweep_tx, 1, 10).await?;

            let k_b_revealed = alice_secret.to_bytes();
            let complete_state = SwapState::Complete {
                role,
                addresses: match &state {
                    SwapState::WowLocked { addresses, .. } => addresses.clone(),
                    _ => unreachable!(),
                },
                k_b_revealed,
            };

            let swap_id_bytes = complete_state.swap_id().ok_or_else(|| {
                anyhow::anyhow!("swap state has no swap_id (still in KeyGeneration phase?)")
            })?;
            let state_json = serde_json::to_string(&complete_state)?;
            store_shared.lock().unwrap().save_with_secret(&swap_id_bytes, &state_json, None)?;

            println!("XMR claimed. Swap complete.");
        }

        Command::GenerateClaimProof { presig, spend_key } => {
            let presig_msg: ProtocolMessage = decode_message(&presig)?;
            let pre_sig = match presig_msg {
                ProtocolMessage::AdaptorPreSig { pre_sig } => pre_sig,
                _ => anyhow::bail!("Expected AdaptorPreSig message"),
            };
            let key_bytes = hex::decode(&spend_key)?;
            let key_arr: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("spend key must be 32 bytes"))?;
            let scalar = Scalar::from_canonical_bytes(key_arr)
                .into_option()
                .ok_or_else(|| anyhow::anyhow!("invalid scalar"))?;

            let completed = pre_sig
                .complete(&scalar)
                .map_err(|e| anyhow::anyhow!("failed to complete pre-sig: {}", e))?;
            let claim_proof = ProtocolMessage::ClaimProof {
                completed_sig: completed,
            };
            println!("{}", encode_message(&claim_proof));
        }

        Command::Refund {
            swap_id,
            xmr_daemon,
            wow_daemon,
        } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, _secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;
            let _ = (xmr_daemon, wow_daemon);
            validate_persisted_timing(&state)?;
            let decision = guarantee_decision(GuaranteeMode::LegacyRefundNoEvidence);
            return Err(guarantee_failure("refund", decision));
        }

        Command::GenerateRefundCooperate { swap_id } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let (state, _secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;
            validate_persisted_timing(&state)?;
            let decision = guarantee_decision(GuaranteeMode::CooperativeRefundCommands);
            return Err(guarantee_failure("generate-refund-cooperate", decision));
        }

        Command::BuildRefund {
            swap_id,
            cooperate_msg,
            destination,
            xmr_daemon,
            wow_daemon,
            scan_from,
        } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let _ = (
                cooperate_msg,
                destination,
                xmr_daemon,
                wow_daemon,
                scan_from,
            );
            let (state, _secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;
            validate_persisted_timing(&state)?;
            let decision = guarantee_decision(GuaranteeMode::CooperativeRefundCommands);
            return Err(guarantee_failure("build-refund", decision));
        }

        Command::BroadcastRefund {
            swap_id,
            xmr_daemon,
            wow_daemon,
        } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;
            let _ = (xmr_daemon, wow_daemon);
            let (state, _secret_bytes, _) = load_and_decrypt_state(&store_shared.lock().unwrap(), &id, &enc_key)?;
            validate_persisted_timing(&state)?;

            let decision = match &state {
                SwapState::WowLocked { role, .. } | SwapState::XmrLocked { role, .. } => match role
                {
                    SwapRole::Alice => guarantee_decision(GuaranteeMode::LiveXmrUnlockTimeRefund),
                    SwapRole::Bob => guarantee_decision(GuaranteeMode::LiveWowCooperativeRefund),
                },
                other => anyhow::bail!("cannot broadcast refund from {} state", phase_name(other)),
            };
            return Err(guarantee_failure("broadcast-refund", decision));
        }

        Command::Resume { swap_id } => {
            let password = get_password(cli.password.as_deref())?;
            let salt = store_shared.lock().unwrap().get_or_create_salt()?;
            let enc_key = derive_key(password.as_bytes(), &salt);

            let id = parse_swap_id(&swap_id)?;

            let (state_json, encrypted_secret) = store_shared.lock().unwrap()
                .load_with_secret(&id)?
                .ok_or_else(|| anyhow::anyhow!("swap {} not found", swap_id))?;

            let state: SwapState = serde_json::from_str(&state_json)?;

            match &state {
                SwapState::Complete { .. } | SwapState::Refunded { .. } => {}
                _ => {
                    let encrypted_blob = encrypted_secret.ok_or_else(|| {
                        anyhow::anyhow!("no encrypted secret found for swap {}", swap_id)
                    })?;
                    let secret_bytes = decrypt_secret(&enc_key, &encrypted_blob)
                        .map_err(|_| anyhow::anyhow!("Wrong password"))?;

                    let scalar = Scalar::from_canonical_bytes(*secret_bytes)
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
            validate_persisted_timing(&state)?;

            println!("=== Swap Resume ===");
            println!("Swap ID: {}", swap_id);
            println!("Role:    {}", role_name(&state));
            println!("Phase:   {}", phase_name(&state));

            match &state {
                SwapState::JointAddress {
                    addresses, params, ..
                }
                | SwapState::XmrLocked {
                    addresses, params, ..
                }
                | SwapState::WowLocked {
                    addresses, params, ..
                } => {
                    println!("XMR address: {}", addresses.xmr_address);
                    println!("WOW address: {}", addresses.wow_address);
                    println!("Amount XMR:  {}", params.amount_xmr);
                    println!("Amount WOW:  {}", params.amount_wow);
                    print_refund_timing(params);
                }
                SwapState::Complete { addresses, .. } | SwapState::Refunded { addresses, .. } => {
                    println!("XMR address: {}", addresses.xmr_address);
                    println!("WOW address: {}", addresses.wow_address);
                }
                SwapState::KeyGeneration { params, .. }
                | SwapState::DleqExchange { params, .. } => {
                    println!("Amount XMR:  {}", params.amount_xmr);
                    println!("Amount WOW:  {}", params.amount_wow);
                    print_refund_timing(params);
                }
            }

            print_refund_checkpoints(&state);

            println!();
            println!("--- Next Safe Action ---");
            println!("{}", state.next_safe_action());
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
                Some(words) => {
                    mnemonic_to_scalar(&words, seed_coin).map_err(|e| anyhow::anyhow!("{}", e))?
                }
                None => Scalar::random(&mut OsRng),
            };
            let view_scalar = derive_view_key(&spend_scalar);
            let spend_pubkey = spend_scalar * G;
            let view_pubkey = view_scalar * G;
            let address = encode_address(&spend_pubkey, &view_pubkey, net);

            eprintln!("WARNING: These are private keys. Store them securely and never share them.");
            eprintln!();
            println!("Network:             {}", network);
            println!(
                "Spend key (private): {}",
                hex::encode(spend_scalar.to_bytes())
            );
            println!(
                "View key (private):  {}",
                hex::encode(view_scalar.to_bytes())
            );
            println!("Seed:                {}", scalar_to_mnemonic(&spend_scalar));
            println!("Address:             {}", address);
        }

        Command::ScanTest {
            network,
            daemon,
            spend_key,
            view_key,
            mnemonic,
            scan_from,
            verbose,
        } => {
            let seed_coin = if network.contains("wow") {
                SeedCoin::Wownero
            } else {
                SeedCoin::Monero
            };
            let (spend_scalar, view_scalar) =
                resolve_sender_keys(&mnemonic, &spend_key, &view_key, seed_coin)?;
            let spend_point = spend_scalar * G;
            let view_point = view_scalar * G;

            let address = if network.contains("wow") {
                encode_address(&spend_point, &view_point, Network::Wownero)
            } else {
                encode_address(&spend_point, &view_point, Network::MoneroStagenet)
            };
            println!("Scanning {} for address {}", network, address);
            println!(
                "Spend pubkey: {}",
                hex::encode(spend_point.compress().to_bytes())
            );
            // only print view privkey with --verbose
            if verbose {
                println!("View privkey: {}", hex::encode(view_scalar.to_bytes()));
            } else {
                println!("View privkey: [redacted, use --verbose to display]");
            }
            println!("Scan from: {} to tip", scan_from);

            if network.contains("wow") {
                let wallet = WowWallet::with_sender_keys(&daemon, spend_scalar, view_scalar)
                    .with_scan_from(scan_from);
                let results = wallet.scan(&spend_point, &view_scalar, scan_from).await?;
                println!("Found {} outputs", results.len());
                for r in &results {
                    println!(
                        "  height={} amount={} tx={}",
                        r.block_height,
                        r.amount,
                        hex::encode(r.tx_hash)
                    );
                }
            } else {
                let wallet = XmrWallet::with_sender_keys(&daemon, spend_scalar, view_scalar)
                    .with_scan_from(scan_from);
                let results = wallet.scan(&spend_point, &view_scalar, scan_from).await?;
                println!("Found {} outputs", results.len());
                for r in &results {
                    println!(
                        "  height={} amount={} tx={}",
                        r.block_height,
                        r.amount,
                        hex::encode(r.tx_hash)
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmr_wow_client::coord_message::wrap_protocol_message;
    use xmr_wow_crypto::{AdaptorSignature, CompletedSignature, DleqProof, KeyContribution};
    use rand::rngs::OsRng;

    fn dummy_swap_id() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn make_init_bytes() -> Vec<u8> {
        let contrib = KeyContribution::generate(&mut OsRng);
        let proof = DleqProof::prove(
            &contrib.secret,
            &contrib.public,
            b"xmr-wow-swap-v1",
            &mut OsRng,
        );
        let msg = xmr_wow_client::ProtocolMessage::Init {
            pubkey: contrib.public_bytes(),
            proof,
            amount_xmr: 1_000_000_000_000,
            amount_wow: 500_000_000_000_000,
            xmr_refund_height: 2000,
            wow_refund_height: 1000,
            refund_timing: None,
            alice_refund_address: None,
        };
        let coord = wrap_protocol_message(dummy_swap_id(), &msg).unwrap();
        serde_json::to_vec(&coord).unwrap()
    }

    fn make_response_bytes() -> Vec<u8> {
        let contrib = KeyContribution::generate(&mut OsRng);
        let proof = DleqProof::prove(
            &contrib.secret,
            &contrib.public,
            b"xmr-wow-swap-v1",
            &mut OsRng,
        );
        let msg = xmr_wow_client::ProtocolMessage::Response {
            pubkey: contrib.public_bytes(),
            proof,
            bob_refund_address: None,
        };
        let coord = wrap_protocol_message(dummy_swap_id(), &msg).unwrap();
        serde_json::to_vec(&coord).unwrap()
    }

    fn make_adaptor_pre_sig_bytes() -> Vec<u8> {
        let msg = xmr_wow_client::ProtocolMessage::AdaptorPreSig {
            pre_sig: AdaptorSignature {
                r_plus_t: [0xAAu8; 32],
                s_prime: [0xBBu8; 32],
            },
        };
        let coord = wrap_protocol_message(dummy_swap_id(), &msg).unwrap();
        serde_json::to_vec(&coord).unwrap()
    }

    fn make_claim_proof_bytes() -> Vec<u8> {
        let msg = xmr_wow_client::ProtocolMessage::ClaimProof {
            completed_sig: CompletedSignature {
                r_t: [0xCCu8; 32],
                s: [0xDDu8; 32],
            },
        };
        let coord = wrap_protocol_message(dummy_swap_id(), &msg).unwrap();
        serde_json::to_vec(&coord).unwrap()
    }

    #[test]
    fn derive_state_empty() {
        let (count, _, inferred) = derive_swap_state(&[]);
        assert_eq!(count, 0);
        assert_eq!(inferred, "No messages");
    }

    #[test]
    fn derive_state_init_only() {
        let msgs = vec![make_init_bytes()];
        let (count, last, inferred) = derive_swap_state(&msgs);
        assert_eq!(count, 1);
        assert_eq!(last, "Init");
        assert_eq!(inferred, "Awaiting Bob response");
    }

    #[test]
    fn derive_state_init_response() {
        let msgs = vec![make_init_bytes(), make_response_bytes()];
        let (count, last, inferred) = derive_swap_state(&msgs);
        assert_eq!(count, 2);
        assert_eq!(last, "Response");
        assert_eq!(inferred, "Awaiting lock transactions");
    }

    #[test]
    fn derive_state_init_response_adaptor_pre_sig() {
        let msgs = vec![
            make_init_bytes(),
            make_response_bytes(),
            make_adaptor_pre_sig_bytes(),
        ];
        let (count, last, inferred) = derive_swap_state(&msgs);
        assert_eq!(count, 3);
        assert_eq!(last, "AdaptorPreSig");
        assert_eq!(inferred, "Awaiting claim proof");
    }

    #[test]
    fn derive_state_full_sequence_claim_proof() {
        let msgs = vec![
            make_init_bytes(),
            make_response_bytes(),
            make_adaptor_pre_sig_bytes(),
            make_claim_proof_bytes(),
        ];
        let (count, last, inferred) = derive_swap_state(&msgs);
        assert_eq!(count, 4);
        assert_eq!(last, "ClaimProof");
        assert_eq!(inferred, "Complete (claim seen)");
    }
}
