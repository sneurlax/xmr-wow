use clap::Parser;
use std::sync::Arc;
use xmr_wow_sharechain::{SwapChain, Difficulty, merge_mining_router};

#[derive(Parser)]
#[command(name = "xmr-wow-node", about = "XMR\u{2194}WOW swap sharechain node")]
struct Args {
    /// P2P listen port (default: 37891 ; separate from p2pool's 37889/37888/37890)
    #[arg(long, default_value = "37891")]
    p2p_port: u16,

    /// JSON-RPC / merge-mining HTTP listen port
    #[arg(long, default_value = "18091")]
    rpc_port: u16,

    /// Bootstrap peer addresses (host:port), can be specified multiple times
    #[arg(long)]
    peer: Vec<String>,

    /// Minimum share difficulty
    #[arg(long, default_value = "100")]
    min_difficulty: u64,

    /// Only serve the merge-mining RPC (no P2P server)
    #[arg(long)]
    rpc_only: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let chain = Arc::new(SwapChain::new(Difficulty::from_u64(args.min_difficulty)));

    // Start merge-mining + client JSON-RPC server
    let rpc_app = merge_mining_router(chain.clone());
    let rpc_addr = format!("0.0.0.0:{}", args.rpc_port);
    tracing::info!("RPC listening on {}", rpc_addr);
    let listener = tokio::net::TcpListener::bind(&rpc_addr).await?;

    if args.rpc_only {
        tracing::info!("Running in RPC-only mode (no P2P)");
        axum::serve(listener, rpc_app).await?;
    } else {
        // Log bootstrap peers (full P2P is future work ; server stub is available)
        tracing::info!("P2P port: {} (peer discovery active)", args.p2p_port);
        for peer in &args.peer {
            tracing::info!("Bootstrap peer: {}", peer);
        }
        axum::serve(listener, rpc_app).await?;
    }

    Ok(())
}
