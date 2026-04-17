use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use monero_wallet::address::Network as XmrNetwork;
use simnet_testbed::{
    cuprate_simnet::SimnetWallet, wownero_simnet::WowSimnetWallet, SimnetTestbed,
};

struct Args {
    env_file: PathBuf,
    bind_host: String,
    local_host: String,
    docker_host: String,
    mine_interval_ms: u64,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut env_file = None;
    let mut bind_host = String::from("0.0.0.0");
    let mut local_host = String::from("127.0.0.1");
    let mut docker_host = String::from("host.docker.internal");
    let mut mine_interval_ms = 1_000_u64;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--env-file" => env_file = Some(PathBuf::from(expect_value(&mut args, "--env-file")?)),
            "--bind-host" => bind_host = expect_value(&mut args, "--bind-host")?,
            "--local-host" => local_host = expect_value(&mut args, "--local-host")?,
            "--docker-host" => docker_host = expect_value(&mut args, "--docker-host")?,
            "--mine-interval-ms" => {
                mine_interval_ms = expect_value(&mut args, "--mine-interval-ms")?
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid --mine-interval-ms: {e}"))?;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    let env_file = env_file.ok_or_else(|| anyhow::anyhow!("--env-file is required"))?;

    Ok(Args {
        env_file,
        bind_host,
        local_host,
        docker_host,
        mine_interval_ms,
    })
}

fn expect_value(args: &mut impl Iterator<Item = String>, flag: &str) -> anyhow::Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run --manifest-path deps/simnet-testbed/Cargo.toml --bin docker-runtime-backend -- \\
  --env-file <path> [--bind-host 0.0.0.0] [--local-host 127.0.0.1] \\
  [--docker-host host.docker.internal] [--mine-interval-ms 1000]"
    );
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn wow_mainnet_address(wallet: &WowSimnetWallet) -> String {
    wallet
        .address(wownero_wallet::address::Network::Mainnet)
        .to_string()
}

fn xmr_stagenet_address(wallet: &SimnetWallet) -> String {
    wallet.address(XmrNetwork::Stagenet).to_string()
}

fn write_env_file(
    path: &Path,
    docker_host: &str,
    testbed: &SimnetTestbed,
    alice_xmr: &SimnetWallet,
    bob_wow: &WowSimnetWallet,
    alice_wow_dest: &WowSimnetWallet,
    bob_xmr_dest: &SimnetWallet,
) -> anyhow::Result<()> {
    let xmr_daemon = format!("http://{}:{}", docker_host, testbed.xmr_rpc_port());
    let wow_daemon = format!("http://{}:{}", docker_host, testbed.wow_rpc_port());
    let contents = format!(
        "\
XMR_DAEMON_URL={xmr_daemon}
WOW_DAEMON_URL={wow_daemon}
SWAP_PASSWORD=proof-harness
XMR_WOW_PROOF_HARNESS=1
ALICE_XMR_REFUND_ADDRESS={alice_xmr_refund}
ALICE_WOW_DESTINATION_ADDRESS={alice_wow_dest}
BOB_WOW_REFUND_ADDRESS={bob_wow_refund}
BOB_XMR_DESTINATION_ADDRESS={bob_xmr_dest}
ALICE_XMR_SPEND_KEY={alice_xmr_spend}
ALICE_XMR_VIEW_KEY={alice_xmr_view}
BOB_WOW_SPEND_KEY={bob_wow_spend}
BOB_WOW_VIEW_KEY={bob_wow_view}
ALICE_XMR_SCAN_FROM=0
ALICE_WOW_SCAN_FROM=0
BOB_WOW_SCAN_FROM=0
BOB_XMR_SCAN_FROM=0
AMOUNT_XMR=500000000000
AMOUNT_WOW=500000000000
XMR_REFUND_DELAY=80
WOW_REFUND_DELAY=240
",
        alice_xmr_refund = xmr_stagenet_address(alice_xmr),
        alice_wow_dest = wow_mainnet_address(alice_wow_dest),
        bob_wow_refund = wow_mainnet_address(bob_wow),
        bob_xmr_dest = xmr_stagenet_address(bob_xmr_dest),
        alice_xmr_spend = bytes_hex(&alice_xmr.spend_scalar.to_bytes()),
        alice_xmr_view = bytes_hex(&alice_xmr.view_scalar.to_bytes()),
        bob_wow_spend = bytes_hex(&bob_wow.spend_scalar.to_bytes()),
        bob_wow_view = bytes_hex(&bob_wow.view_scalar.to_bytes()),
    );
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, contents)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    let env_parent = args
        .env_file
        .parent()
        .ok_or_else(|| anyhow::anyhow!("env file must have a parent directory"))?;
    fs::create_dir_all(env_parent)?;

    let testbed = SimnetTestbed::new_with_rpc_hosts(&args.bind_host, &args.local_host).await?;
    let alice_xmr = SimnetWallet::generate();
    let bob_wow = WowSimnetWallet::generate();
    let alice_wow_dest = WowSimnetWallet::generate();
    let bob_xmr_dest = SimnetWallet::generate();

    testbed
        .mine_xmr_to(&alice_xmr.spend_pub, &alice_xmr.view_scalar, 2)
        .await?;
    testbed.mine_xmr(66).await?;
    testbed
        .mine_wow_to(&bob_wow.spend_pub, &bob_wow.view_scalar, 2)
        .await?;
    testbed.mine_wow(100).await?;

    write_env_file(
        &args.env_file,
        &args.docker_host,
        &testbed,
        &alice_xmr,
        &bob_wow,
        &alice_wow_dest,
        &bob_xmr_dest,
    )?;

    eprintln!(
        "docker-runtime-backend ready: xmr=http://{}:{} wow=http://{}:{} env_file={}",
        args.local_host,
        testbed.xmr_rpc_port(),
        args.local_host,
        testbed.wow_rpc_port(),
        args.env_file.display(),
    );

    let mine_interval = Duration::from_millis(args.mine_interval_ms);
    let miner = tokio::spawn(async move {
        loop {
            if let Err(err) = testbed.mine_xmr(1).await {
                eprintln!("xmr auto-mine failed: {err}");
                break;
            }
            if let Err(err) = testbed.mine_wow(1).await {
                eprintln!("wow auto-mine failed: {err}");
                break;
            }
            tokio::time::sleep(mine_interval).await;
        }
    });

    shutdown_signal().await;
    miner.abort();
    let _ = miner.await;
    Ok(())
}
