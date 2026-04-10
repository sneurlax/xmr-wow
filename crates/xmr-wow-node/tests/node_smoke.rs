//! Smoke tests for the xmr-wow-node binary.

use std::process::{Command, Stdio};
use std::time::Duration;

/// Path to the xmr-wow-node binary, resolved by cargo at compile time.
fn node_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo when running integration tests
    // for binary crates. The binary is compiled before tests run.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_xmr-wow-node"))
}

/// Test 1: --help exits 0 and mentions "sharechain node".
#[test]
fn test_help_flag() {
    let output = Command::new(node_bin())
        .arg("--help")
        .output()
        .expect("failed to run xmr-wow-node --help");

    assert!(
        output.status.success(),
        "xmr-wow-node --help should exit 0, got: {}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sharechain node"),
        "help output should mention 'sharechain node', got:\n{}",
        stdout
    );
}

/// Test 2: --rpc-only starts and responds to JSON-RPC get_chain_height.
///
/// The RPC server exposes POST /json_rpc (JSON-RPC 2.0 protocol).
/// We use a fixed high port (45321) and blocking std::net::TcpStream
/// to avoid pulling in async dependencies.
#[test]
fn test_rpc_only_serves_json_rpc() {
    let port: u16 = 45321;

    let mut child = Command::new(node_bin())
        .arg("--rpc-only")
        .arg("--rpc-port")
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn xmr-wow-node --rpc-only");

    // Give the server time to start.
    std::thread::sleep(Duration::from_millis(600));

    let result = json_rpc_call(
        &format!("127.0.0.1:{}", port),
        r#"{"jsonrpc":"2.0","method":"get_chain_height","params":{},"id":1}"#,
    );

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok((status, body)) => {
            assert_eq!(
                status, 200,
                "JSON-RPC endpoint should return HTTP 200, got {}; body: {}",
                status, body
            );
            assert!(
                body.contains("height"),
                "JSON-RPC response should contain 'height', got: {}",
                body
            );
        }
        Err(e) => {
            panic!("JSON-RPC call to /json_rpc failed: {}", e);
        }
    }
}

/// Minimal blocking HTTP POST using only std::net::TcpStream.
/// Returns (status_code, response_body).
fn json_rpc_call(addr: &str, json_body: &str) -> Result<(u16, String), String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(addr)
        .map_err(|e| format!("connect to {}: {}", addr, e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok();

    let request = format!(
        "POST /json_rpc HTTP/1.0\r\n\
         Host: {addr}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        addr = addr,
        len = json_body.len(),
        body = json_body
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {}", e))?;

    // Split headers from body.
    let (header_part, body_part) = if let Some(pos) = response.find("\r\n\r\n") {
        (&response[..pos], response[pos + 4..].to_string())
    } else {
        (response.as_str(), String::new())
    };

    // Parse status code from first line.
    let first_line = header_part.lines().next().unwrap_or("");
    let status_str = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("no status in response: {:?}", first_line))?;
    let status = status_str
        .parse::<u16>()
        .map_err(|e| format!("parse status '{}': {}", status_str, e))?;

    Ok((status, body_part))
}
