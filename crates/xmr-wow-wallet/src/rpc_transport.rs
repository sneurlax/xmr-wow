//! Reqwest transport for monero-oxide and wownero-oxide daemon RPC.

use core::future::Future;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

/// Shared daemon transport for both chains.
#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    url: String,
}

impl ReqwestTransport {
    /// Build a transport for the given daemon URL.
    pub fn new(url: &str) -> Self {
        ReqwestTransport {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build reqwest client"),
            url: url.trim_end_matches('/').to_string(),
        }
    }

    /// Build a Monero daemon handle.
    pub async fn monero_daemon(
        &self,
    ) -> Result<monero_daemon_rpc::MoneroDaemon<Self>, monero_interface::InterfaceError> {
        monero_daemon_rpc::MoneroDaemon::new(self.clone()).await
    }

    /// Build a Wownero daemon handle.
    pub async fn wownero_daemon(
        &self,
    ) -> Result<wownero_daemon_rpc::MoneroDaemon<Self>, wownero_interface::InterfaceError> {
        wownero_daemon_rpc::MoneroDaemon::new(self.clone()).await
    }

    /// Shared POST path for both daemon traits.
    async fn post_inner(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> Result<Vec<u8>, String> {
        let url = format!("{}/{}", self.url, route);
        let content_type = if route.ends_with(".bin") {
            "application/octet-stream"
        } else {
            "application/json"
        };
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("reqwest POST {} (daemon: {}): {}", route, self.url, e))?;

        let mut bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("reqwest read body {} (daemon: {}): {}", route, self.url, e))?
            .to_vec();

        if let Some(limit) = response_size_limit {
            bytes.truncate(limit);
        }

        Ok(bytes)
    }
}

/// Perform a plain HTTP/1.1 JSON POST without relying on reqwest/hyper body
/// decoding. Used for Shadow-only `/get_transactions` confirmation polling,
/// where reqwest's body readers fail below the serde layer.
pub async fn post_json_http1_identity_raw(
    base_url: &str,
    route: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|e| format!("parse daemon url {}: {}", base_url, e))?;
    if url.scheme() != "http" {
        return Err(format!(
            "unsupported daemon scheme for raw transport {}: {}",
            base_url,
            url.scheme()
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| format!("missing host in daemon url {}", base_url))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("missing port in daemon url {}", base_url))?;
    let route = route.trim_start_matches('/');
    let base_path = url.path().trim_end_matches('/');
    let request_path = if base_path.is_empty() || base_path == "/" {
        format!("/{}", route)
    } else {
        format!("{}/{}", base_path, route)
    };
    let host_header = if let Some(explicit_port) = url.port() {
        format!("{}:{}", host, explicit_port)
    } else {
        host.to_string()
    };

    let mut stream = timeout(Duration::from_secs(30), TcpStream::connect((host, port)))
        .await
        .map_err(|_| format!("connect timeout {}{}", base_url, request_path))?
        .map_err(|e| format!("connect {}{}: {}", base_url, request_path, e))?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        request_path,
        host_header,
        body.len()
    );

    timeout(
        Duration::from_secs(30),
        stream.write_all(request.as_bytes()),
    )
    .await
    .map_err(|_| format!("write timeout {}{}", base_url, request_path))?
    .map_err(|e| format!("write {}{}: {}", base_url, request_path, e))?;
    timeout(Duration::from_secs(30), stream.write_all(body))
        .await
        .map_err(|_| format!("body write timeout {}{}", base_url, request_path))?
        .map_err(|e| format!("body write {}{}: {}", base_url, request_path, e))?;
    timeout(Duration::from_secs(30), stream.flush())
        .await
        .map_err(|_| format!("flush timeout {}{}", base_url, request_path))?
        .map_err(|e| format!("flush {}{}: {}", base_url, request_path, e))?;

    let response = read_http_response(&mut stream, base_url, &request_path).await?;
    extract_http_body(&response, base_url, &request_path)
}

async fn read_http_response(
    stream: &mut TcpStream,
    base_url: &str,
    request_path: &str,
) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];

    loop {
        let read = timeout(Duration::from_secs(30), stream.read(&mut buf))
            .await
            .map_err(|_| format!("read timeout {}{}", base_url, request_path))?
            .map_err(|e| format!("read {}{}: {}", base_url, request_path, e))?;

        if read == 0 {
            break;
        }

        response.extend_from_slice(&buf[..read]);

        if let Some(complete_len) = response_complete_len(&response)? {
            response.truncate(complete_len);
            return Ok(response);
        }
    }

    Ok(response)
}

fn response_complete_len(response: &[u8]) -> Result<Option<usize>, String> {
    let Some(headers_end) = find_subslice(response, b"\r\n\r\n") else {
        return Ok(None);
    };
    let body_start = headers_end + 4;
    let header_text = String::from_utf8_lossy(&response[..headers_end]);

    if header_value(&header_text, "transfer-encoding")
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return match decode_chunked_body(&response[body_start..]) {
            Ok((_, consumed)) => Ok(Some(body_start + consumed)),
            Err(err) if err == "incomplete chunked body" => Ok(None),
            Err(err) => Err(err),
        };
    }

    if let Some(length) = header_value(&header_text, "content-length") {
        let expected = length
            .trim()
            .parse::<usize>()
            .map_err(|e| format!("invalid content-length {:?}: {}", length, e))?;
        if response.len() >= body_start + expected {
            return Ok(Some(body_start + expected));
        }
        return Ok(None);
    }

    Ok(None)
}

fn extract_http_body(
    response: &[u8],
    base_url: &str,
    request_path: &str,
) -> Result<Vec<u8>, String> {
    let headers_end = find_subslice(response, b"\r\n\r\n").ok_or_else(|| {
        format!(
            "malformed HTTP response {}{}: missing header terminator ({} bytes, first 200: {:?})",
            base_url,
            request_path,
            response.len(),
            String::from_utf8_lossy(&response[..response.len().min(200)]),
        )
    })?;
    let body_start = headers_end + 4;
    let header_text = String::from_utf8_lossy(&response[..headers_end]);

    if header_value(&header_text, "transfer-encoding")
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        let (body, _) = decode_chunked_body(&response[body_start..])?;
        return Ok(body);
    }

    if let Some(length) = header_value(&header_text, "content-length") {
        let expected = length
            .trim()
            .parse::<usize>()
            .map_err(|e| format!("invalid content-length {:?}: {}", length, e))?;
        if response.len() < body_start + expected {
            return Err(format!(
                "truncated HTTP body {}{}: expected {} bytes, got {}",
                base_url,
                request_path,
                expected,
                response.len().saturating_sub(body_start)
            ));
        }
        return Ok(response[body_start..body_start + expected].to_vec());
    }

    Ok(response[body_start..].to_vec())
}

fn decode_chunked_body(body: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut out = Vec::new();
    let mut cursor = 0;

    loop {
        let Some(line_end_rel) = find_subslice(&body[cursor..], b"\r\n") else {
            return Err("incomplete chunked body".into());
        };
        let line_end = cursor + line_end_rel;
        let size_line = std::str::from_utf8(&body[cursor..line_end])
            .map_err(|e| format!("invalid chunk size line: {}", e))?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|e| format!("invalid chunk size {:?}: {}", size_hex, e))?;

        cursor = line_end + 2;
        if body.len() < cursor + size + 2 {
            return Err("incomplete chunked body".into());
        }

        out.extend_from_slice(&body[cursor..cursor + size]);
        cursor += size;

        if &body[cursor..cursor + 2] != b"\r\n" {
            return Err("chunk missing trailing CRLF".into());
        }
        cursor += 2;

        if size == 0 {
            while body.len() >= cursor + 2 {
                if &body[cursor..cursor + 2] == b"\r\n" {
                    cursor += 2;
                    break;
                }

                let Some(trailer_end_rel) = find_subslice(&body[cursor..], b"\r\n") else {
                    return Err("incomplete chunked trailer".into());
                };
                cursor += trailer_end_rel + 2;
            }
            return Ok((out, cursor));
        }
    }
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

impl monero_daemon_rpc::HttpTransport for ReqwestTransport {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, monero_interface::InterfaceError>> {
        let route = route.to_string();
        let this = self.clone();
        async move {
            this.post_inner(&route, body, response_size_limit)
                .await
                .map_err(monero_interface::InterfaceError::InterfaceError)
        }
    }
}

impl wownero_daemon_rpc::HttpTransport for ReqwestTransport {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, wownero_interface::InterfaceError>> {
        let route = route.to_string();
        let this = self.clone();
        async move {
            this.post_inner(&route, body, response_size_limit)
                .await
                .map_err(wownero_interface::InterfaceError::InterfaceError)
        }
    }
}
