//! Reqwest transport for monero-oxide and wownero-oxide daemon RPC.

use core::future::Future;

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
