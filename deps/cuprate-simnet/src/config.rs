use cuprate_consensus_context::ContextConfig;
use cuprate_helper::network::Network;

#[derive(Debug, Clone)]
pub struct SimnetConfig {
    pub network: Network,
    /// always true for now; here so callers can gate on it later
    pub skip_pow: bool,
    pub reader_threads: usize,
}

impl SimnetConfig {
    pub fn mainnet() -> Self {
        Self { network: Network::Mainnet, skip_pow: true, reader_threads: 1 }
    }

    pub fn testnet() -> Self {
        Self { network: Network::Testnet, skip_pow: true, reader_threads: 1 }
    }

    pub fn context_config(&self) -> ContextConfig {
        match self.network {
            Network::Mainnet => ContextConfig::main_net(),
            Network::Testnet => ContextConfig::test_net(),
            Network::Stagenet => ContextConfig::stage_net(),
        }
    }
}

impl Default for SimnetConfig {
    fn default() -> Self {
        Self::mainnet()
    }
}
