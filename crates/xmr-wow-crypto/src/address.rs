// stub ; implementation provided by xmr-wow-crypto agent

/// Which Monero-family network an address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    MoneroMainnet,
    MoneroStagenet,
    MoneroTestnet,
    Wownero,
}
