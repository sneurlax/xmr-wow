// stub

/// Which Monero-family network an address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    MoneroMainnet,
    MoneroStagenet,
    MoneroTestnet,
    Wownero,
}
