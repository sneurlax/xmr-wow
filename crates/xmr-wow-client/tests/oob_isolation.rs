use std::sync::{Arc, Mutex};
use xmr_wow_client::{OobMessenger, SharechainMessenger};

#[test]
fn oob_messenger_is_zero_sized() {
    assert_eq!(
        std::mem::size_of::<OobMessenger>(),
        0,
        "OobMessenger must be a zero-sized type (no sharechain fields)"
    );
}

#[test]
fn sharechain_messenger_requires_node_url() {
    let store = Arc::new(Mutex::new(xmr_wow_client::SwapStore::open_in_memory().unwrap()));
    let m = SharechainMessenger {
        node_url: "http://127.0.0.1:34568".into(),
        store,
    };
    assert_eq!(
        m.node_url, "http://127.0.0.1:34568",
        "SharechainMessenger must store the node_url field"
    );
}

#[test]
fn oob_messenger_has_no_node_url_field() {
    // Adding any field to OobMessenger would break this struct literal.
    let _m = OobMessenger;
}

#[test]
fn sharechain_messenger_is_not_zero_sized() {
    assert_ne!(
        std::mem::size_of::<SharechainMessenger>(),
        0,
        "SharechainMessenger must NOT be zero-sized: it holds sharechain connection state"
    );
}
