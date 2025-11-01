//! Shared test helpers.

use xmr_wow_script::{Engine, ScriptContext, StubBackend, AlwaysFailBackend};

pub fn stub_engine() -> Engine<StubBackend> {
    Engine::new(StubBackend)
}

pub fn fail_engine() -> Engine<AlwaysFailBackend> {
    Engine::new(AlwaysFailBackend)
}

pub fn ctx(height: u64) -> ScriptContext {
    ScriptContext {
        current_height: height,
        tx_hash: [0xABu8; 32],
        output_id: [0xCDu8; 32],
    }
}

/// 32 bytes all set to `v`.
pub fn bytes32(v: u8) -> Vec<u8> {
    vec![v; 32]
}

/// 64 bytes all set to `v`.
pub fn bytes64(v: u8) -> Vec<u8> {
    vec![v; 64]
}
