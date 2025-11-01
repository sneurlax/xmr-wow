//! Property-based no-panic tests for the VM.
//!
//! Invariant: the VM must NEVER panic on any input.
//! Uses proptest on stable Rust (libfuzzer requires nightly).

mod helpers;
use helpers::ctx;
use proptest::prelude::*;
use xmr_wow_script::{deserialize_script, Engine, ScriptContext, StubBackend};

fn engine() -> Engine<StubBackend> {
    Engine::new(StubBackend)
}

proptest! {
    // Full random bytes as script with empty witness
    #[test]
    fn arbitrary_bytes_as_script_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(script) = deserialize_script(&data) {
            let result = engine().execute(&script, &[], &ctx(0));
            let _ = result; // must not panic
        }
    }

    // Split arbitrary bytes into script + witness
    #[test]
    fn arbitrary_split_script_witness_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..512),
        height in 0u64..10_000
    ) {
        let mid = data.len() / 2;
        let script_bytes = &data[..mid];
        let witness_bytes = &data[mid..];
        if let Ok(script) = deserialize_script(script_bytes) {
            let witness: Vec<Vec<u8>> = witness_bytes.chunks(32).map(|c| c.to_vec()).collect();
            let ctx = ScriptContext { current_height: height, tx_hash: [0u8;32], output_id: [0u8;32] };
            let result = engine().execute(&script, &witness, &ctx);
            let _ = result;
        }
    }

    // Arbitrary witness items with known-valid scripts
    #[test]
    fn arbitrary_witness_on_push_script_never_panics(
        items in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..128),
            0..20
        )
    ) {
        use xmr_wow_script::Opcode;
        let script = vec![Opcode::Push(vec![0x01])];
        let result = engine().execute(&script, &items, &ctx(0));
        let _ = result;
    }
}
