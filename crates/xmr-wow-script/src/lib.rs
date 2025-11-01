// xmr-wow-script: escrow script VM for XMR<->WOW swaps
// Ported from xmr-script-vm; semantics unchanged.

pub mod backend;
pub mod engine;
pub mod error;
pub mod opcode;
pub mod scripts;

pub use engine::{Engine, ExecutionResult, Limits, ScriptContext, SecretReveal};
pub use error::ScriptError;
pub use opcode::{deserialize_script, serialize_script, Opcode};

#[cfg(feature = "stub-crypto")]
pub use backend::{AlwaysFailBackend, StubBackend};

#[cfg(feature = "real-crypto")]
pub use backend::Ed25519Backend;
