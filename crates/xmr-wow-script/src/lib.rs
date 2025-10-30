// xmr-wow-script: escrow script VM for XMR<->WOW swaps
// Ported from xmr-script-vm; semantics unchanged.

pub mod opcode;
pub mod engine;
pub mod backend;
pub mod error;
pub mod scripts;

pub use engine::Engine;
pub use error::VmError;
pub use scripts::swap_escrow::build_swap_escrow_script;

#[cfg(feature = "stub-crypto")]
pub use backend::{StubBackend, AlwaysFailBackend};
