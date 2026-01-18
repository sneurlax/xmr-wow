//! Stack machine execution engine.
//!
//! # Design constraints (NON-NEGOTIABLE)
//!
//! 1. The VM is NOT Turing-complete. There are no loop opcodes, no backward
//!    jumps, and no recursion. Each script executes in O(n) time where n is
//!    the number of opcodes. This is a deliberate security property: script
//!    execution time is bounded by the script length.
//!
//! 2. The VM NEVER PANICS on any input. All failure modes return
//!    `ExecutionResult { valid: false, error: Some(...) }`. Every opcode
//!    handler must use `?` or explicit error returns ; no unwrap/expect.
//!
//! 3. Hard limits enforced unconditionally:
//!    - Stack depth:    100 elements
//!    - Op count:       1 000 per execution
//!    - Script bytes:   10 KiB (enforced at deserialization, not here)
//!
//! # Stack element semantics
//!
//! Stack items are raw `Vec<u8>`. Truthiness: an item is TRUTHY if it is
//! non-empty and not all-zero bytes. This matches Bitcoin Script semantics.
//!
//! Numeric results (Equal, CheckKeyPair, CheckSig) push:
//!   - `[0x01]` for true
//!   - `[0x00]` for false

use crate::{
    backend::CryptoBackend,
    error::ScriptError,
    opcode::Opcode,
};

/// Execution limits. Tunable at Engine construction time.
pub struct Limits {
    pub max_stack_depth: usize,
    pub max_script_ops: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_stack_depth: 100,
            max_script_ops: 1000,
        }
    }
}

/// Context provided by the node for each script evaluation.
pub struct ScriptContext {
    /// Block height at which the spending transaction appears.
    pub current_height: u64,
    /// Hash of the spending transaction (for CheckSig message).
    pub tx_hash: [u8; 32],
    /// The output being spent (for audit / RevealSecret correlation).
    pub output_id: [u8; 32],
}

/// A secret-reveal event emitted when RevealSecret executes.
///
/// The node observes this to notify the counterparty chain watcher
/// that the key material has been extracted from the chain and should
/// be forwarded to the recipient.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretReveal {
    /// The commitment (e.g., K_b_prime) being revealed.
    pub commitment: [u8; 32],
    /// The recipient's sidechain public key to send the reveal to.
    pub recipient: [u8; 32],
}

/// Result of executing a script.
#[derive(Debug)]
pub struct ExecutionResult {
    /// True only if the script executed completely and the final stack
    /// state is valid (truthy top item, no pending if-blocks).
    pub valid: bool,
    /// Any RevealSecret events emitted during execution.
    pub revealed_secrets: Vec<SecretReveal>,
    /// Populated on any execution failure.
    pub error: Option<ScriptError>,
}

impl ExecutionResult {
    fn ok(revealed_secrets: Vec<SecretReveal>) -> Self {
        ExecutionResult { valid: true, revealed_secrets, error: None }
    }

    fn fail(err: ScriptError) -> Self {
        ExecutionResult { valid: false, revealed_secrets: vec![], error: Some(err) }
    }
}

/// The script execution engine.
///
/// Generic over `C: CryptoBackend` for zero-cost dispatch.
/// Use `Engine::<StubBackend>::default()` in tests.
/// Use `Engine::<Ed25519Backend>::default()` in production.
pub struct Engine<C: CryptoBackend> {
    pub crypto: C,
    pub limits: Limits,
}

impl<C: CryptoBackend> Engine<C> {
    pub fn new(crypto: C) -> Self {
        Engine { crypto, limits: Limits::default() }
    }

    pub fn with_limits(crypto: C, limits: Limits) -> Self {
        Engine { crypto, limits }
    }

    /// Execute `script` with `witness` items pre-loaded onto the stack.
    ///
    /// Witness items are pushed left-to-right before execution starts,
    /// so `witness[0]` ends up deepest and `witness[last]` is on top
    /// when the first opcode runs.
    ///
    /// The function always returns (never panics). On error, `valid=false`
    /// and `error` is populated.
    pub fn execute(
        &self,
        script: &[Opcode],
        witness: &[Vec<u8>],
        context: &ScriptContext,
    ) -> ExecutionResult {
        match self.execute_inner(script, witness, context) {
            Ok(revealed) => ExecutionResult::ok(revealed),
            Err(e) => ExecutionResult::fail(e),
        }
    }

    fn execute_inner(
        &self,
        script: &[Opcode],
        witness: &[Vec<u8>],
        context: &ScriptContext,
    ) -> Result<Vec<SecretReveal>, ScriptError> {
        let mut stack: Vec<Vec<u8>> = Vec::with_capacity(16);
        let mut revealed: Vec<SecretReveal> = Vec::new();
        let mut op_count: usize = 0;

        // Push witness items. Witness[0] deepest, witness[last] on top.
        for item in witness {
            self.push_checked(&mut stack, item.clone())?;
        }

        // Flatten the if/else/endif control flow into a single pass.
        // We pre-resolve the if-tree so that the execution loop is simple.
        let resolved = resolve_control_flow(script)?;
        let mut pc = 0usize;

        while pc < resolved.len() {
            // Op count guard ; prevents DoS via huge but valid scripts.
            op_count += 1;
            if op_count > self.limits.max_script_ops {
                return Err(ScriptError::OpCountExceeded { max: self.limits.max_script_ops });
            }

            let op = &resolved[pc];
            pc += 1;

            match op {
                ResolvedOp::Execute(opcode) => {
                    self.execute_opcode(opcode, &mut stack, context, &mut revealed)?;
                }
                ResolvedOp::JumpIfFalsy(target) => {
                    let top = self.pop(&mut stack, 1)?;
                    if !is_truthy(&top[0]) {
                        pc = *target;
                    }
                }
                ResolvedOp::Jump(target) => {
                    pc = *target;
                }
                ResolvedOp::Nop => {}
            }
        }

        // Final stack check: must have exactly one truthy item on top.
        // We require the script to leave a clean truthy result.
        if stack.is_empty() {
            return Err(ScriptError::VerifyFailed);
        }
        if !is_truthy(stack.last().unwrap()) {
            return Err(ScriptError::VerifyFailed);
        }

        Ok(revealed)
    }

    fn execute_opcode(
        &self,
        op: &Opcode,
        stack: &mut Vec<Vec<u8>>,
        context: &ScriptContext,
        revealed: &mut Vec<SecretReveal>,
    ) -> Result<(), ScriptError> {
        match op {
            Opcode::Push(data) => {
                self.push_checked(stack, data.clone())?;
            }

            Opcode::Dup => {
                let top = stack
                    .last()
                    .ok_or(ScriptError::StackUnderflow { needed: 1, have: 0 })?
                    .clone();
                self.push_checked(stack, top)?;
            }

            Opcode::Drop => {
                self.pop(stack, 1)?;
            }

            Opcode::Swap => {
                let items = self.pop(stack, 2)?;
                // items[0] was top, items[1] was below ; swap them back
                self.push_checked(stack, items[0].clone())?;
                self.push_checked(stack, items[1].clone())?;
            }

            Opcode::Pick(n) => {
                let idx = *n as usize;
                if idx >= stack.len() {
                    return Err(ScriptError::PickOutOfRange {
                        index: idx,
                        depth: stack.len(),
                    });
                }
                let item = stack[stack.len() - 1 - idx].clone();
                self.push_checked(stack, item)?;
            }

            Opcode::Equal => {
                let items = self.pop(stack, 2)?;
                let result = if items[0] == items[1] { vec![0x01] } else { vec![0x00] };
                self.push_checked(stack, result)?;
            }

            Opcode::EqualVerify => {
                let items = self.pop(stack, 2)?;
                if items[0] != items[1] {
                    return Err(ScriptError::EqualVerifyFailed);
                }
            }

            Opcode::Verify => {
                let items = self.pop(stack, 1)?;
                if !is_truthy(&items[0]) {
                    return Err(ScriptError::VerifyFailed);
                }
            }

            Opcode::CheckKeyPair => {
                // Stack: [..., scalar (32), point (32)]  ; point on top
                let items = self.pop(stack, 2)?;
                let point_bytes = to_32(&items[0])?; // top
                let scalar_bytes = to_32(&items[1])?; // below top
                let valid = self.crypto.check_keypair(scalar_bytes, point_bytes)?;
                self.push_checked(stack, if valid { vec![0x01] } else { vec![0x00] })?;
            }

            Opcode::CheckKeyPairVerify => {
                let items = self.pop(stack, 2)?;
                let point_bytes = to_32(&items[0])?;
                let scalar_bytes = to_32(&items[1])?;
                let valid = self.crypto.check_keypair(scalar_bytes, point_bytes)?;
                if !valid {
                    return Err(ScriptError::KeyPairMismatch);
                }
            }

            Opcode::CheckSig => {
                // Stack: [..., message (var), pubkey (32), sig (64)]  ; sig on top
                let sig_raw = self.pop_one(stack)?;
                let pubkey_raw = self.pop_one(stack)?;
                let msg = self.pop_one(stack)?;
                let sig = to_64(&sig_raw)?;
                let pubkey = to_32(&pubkey_raw)?;
                let valid = self.crypto.check_sig(sig, pubkey, &msg)?;
                self.push_checked(stack, if valid { vec![0x01] } else { vec![0x00] })?;
            }

            Opcode::CheckSigVerify => {
                let sig_raw = self.pop_one(stack)?;
                let pubkey_raw = self.pop_one(stack)?;
                let msg = self.pop_one(stack)?;
                let sig = to_64(&sig_raw)?;
                let pubkey = to_32(&pubkey_raw)?;
                let valid = self.crypto.check_sig(sig, pubkey, &msg)?;
                if !valid {
                    return Err(ScriptError::SignatureInvalid);
                }
            }

            Opcode::Hash256 => {
                let data = self.pop_one(stack)?;
                let digest = self.crypto.hash256(&data);
                self.push_checked(stack, digest.to_vec())?;
            }

            Opcode::HashLockVerify => {
                // Stack: [..., preimage (var), expected_hash (32)]  ; hash on top
                let expected = self.pop_one(stack)?;
                let preimage = self.pop_one(stack)?;
                let expected = to_32(&expected)?;
                let actual = self.crypto.hash256(&preimage);
                if actual != *expected {
                    return Err(ScriptError::HashLockMismatch);
                }
            }

            Opcode::CheckLockTimeVerify(required) => {
                if context.current_height < *required {
                    return Err(ScriptError::LockTimeNotReached {
                        current: context.current_height,
                        required: *required,
                    });
                }
            }

            Opcode::CheckLockTimeExpiry(expiry) => {
                if context.current_height >= *expiry {
                    return Err(ScriptError::LockTimeExpired {
                        current: context.current_height,
                        expiry: *expiry,
                    });
                }
            }

            Opcode::RevealSecret => {
                // Stack: [..., recipient_pubkey (32), secret_commitment (32)]
                // commitment on top
                let commitment_raw = self.pop_one(stack)?;
                let recipient_raw = self.pop_one(stack)?;
                let commitment = *to_32(&commitment_raw)?;
                let recipient = *to_32(&recipient_raw)?;
                revealed.push(SecretReveal { commitment, recipient });
            }

            // Control flow opcodes (If/Else/EndIf) should have been
            // resolved by resolve_control_flow and replaced with
            // JumpIfFalsy / Jump / Nop. Hitting them here is a bug.
            Opcode::If | Opcode::Else | Opcode::EndIf => {
                return Err(ScriptError::UnmatchedControlFlow);
            }
        }
        Ok(())
    }

    /// Push an item, enforcing the stack depth limit.
    fn push_checked(
        &self,
        stack: &mut Vec<Vec<u8>>,
        item: Vec<u8>,
    ) -> Result<(), ScriptError> {
        if stack.len() >= self.limits.max_stack_depth {
            return Err(ScriptError::StackDepthExceeded {
                max: self.limits.max_stack_depth,
            });
        }
        stack.push(item);
        Ok(())
    }

    /// Pop `n` items from the stack. Returns them with index 0 = top.
    fn pop(&self, stack: &mut Vec<Vec<u8>>, n: usize) -> Result<Vec<Vec<u8>>, ScriptError> {
        if stack.len() < n {
            return Err(ScriptError::StackUnderflow { needed: n, have: stack.len() });
        }
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            items.push(stack.pop().unwrap());
        }
        Ok(items)
    }

    fn pop_one(&self, stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, ScriptError> {
        stack
            .pop()
            .ok_or(ScriptError::StackUnderflow { needed: 1, have: 0 })
    }
}

// -- Control flow resolution ---------------------------------------------------
//
// Before execution we flatten if/else/endif into jump instructions.
// This makes the execution loop simple and avoids recursive nesting.

#[derive(Debug)]
enum ResolvedOp<'a> {
    /// Execute this opcode normally.
    Execute(&'a Opcode),
    /// Pop top of stack; if falsy, jump to `target` (absolute index in resolved vec).
    JumpIfFalsy(usize),
    /// Unconditional jump.
    Jump(usize),
    /// No-op placeholder (was an Else or EndIf marker).
    Nop,
}

fn resolve_control_flow(script: &[Opcode]) -> Result<Vec<ResolvedOp<'_>>, ScriptError> {
    // First pass: emit ResolvedOps with placeholder targets (0).
    // Second pass: backpatch targets.
    //
    // For each If:
    //   emit JumpIfFalsy(?) ; placeholder, points to after Else or EndIf
    // For each Else:
    //   emit Jump(?)        ; placeholder, points to after EndIf
    //   the If's JumpIfFalsy is patched to point here+1 (first op of else-branch)
    // For each EndIf:
    //   emit Nop
    //   patch the pending jump target to point here

    let mut resolved: Vec<ResolvedOp<'_>> = Vec::with_capacity(script.len());
    // Stack of (if_jump_idx, else_jump_idx_opt) for nesting
    let mut if_stack: Vec<(usize, Option<usize>)> = Vec::new();

    for op in script {
        match op {
            Opcode::If => {
                let jump_idx = resolved.len();
                resolved.push(ResolvedOp::JumpIfFalsy(0)); // target TBD
                if_stack.push((jump_idx, None));
            }
            Opcode::Else => {
                let (if_jump_idx, ref else_jump_opt) = if_stack
                    .last_mut()
                    .ok_or(ScriptError::UnmatchedControlFlow)?;
                if else_jump_opt.is_some() {
                    return Err(ScriptError::UnmatchedControlFlow);
                }
                // Emit unconditional Jump (skips else-branch when if-branch taken)
                let else_jump_idx = resolved.len();
                resolved.push(ResolvedOp::Jump(0)); // target TBD
                // Patch the If's JumpIfFalsy to jump here+1 (start of else-branch)
                if let ResolvedOp::JumpIfFalsy(ref mut t) = resolved[*if_jump_idx] {
                    *t = else_jump_idx + 1;
                }
                let entry = if_stack.last_mut().unwrap();
                entry.1 = Some(else_jump_idx);
            }
            Opcode::EndIf => {
                let (if_jump_idx, else_jump_opt) = if_stack
                    .pop()
                    .ok_or(ScriptError::UnmatchedControlFlow)?;
                let end_idx = resolved.len(); // index of the Nop we're about to push
                resolved.push(ResolvedOp::Nop);
                match else_jump_opt {
                    Some(else_jump_idx) => {
                        // Patch the Else's Jump to point past EndIf
                        if let ResolvedOp::Jump(ref mut t) = resolved[else_jump_idx] {
                            *t = end_idx + 1;
                        }
                        // If's JumpIfFalsy was already patched in Else handling
                    }
                    None => {
                        // No else-branch: If's JumpIfFalsy should jump to end_idx+1
                        if let ResolvedOp::JumpIfFalsy(ref mut t) = resolved[if_jump_idx] {
                            *t = end_idx + 1;
                        }
                    }
                }
            }
            other => {
                resolved.push(ResolvedOp::Execute(other));
            }
        }
    }

    if !if_stack.is_empty() {
        return Err(ScriptError::UnmatchedControlFlow);
    }

    Ok(resolved)
}

// -- Helpers -------------------------------------------------------------------

/// An item is truthy if it is non-empty and not all-zero bytes.
fn is_truthy(item: &[u8]) -> bool {
    !item.is_empty() && item.iter().any(|&b| b != 0)
}

fn to_32(bytes: &[u8]) -> Result<&[u8; 32], ScriptError> {
    bytes
        .try_into()
        .map_err(|_| ScriptError::InvalidPointLength { got: bytes.len() })
}

fn to_64(bytes: &[u8]) -> Result<&[u8; 64], ScriptError> {
    bytes
        .try_into()
        .map_err(|_| ScriptError::InvalidSignatureLength { got: bytes.len() })
}
