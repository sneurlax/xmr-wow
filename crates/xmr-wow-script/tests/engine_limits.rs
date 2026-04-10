//! Tests for engine resource limit enforcement.

mod helpers;
use helpers::{ctx, stub_engine};
use xmr_wow_script::{Engine, Limits, Opcode, ScriptError, StubBackend};

fn limited_engine(max_ops: usize, max_depth: usize) -> Engine<StubBackend> {
    Engine::with_limits(
        StubBackend,
        Limits { max_stack_depth: max_depth, max_script_ops: max_ops },
    )
}

// -- Op count limit ------------------------------------------------------------

#[test]
fn max_script_ops_limit_enforced() {
    // Use a limit of 5 ops to make it easy to test:
    let eng = limited_engine(5, 1000);
    let script = vec![
        Opcode::Push(vec![0x01]),
        Opcode::Push(vec![0x01]),
        Opcode::Push(vec![0x01]),
        Opcode::Push(vec![0x01]),
        Opcode::Push(vec![0x01]),
        Opcode::Push(vec![0x01]), // op 6 ; exceeds limit of 5
        Opcode::Push(vec![0x01]),
    ];
    let result = eng.execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::OpCountExceeded { max: 5 }));
}

#[test]
fn ops_at_exactly_limit_succeeds() {
    // Script with exactly max_ops operations (including final push of result)
    let eng = limited_engine(3, 100);
    // 3 ops that leave truthy on stack:
    let script = vec![
        Opcode::Push(vec![0x01]),
        Opcode::Drop, // op 2
        Opcode::Push(vec![0x01]), // op 3 ; exactly at limit
    ];
    let result = eng.execute(&script, &[], &ctx(0));
    assert!(result.valid, "{:?}", result.error);
}

// -- Stack depth limit ---------------------------------------------------------

#[test]
fn max_stack_depth_enforced() {
    // Try to push 101 items with default limits (max 100)
    let eng = limited_engine(10000, 5); // max stack depth = 5
    let script: Vec<Opcode> = (0..6)
        .map(|_| Opcode::Push(vec![0x01]))
        .collect();
    // item 6 exceeds stack depth of 5
    let result = eng.execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::StackDepthExceeded { max: 5 }));
}

#[test]
fn stack_depth_at_exactly_limit_succeeds() {
    let eng = limited_engine(10000, 3); // max stack = 3
    let script = vec![
        Opcode::Push(vec![0x01]),
        Opcode::Push(vec![0x02]),
        Opcode::Push(vec![0x01]), // 3rd push ; at limit, should succeed
    ];
    let result = eng.execute(&script, &[], &ctx(0));
    assert!(result.valid, "{:?}", result.error);
}

#[test]
fn witness_items_count_toward_stack_depth() {
    let eng = limited_engine(10000, 2); // max stack = 2
    let script = vec![Opcode::Push(vec![0x01])]; // 1 more push
    let witness = vec![vec![0x01], vec![0x02]]; // 2 witness items fill stack
    // Pushing the third item (from script) should fail
    let result = eng.execute(&script, &witness, &ctx(0));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::StackDepthExceeded { max: 2 }));
}

// -- Empty script / edge cases -------------------------------------------------

#[test]
fn empty_script_with_no_witness_fails() {
    let result = stub_engine().execute(&[], &[], &ctx(0));
    assert!(!result.valid);
    // Empty stack at end -> VerifyFailed
    assert_eq!(result.error, Some(ScriptError::VerifyFailed));
}

#[test]
fn script_leaving_falsy_on_stack_fails() {
    let script = vec![Opcode::Push(vec![0x00])];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::VerifyFailed));
}

#[test]
fn script_leaving_truthy_on_stack_succeeds() {
    let script = vec![Opcode::Push(vec![0x01])];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(result.valid);
}

// -- Control flow --------------------------------------------------------------

#[test]
fn unmatched_if_fails_at_parse() {
    let script = vec![
        Opcode::Push(vec![0x01]),
        Opcode::If,
        Opcode::Push(vec![0x01]),
        // Missing EndIf
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::UnmatchedControlFlow));
}

#[test]
fn unmatched_endif_fails_at_parse() {
    let script = vec![
        Opcode::Push(vec![0x01]),
        Opcode::EndIf, // no matching If
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert_eq!(result.error, Some(ScriptError::UnmatchedControlFlow));
}

#[test]
fn nested_if_works() {
    // Nested if/else/endif
    let script = vec![
        Opcode::Push(vec![0x01]), // truthy
        Opcode::If,
            Opcode::Push(vec![0x01]), // truthy
            Opcode::If,
                Opcode::Push(vec![0x01]),
            Opcode::Else,
                Opcode::Push(vec![0x00]),
            Opcode::EndIf,
        Opcode::Else,
            Opcode::Push(vec![0x00]),
        Opcode::EndIf,
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(result.valid, "{:?}", result.error);
}

#[test]
fn pick_out_of_range_fails() {
    let script = vec![
        Opcode::Push(vec![0x01]),
        Opcode::Pick(5), // only 1 item on stack
    ];
    let result = stub_engine().execute(&script, &[], &ctx(0));
    assert!(!result.valid);
    assert!(matches!(result.error, Some(ScriptError::PickOutOfRange { .. })));
}
