"""
Smoke test for the xmr-wow sharechain agent.

Asserts:
1. The module imports without syntax errors (via ast.parse, not runtime
   import: the base_agent import chain requires monerosim PYTHONPATH).
2. The XmrWowSharechainAgent class is defined.
3. _run_cli contains "--proof-harness".
4. _coord_args returns --transport sharechain --node-url form
   (not old --coord-* flags).
5. init-bob path uses --swap-id.
6. COORD_FILE constant is present on the class.
"""

from __future__ import annotations

import ast
from pathlib import Path


AGENT_PATH = Path(__file__).resolve().parents[1] / "xmr_wow_sharechain_agent.py"


def _agent_source() -> str:
    return AGENT_PATH.read_text(encoding="utf-8")


def test_agent_parses():
    src = _agent_source()
    ast.parse(src)


def test_agent_class_defined():
    tree = ast.parse(_agent_source())
    class_names = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
    }
    assert "XmrWowSharechainAgent" in class_names, (
        f"XmrWowSharechainAgent class missing; found: {sorted(class_names)}"
    )


def test_run_cli_has_proof_harness():
    src = _agent_source()
    assert '"--proof-harness"' in src, (
        "--proof-harness flag must be passed by _run_cli"
    )


def test_coord_args_uses_transport_sharechain():
    src = _agent_source()
    assert '"--transport"' in src and '"sharechain"' in src, (
        "_coord_args must emit --transport sharechain"
    )
    assert '"--node-url"' in src, "--node-url required"
    assert '"--coord-node"' not in src, "Old --coord-node flag must be removed"
    assert '"--coord-topic"' not in src, "Old --coord-topic flag must be removed"


def test_init_bob_passes_swap_id():
    src = _agent_source()
    assert '"--swap-id"' in src, (
        "init-bob requires --swap-id from COORD_FILE handoff"
    )


def test_coord_file_constant_present():
    tree = ast.parse(_agent_source())
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "XmrWowSharechainAgent":
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name) and target.id == "COORD_FILE":
                            return
    raise AssertionError("COORD_FILE class constant missing on XmrWowSharechainAgent")


def test_orchestration_helpers_preserved():
    """Regression guard: orchestration helpers must survive the port."""
    src = _agent_source()
    for helper in ("_start_wow_runtime", "_lock_wow_with_retry", "_run_cli"):
        assert helper in src, f"old-agent helper {helper} missing from ported file"
