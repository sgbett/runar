# Compiler Stack Lowering Divergence Bug

## Summary

The Python and Ruby compilers produce different Bitcoin Script than the TS reference compiler for contracts using complex builtins (`bbFieldMul`, `merkleRootSha256`, `hash256+cat` patterns). The scripts are structurally valid but have extra `OP_ROLL` operations, making them 2+ bytes longer and causing on-chain verification failures.

The Zig compiler has a separate issue: it fails to parse the `StateCovenant` contract entirely (`error.ParseFailed`).

## Affected Tests

Conformance suite (32 total, 4 failing):

| Test | Python | Ruby | Zig | Go |
|------|--------|------|-----|-----|
| babybear | script mismatch | script mismatch | IR mismatch | compile failure |
| merkle-proof | OK | OK | OK | compile failure |
| state-covenant | script mismatch | script mismatch | OK | compile failure |
| stateful-bytestring | OK | OK | OK | script mismatch |

Integration tests failing due to these compiler bugs:
- `integration/python/test_babybear.py` — 3 failures (bbFieldAdd, bbFieldAdd_wrap_around, bbFieldInv_identity)
- `integration/python/test_state_covenant.py` — 3 failures (advance_state, chain_advances, invalid_block_number_rejected)
- `integration/zig/src/state_covenant_test.zig` — ParseFailed, test binary crash

## Root Cause: Python/Ruby Stack Lowering

The Python and Ruby compilers emit 2 extra `OP_ROLL` operations before `OP_MUL` in the `bbFieldMul` builtin, compared to the TS reference. This causes a 2-byte script size difference (e.g., 392 bytes vs 390 bytes for StateCovenant).

### Exact Divergence Point

For the `StateCovenant` contract's `advanceState` method, at opcode index 90 in the emitted script:

```
TS (correct, 390 bytes):
  [87] OP_ROLL          ← bring arg to top
  [88] OP_11
  [89] OP_ROLL          ← bring arg to top
  [90] OP_MUL           ← bbFieldMul multiplication
  [91] PUSH_4 01000078  ← BB prime constant
  [92] OP_MOD           ← modular reduction

Python (wrong, 392 bytes):
  [87] OP_ROLL          ← bring arg to top
  [88] OP_11
  [89] OP_ROLL          ← bring arg to top
  [90] OP_ROLL          ← EXTRA: unnecessary roll
  [91] OP_ROLL          ← EXTRA: unnecessary roll
  [92] OP_MUL           ← bbFieldMul multiplication (2 ops later)
  [93] PUSH_4 01000078
  [94] OP_MOD
```

### Why It Happens

The `_lower_bb_builtin` function in all compilers does:
```python
for arg in args:
    self.bring_to_top(arg, is_last_use)
for _ in args:
    self.sm.pop()
dispatch_bb_builtin(func_name, emit_fn)
```

The `bring_to_top` calls are identical between TS and Python. The `dispatch_bb_builtin` codegen is identical. The `collect_refs` and `compute_last_uses` functions are identical.

The difference is in the **stack state** at the point of the `bbFieldMul` call. The Python compiler's stack map has the operands at different depths than the TS compiler, causing `bring_to_top` to emit extra ROLL ops.

### Where to Investigate

The stack state diverges somewhere BEFORE the `bbFieldMul` call, in the lowering of earlier bindings in the `advanceState` method. The ANF IR is the same (both compilers parse the same source), so the divergence is in:

1. **`_lower_call` or `_lower_bin_op`** for earlier bindings — a different stack arrangement choice
2. **`bring_to_top` depth calculation** — the stack map (`self.sm`) tracking might be off by 1 or 2 items for some operations
3. **The peephole optimizer** — the TS optimizer (543 lines) has more rules than the Python one (255 lines) and may be eliminating redundant ops that the Python optimizer leaves in

### Files to Compare

For each divergence, compare these files between TS and Python:

- Stack lowering: `packages/runar-compiler/src/passes/05-stack-lower.ts` vs `compilers/python/runar_compiler/codegen/stack.py`
- Peephole optimizer: `packages/runar-compiler/src/optimizer/peephole.ts` vs `compilers/python/runar_compiler/codegen/optimizer.py`
- BB codegen: `packages/runar-compiler/src/passes/bb-codegen.ts` vs `compilers/python/runar_compiler/codegen/babybear.py`

Same comparison needed for Ruby:
- `compilers/ruby/lib/runar_compiler/codegen/stack.rb` vs TS
- `compilers/ruby/lib/runar_compiler/codegen/optimizer.rb` vs TS

## Root Cause: Zig Parser Failure

The Zig compiler fails to parse `StateCovenant.runar.ts` with `error.ParseFailed`. This is a separate issue from the stack lowering bug. The Zig parser at `compilers/zig/src/frontend/` likely doesn't handle some syntax pattern used by StateCovenant (possibly multi-line constructor parameters or the combination of `hash256(cat(...))` expressions).

## Root Cause: Go Compiler Failures

The Go compiler fails to compile `babybear`, `merkle-proof`, and `state-covenant` conformance tests. These are separate compilation failures (likely missing builtin support or parser issues in the Go frontend), not stack lowering divergences.

## Debugging Approach

1. **Add a Stack IR dump mode** to the Python compiler: print the stack map state before and after each `_lower_binding` call in the `advanceState` method. Compare with TS by adding the same dump mode there.

2. **Binary search the divergence**: The ANF IR has ~25 bindings for `advanceState`. The stack state diverges somewhere between binding 0 and binding 15 (where `bbFieldMul` is). Dump the stack map after each binding in both compilers to find the exact binding where the stack state first differs.

3. **Fix the stack lowerer**: Once the divergent binding is identified, compare the `_lower_*` function for that ANF value kind between TS and Python to find the logic difference.

4. **Alternatively, fix the peephole optimizer**: If the stack lowerer is correct but the Python peephole optimizer is missing rules that the TS optimizer has, port those rules. The TS peephole at `packages/runar-compiler/src/optimizer/peephole.ts` has 543 lines vs Python's 255 lines.

## How to Verify

```bash
# Run conformance suite (should show 0 failures)
cd conformance && npx tsx runner/index.ts --tests-dir tests

# Run Python integration tests
cd integration/python && PYTHONPATH=../../compilers/python:../../packages/runar-py .venv/bin/pytest -v

# Run Zig integration tests
cd integration/zig && zig build test
```

## What's Already Fixed

- `constructorSlots.paramIndex` bug — fixed in all 6 compilers (property declaration index → constructor param index)
- ANF interpreter readonly field lookup — fixed in all 6 SDKs (name-based constructor param lookup)
- NULLFAIL in Go integration tests — fixed (float64 satoshi truncation in `sdk_provider.go`)
- `codeSepIndexSlots` missing from Go integration helper — fixed
- `ByteString` state serialization in Rust/Python SDKs — fixed (push-data encoding)
