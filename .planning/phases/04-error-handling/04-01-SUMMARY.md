# Phase 4 Plan 1: Replace Panics with Graceful Error Returns in Codegen

**One-liner:** catch_unwind/defer-recover/try-except safety nets in all three compiler codegen pipelines

## What Was Done

### Go Compiler (`compilers/go/codegen/stack.go`)
- **Already handled.** `LowerToStack` at line 3434 already has a `defer/recover` block that catches all panics from the codegen pipeline (stack.go, ec.go, sha256.go, blake3.go, slh_dsa.go) and converts them to `error` returns.
- No changes needed.
- Verified: ~35 `panic()` calls across the Go codegen files are all called within the `LowerToStack` call tree and caught by the existing safety net.

### Rust Compiler (`compilers/rust/src/codegen/stack.rs`)
- **Added `std::panic::catch_unwind` wrapper** around the `lower_to_stack` function.
- Extracted inner logic to `lower_to_stack_inner`.
- The wrapper catches any panics from:
  - `stack.rs` (6 production panics: value not found, unknown operators, unsupported types, etc.)
  - `ec.rs` (1 panic in `ECTracker::find_depth`)
  - `slh_dsa.rs` (2 panics: unknown params, `SLHTracker::find_depth`)
- Panics are converted to `Err(format!("stack lowering: {}", msg))`.
- Test-only panics in `optimizer.rs` (line 709) and `stack.rs` (lines 4245, 4818, 4827) were left unchanged -- they are in `#[test]` functions and serve as test assertions.

### Python Compiler (`compilers/python/runar_compiler/codegen/stack.py`)
- **Added try/except wrapper** around the `lower_to_stack` function.
- Extracted inner logic to `_lower_to_stack_inner`.
- `RuntimeError` exceptions (already used throughout the Python codegen) are re-raised as-is since their messages are already descriptive.
- Other unexpected exceptions are caught and wrapped with `RuntimeError(f"stack lowering: {e}")`.

## Panic/Error Analysis

### Categorization of Panics

**Must convert (user-facing conditions) -- all covered by safety nets:**
- Stack underflow (stack.go:138, stack.rs:638, stack.py:155)
- Invalid stack depth (stack.go:168/178/186)
- Unknown binary/unary operators (stack.go:912/931, stack.rs:986/1010)
- Value not found on stack (stack.go:617, stack.rs:638)
- Unsupported types in deserialize_state (stack.go:1953, stack.rs:2365)
- Argument count mismatches (~15 places in stack.go)
- Invalid hex strings (stack.go:3619)
- Unknown EC builtins (stack.go:3964, stack.rs:3580)
- Unknown SLH-DSA params (slh_dsa.go:1230, slh_dsa.rs:102)
- Tracker find_depth failures (ec.go:70, ec.rs:75, slh_dsa.go:272, slh_dsa.rs:300)

**Can keep (internal invariants / test code):**
- SHA-256 codegen assertDepth (sha256.go:125) -- internal invariant check during code generation
- BLAKE3 codegen assertDepth (blake3.go:147) -- same pattern
- Test-only panics in Rust optimizer.rs and stack.rs test functions

## Deviations from Plan

None -- plan executed exactly as written.

## Verification

- `cd compilers/go && go test ./...` -- all pass (cached, no changes)
- `cd compilers/rust && cargo test` -- 64 tests pass
- `cd compilers/python && python3 -m pytest tests/` -- 463 tests pass

## Commits

| Commit | Description | Files |
|--------|-------------|-------|
| 2061ccd | fix: replace panics with graceful error returns in Rust/Python codegen | stack.rs, stack.py |

## Key Files

- `/Users/siggioskarsson/gitcheckout/runar/compilers/rust/src/codegen/stack.rs` -- Added `catch_unwind` wrapper
- `/Users/siggioskarsson/gitcheckout/runar/compilers/python/runar_compiler/codegen/stack.py` -- Added try/except wrapper
- `/Users/siggioskarsson/gitcheckout/runar/compilers/go/codegen/stack.go` -- Already had defer/recover (no changes)
