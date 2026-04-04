# Rúnar Gap Fix Plan

Generated: 2026-04-04 (updated after fixes applied)
Based on: LANGUAGE-GAP-REPORT.md (2026-04-04 revision)

## Fix Strategy

All 6 compilers pass 28/28 conformance tests using `.runar.ts` input. Multi-format conformance improved from 102/224 pass (46%) to **161/224 pass (72%)** after fixes applied in this session. All compiler test suites and example tests pass (2,636 TS tests, 556 Go, 567 Rust, 650 Python, 144 Ruby, 458 Zig — zero failures).

**Fixes already applied:**
- Ruby OpenStruct compatibility (test_compiler.rb)
- Go/Rust type checker `this.addOutput` via MemberExpr path
- Python `txPreimage` skip in Rust-format parser
- Go/TS Move parser `&mut` method signature detection
- TS build fixes (analyzer unused vars)

**Remaining 62 multi-format failures** are concentrated in:
1. `.runar.zig` format IR structural differences (~15 failures)
2. `.runar.move` format stateful contract IR mismatches (~10 failures)
3. `.runar.sol` format IR differences on complex contracts (~8 failures)
4. token-ft/token-nft complex stateful contracts across formats (~12 failures)
5. Missing example contracts (Sol: 2, Move: 1)

## Trivial Compatibility Fixes (do these first)

### Fix RUBY-0: Fix Ruby 4.0 OpenStruct compatibility

- **Gap report reference**: Ruby §Known Issues (NEW), Cross-Cutting Issues §2
- **What**: `test_compiler.rb:51` uses `OpenStruct` which Ruby 4.0 no longer auto-loads. Add `require 'ostruct'` at the top of the test file.
- **Files to modify**:
  - `compilers/ruby/test/test_compiler.rb`: Add `require 'ostruct'` after line 1 (after other requires)
- **Dependencies**: None
- **Scope**: trivial (< 15 minutes)
- **Acceptance criteria**: `cd compilers/ruby && rake test` passes with 0 errors
- **Verification command**: `cd compilers/ruby && rake test`

### Fix PY-0: Add missing `.runar.zig` dispatch to Python compiler

- **Gap report reference**: Cross-Cutting Issues §1 (Python compiler fails on .runar.zig)
- **What**: `compilers/python/runar_compiler/compiler.py:128` falls through to `raise ValueError` before reaching `.runar.zig`. The parser `parser_zig.py` exists and works. The fix is adding the `.runar.zig` `elif` branch to `_parse_source()`.
- **Files to modify**:
  - `compilers/python/runar_compiler/compiler.py`: Add between the last format elif and the else/raise:
    ```python
    elif lower.endswith(".runar.zig"):
        from runar_compiler.frontend.parser_zig import parse_zig
        return parse_zig(source, file_name)
    ```
  - Update the error message to include `.runar.zig` in the list of supported formats
- **Dependencies**: None
- **Scope**: trivial (< 15 minutes)
- **Acceptance criteria**: `python3 -m runar_compiler --source conformance/tests/basic-p2pkh/P2PKH.runar.zig --hex` produces output (from `compilers/python/`)
- **Verification command**: `cd compilers/python && python3 -m runar_compiler --source ../../conformance/tests/basic-p2pkh/P2PKH.runar.zig --hex`

---

## Critical Parser Fixes

### Fix GO-0: Fix Go Sol/Move/Python parser auto-constructor generation

- **Gap report reference**: Cross-Cutting Issues §1 (multi-format conformance failures)
- **What**: Go compiler fails to compile `.runar.sol`, `.runar.move`, and `.runar.py` format contracts because these parsers don't generate auto-constructors with `super()` calls. Error: "constructor must call super() as its first statement; property 'X' must be assigned in the constructor". The Go `.runar.ts` parser generates constructors correctly — port this logic to the other parsers.
- **Files to modify**:
  - `compilers/go/frontend/parser_sol.go`: Add auto-constructor generation. Study how `parser.go` (TS parser) creates the `ConstructorNode` with `super()` call and property assignments, and replicate for Solidity syntax.
  - `compilers/go/frontend/parser_move.go`: Same for Move parser
  - `compilers/go/frontend/parser_python.go`: Same for Python parser
- **Dependencies**: None
- **Scope**: medium (4-16 hours) — requires understanding each parser's AST generation and the TS parser's auto-constructor logic
- **Acceptance criteria**: `cd conformance && npx tsx runner/index.ts --multi-format --filter basic-p2pkh` passes for `.runar.sol`, `.runar.move`, `.runar.py` formats with Go compiler
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format --filter basic-p2pkh`

### Fix RUST-0: Fix Rust Move parser "No struct declaration" failures

- **Gap report reference**: Cross-Cutting Issues §1 (Rust .runar.move parser failures)
- **What**: Rust's Move parser fails on some contracts with "No 'struct' declaration found in module". Investigate `compilers/rust/src/frontend/parser_move.rs` to determine why struct declarations aren't recognized for multi-format conformance contracts.
- **Files to modify**:
  - `compilers/rust/src/frontend/parser_move.rs`: Fix struct declaration parsing
- **Dependencies**: None
- **Scope**: small to medium (1-8 hours) — needs investigation of specific failure cases
- **Acceptance criteria**: `cd conformance && npx tsx runner/index.ts --multi-format --filter token-nft` passes for `.runar.move` with Rust compiler
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format`

### Fix RUST-1: Fix Rust `.runar.rs` format IR/script mismatches

- **Gap report reference**: Cross-Cutting Issues §1 (IR and script mismatch for .runar.rs)
- **What**: 9 contracts compiled from `.runar.rs` format produce different IR and script hex than from `.runar.ts`. The Rust macro parser generates a different AST for equivalent contracts. Diff the IR output between `.runar.ts` and `.runar.rs` for a failing contract (e.g., `auction`) to identify the AST divergence.
- **Files to modify**:
  - `compilers/rust/src/frontend/parser_rustmacro.rs`: Fix AST generation to match TS parser output
- **Dependencies**: None
- **Scope**: medium (4-16 hours) — requires diffing IR output between formats
- **Acceptance criteria**: Multi-format conformance passes for `.runar.rs` format across all 28 test cases
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format`

---

## Infrastructure & Compatibility Fixes

### Fix GO-1: Fix Go conformance sub-package builds on Go 1.26

- **Gap report reference**: Go §Conformance Test Detail (NEW), Cross-Cutting Issues §3
- **What**: 28 conformance sub-packages under `conformance/tests/` fail to build because Go 1.26 treats `.runar.go` files as regular Go source. Error: `package runar is not in std`. The `.runar.go` contract source files contain `import runar "..."` which Go tries to resolve. Options:
  1. Add `//go:build ignore` build tags to `.runar.go` files in conformance directories
  2. Rename conformance contract files to use a different extension that Go ignores
  3. Add `.go` exclusion patterns in the conformance Go test infrastructure
- **Files to modify**: Either the 28 `.runar.go` files in `conformance/tests/*/` or the conformance test infrastructure
- **Dependencies**: None
- **Scope**: small (1-4 hours) — needs investigation of best approach
- **Acceptance criteria**: `cd conformance && go test ./... -count=1` builds and runs all sub-packages
- **Verification command**: `cd conformance && go test ./... -count=1 -v 2>&1 | tail -50`

### Fix ZIG-1: Fix 12 memory leaks in Zig test suite

- **Gap report reference**: Zig §Test Infrastructure Issues
- **What**: 12 memory leaks in `zig build test` cause exit code 1 despite all 458 tests passing. All leaks are in test code, not implementation.
- **Root cause**: Test functions in `parse_ruby.zig` allocate token arrays and error arrays without freeing them. `dce.zig` has one additional cleanup leak.
- **Files to modify**:
  - `compilers/zig/src/passes/parse_ruby.zig`: Add `defer` cleanup in test functions at lines 2074-2409. Each test that calls `parseRuby()` needs to clean up allocated arrays.
  - `compilers/zig/src/passes/dce.zig`: Fix resource cleanup in test "eliminateDeadBindings preserves side-effecting bindings"
- **Pattern to apply**:
  ```zig
  // Before:
  const result = parseRuby(allocator, source, "P2PKH.runar.rb");
  // After:
  const result = parseRuby(allocator, source, "P2PKH.runar.rb");
  defer allocator.free(result.errors);
  ```
- **Dependencies**: None
- **Scope**: small (1-4 hours)
- **Acceptance criteria**: `zig build test` passes with 0 leaked allocations and exit code 0
- **Verification command**: `cd compilers/zig && zig build test`

### Fix CC-1: Update conformance runner INPUT_FORMATS for Zig

- **Gap report reference**: Zig §Known Issues, Cross-Cutting Issues §1
- **What**: `conformance/runner/runner.ts:51-60` excludes 'zig' from `.runar.sol`, `.runar.move`, `.runar.py` format lists despite Zig having working parsers for all three (`compilers/zig/src/passes/parse_sol.zig`, `parse_move.zig`, `parse_python.zig`). Add 'zig' to these three format entries.
- **Files to modify**:
  - `conformance/runner/runner.ts`: Lines 51-60, add 'zig' to the `.runar.sol`, `.runar.move`, `.runar.py` entries
- **Dependencies**: Should verify Zig's parsers actually produce correct output first — run a spot check: `cd compilers/zig && zig-out/bin/runar-zig --source ../../conformance/tests/basic-p2pkh/P2PKH.runar.sol --hex`
- **Scope**: trivial (< 30 minutes, including verification)
- **Acceptance criteria**: `cd conformance && npx tsx runner/index.ts --multi-format --filter basic-p2pkh` includes Zig for `.runar.sol`, `.runar.move`, `.runar.py` and passes
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format --filter basic-p2pkh`

### Fix CC-2: Update `conformance/formats.json` AFTER parser fixes

- **Gap report reference**: Cross-Cutting Issues §1
- **What**: After parser bugs are fixed (GO-0, PY-0, RUST-0, RUST-1, CC-1), update `formats.json` to reflect expanded format support.
- **Files to modify**:
  - `conformance/formats.json`: Update each format entry's `compilers` array
- **Dependencies**: GO-0, PY-0, RUST-0, RUST-1, CC-1 (all parser fixes must land first)
- **Scope**: trivial (< 30 minutes)
- **Acceptance criteria**: `npx tsx conformance/runner/index.ts --multi-format` passes with expanded compiler lists
- **Verification command**: `cd conformance && npx tsx runner/index.ts --multi-format`

### Fix CC-3: Clean up outdated/misleading comments

- **Gap report reference**: Go §Known Issues, Ruby §Stub/Placeholder Inventory
- **What**: Two misleading comments:
  1. `compilers/go/frontend/anf_ec_optimizer_test.go:627` — says "Rule 10 is not implemented" but Rule 10 works
  2. `compilers/ruby/lib/runar_compiler/codegen/stack.rb:848` — says "TODO: will be added in Part 2" but implementations are present
- **Files to modify**:
  - `compilers/go/frontend/anf_ec_optimizer_test.go`: Update lines 626-629
  - `compilers/ruby/lib/runar_compiler/codegen/stack.rb`: Update line 848 comment
- **Scope**: trivial (< 15 minutes)
- **Acceptance criteria**: No misleading TODO/not-implemented comments remain
- **Verification command**: `cd compilers/go && go test ./frontend/ -run AddMulGen -v` and `cd compilers/ruby && rake test`

---

## Example & Integration Coverage Fixes

### Fix SOL-1: Add 5 missing Solidity-like example contracts

- **Gap report reference**: Example Contract Integration Coverage Matrix (5 ❌ entries for Sol)
- **What**: Create example contracts and tests for 5 contracts missing from `examples/sol/`.
- **Files to create**:
  - `examples/sol/convergence-proof/ConvergenceProof.runar.sol` — copy from `conformance/tests/convergence-proof/convergence-proof.runar.sol`
  - `examples/sol/convergence-proof/ConvergenceProof.test.ts` — port from `examples/ts/convergence-proof/ConvergenceProof.test.ts` (change source read and pass `.runar.sol` fileName)
  - `examples/sol/function-patterns/FunctionPatterns.runar.sol` + test
  - `examples/sol/post-quantum-wallet/PostQuantumWallet.runar.sol` + test
  - `examples/sol/schnorr-zkp/SchnorrZKP.runar.sol` + test
  - `examples/sol/sphincs-wallet/SPHINCSWallet.runar.sol` + test
- **Dependencies**: None
- **Scope**: small (1-4 hours) — contracts exist in conformance, tests need minor adaptation
- **Acceptance criteria**: `npx vitest run examples/sol/` passes with all contract test suites
- **Verification command**: `npx vitest run examples/sol/`

### Fix MOVE-1: Add 5 missing Move-style example contracts

- **Gap report reference**: Example Contract Integration Coverage Matrix (5 ❌ entries for Move)
- **What**: Same 5 contracts as SOL-1 but for Move format.
- **Files to create**:
  - `examples/move/convergence-proof/ConvergenceProof.runar.move` + test
  - `examples/move/function-patterns/FunctionPatterns.runar.move` + test
  - `examples/move/post-quantum-wallet/PostQuantumWallet.runar.move` + test
  - `examples/move/schnorr-zkp/SchnorrZKP.runar.move` + test
  - `examples/move/sphincs-wallet/SPHINCSWallet.runar.move` + test
- **Dependencies**: None
- **Scope**: small (1-4 hours)
- **Acceptance criteria**: `npx vitest run examples/move/` passes with all contract test suites
- **Verification command**: `npx vitest run examples/move/`

### Fix RUBY-1: Add missing message-board example

- **Gap report reference**: Ruby §Test Gaps, Example Contract Integration Coverage Matrix
- **What**: `examples/ruby/message-board/` does not exist. All other formats have this contract.
- **Files to create**:
  - `examples/ruby/message-board/MessageBoard.runar.rb` — port from `examples/ts/message-board/MessageBoard.runar.ts`
  - `examples/ruby/message-board/message_board_spec.rb` — port from `examples/ts/message-board/MessageBoard.test.ts`
- **Dependencies**: None
- **Scope**: trivial (< 1 hour)
- **Acceptance criteria**: `cd examples/ruby && bundle exec rspec message-board/` passes
- **Verification command**: `cd examples/ruby && bundle exec rspec message-board/message_board_spec.rb`

### Fix ZIG-2: Expand Zig on-chain integration tests

- **Gap report reference**: On-Chain Integration Test Coverage Matrix, Cross-Cutting Issues §5
- **What**: Zig only has 7 integration test contracts vs 16-20 for other languages. Add integration tests for the missing contracts.
- **Files to create** in `integration/zig/src/`:
  - `auction_test.zig` — port from `integration/go/auction_test.go`
  - `convergence_proof_test.zig` — port from `integration/go/convergence_proof_test.go`
  - `covenant_vault_test.zig` — port from `integration/go/covenant_vault_test.go`
  - `ec_isolation_test.zig` — port from `integration/go/ec_isolation_test.go`
  - `fungible_token_test.zig` — port from `integration/go/token_ft_test.go`
  - `nft_test.zig` — port from `integration/go/token_nft_test.go`
  - `oracle_price_test.zig` — port from `integration/go/oracle_price_test.go`
  - `schnorr_zkp_test.zig` — port from `integration/go/schnorr_zkp_test.go`
  - `sphincs_wallet_test.zig` — port from `integration/rust/tests/sphincs_wallet.rs`
  - `tic_tac_toe_test.zig` — port from `integration/go/tic_tac_toe_test.go`
  - `post_quantum_wallet_test.zig` — port from `integration/rust/tests/post_quantum_wallet.rs`
- **Dependencies**: ZIG-1 first (so CI is clean)
- **Scope**: large (16+ hours) — each test requires adapting test harness and contract interaction patterns to Zig
- **Acceptance criteria**: Zig integration test count reaches at least 17 (matching Go/Rust)
- **Verification command**: `cd integration/zig && zig build test`

---

## Summary Statistics

| Language/Area | Total fixes | Trivial | Small | Medium | Large | Unknown |
|---------------|------------|---------|-------|--------|-------|---------|
| Ruby | 2 | 2 | 0 | 0 | 0 | 0 |
| Python | 1 | 1 | 0 | 0 | 0 | 0 |
| Go (parser) | 1 | 0 | 0 | 1 | 0 | 0 |
| Go (infra) | 1 | 0 | 1 | 0 | 0 | 0 |
| Rust (parser) | 2 | 0 | 1 | 1 | 0 | 0 |
| Zig | 2 | 0 | 1 | 0 | 1 | 0 |
| Cross-cutting | 3 | 3 | 0 | 0 | 0 | 0 |
| Solidity-like | 1 | 0 | 1 | 0 | 0 | 0 |
| Move-style | 1 | 0 | 1 | 0 | 0 | 0 |
| **Total** | **14** | **6** | **5** | **2** | **1** | **0** |

## Suggested Execution Order

### Milestone 1: Quick wins — trivial fixes (RUBY-0, PY-0, CC-3)

- **RUBY-0**: Add `require 'ostruct'` to Ruby test file (5 min)
- **PY-0**: Add `.runar.zig` dispatch to Python compiler (5 min)
- **CC-3**: Clean up misleading comments in Go and Ruby (10 min)

After this milestone: Ruby compiler tests pass on Ruby 4.0. Python can compile `.runar.zig` files. No misleading stubs in codebase.

### Milestone 2: Critical cross-format parser fixes (GO-0, RUST-0, RUST-1)

- **GO-0**: Fix Go Sol/Move/Python parser auto-constructors (medium, highest impact)
- **RUST-0**: Fix Rust Move parser struct detection (small to medium)
- **RUST-1**: Fix Rust `.runar.rs` IR/script mismatches (medium)

After this milestone: Multi-format conformance failures drop from ~120 to near-zero.

### Milestone 3: Infrastructure cleanup (GO-1, ZIG-1, CC-1, CC-2)

- **GO-1**: Fix Go conformance sub-package builds on Go 1.26 (small)
- **ZIG-1**: Fix Zig test memory leaks (small)
- **CC-1**: Add Zig to conformance runner format support (trivial)
- **CC-2**: Update `formats.json` after parser fixes land (trivial)

After this milestone: All CI green. `--multi-format` conformance covers all compilers for all formats. Go conformance sub-packages build.

### Milestone 4: Example and integration coverage parity (SOL-1, MOVE-1, RUBY-1, ZIG-2)

- **SOL-1**: Add 5 Sol examples (small)
- **MOVE-1**: Add 5 Move examples (small)
- **RUBY-1**: Add Ruby message-board (trivial)
- **ZIG-2**: Expand Zig integration tests from 7 to 17+ (large)

After this milestone: All formats have equivalent example coverage. All languages have comparable on-chain integration test coverage.
