# Compiler Bugs — Example Contract Compilation Report

Compiled all 165 example contracts across 8 languages. 138 passed, 27 failed.

## Rust Parser

### Private method return types ignored

**Contracts:** `rust/function-patterns/FunctionPatterns.runar.rs`

Private methods with explicit `-> Bigint` return type annotations are treated as returning `void`. The Rust parser (`01-parse-rust.ts`) does not extract the return type from the `-> Type` syntax on non-`#[public]` methods.

```rust
// This return type is ignored by the parser:
fn scale_value(&self, value: Bigint, numerator: Bigint, denominator: Bigint) -> Bigint {
    mul_div(value, numerator, denominator)
}
```

Results in:
- `Right operand of '+' must be bigint, got 'void'`
- `Type 'void' is not assignable to type 'bigint'`

### Explicit txPreimage property rejected

**Contracts:** `rust/auction/Auction.runar.rs`, `rust/tic-tac-toe/TicTacToe.runar.rs`, `rust/token-ft/FungibleTokenExample.runar.rs`

These contracts explicitly declare `txPreimage: SigHashPreimage` as a struct field, which the validator rejects because `txPreimage` is an implicit property of `StatefulSmartContract`. The Rust contracts should either omit this field (relying on the compiler to inject it) or the validator should silently ignore it.

```
'txPreimage' is an implicit property of StatefulSmartContract and must not be declared
```

## Python Parser

### Majority of contracts fail to parse (19 out of 22)

Most Python contracts fail with `Expected class declaration` at L1 or type-related errors. This suggests the Python parser expects a different import/class structure than what the example contracts use.

**"Expected class declaration" (12 contracts):** blake3, convergence-proof, covenant-vault, ec-demo, math-demo, post-quantum-wallet, schnorr-zkp, sha256-compress, sha256-finalize, sphincs-wallet, python-specific formatting

**"Constructor must call super()" (7 contracts):** escrow, oracle-price, p2blake3pkh, p2pkh, token-ft, token-nft, message-board — the parser likely doesn't recognize the Python `super().__init__()` pattern.

**"Unsupported type ''" (3 contracts):** auction, message-board, stateful-counter — property type annotations are not being extracted.

**"Unexpected token 'in'" (1 contract):** function-patterns — Python's `in` keyword in expressions is not supported by the parser.

## Move Parser

### Missing builtin: assertCorrectPlayer

**Contract:** `move/tic-tac-toe/TicTacToe.runar.move`

The TicTacToe contract calls `assertCorrectPlayer()` as a standalone function, but the compiler doesn't recognize it as a builtin. This is likely a contract issue (should be `self.assert_correct_player()` or similar method call).

## Go Parser

### Missing builtin: isPositive

**Contract:** `go/function-patterns/FunctionPatterns.runar.go`

The contract calls `isPositive()` which is not a Rúnar builtin. This is a contract issue — `isPositive` should be a private method, not a standalone function call.

## Ruby Parser

### Missing type annotations on private method parameters

**Contract:** `ruby/tic-tac-toe/TicTacToe.runar.rb`

All private helper method parameters lack type annotations. The Ruby parser requires explicit type annotations on all parameters.

```
Parameter 'player' in method 'assertCorrectPlayer' must have a type annotation
```

## Summary

| Language | Total | Pass | Fail | Notes |
|----------|-------|------|------|-------|
| TypeScript | 22 | 22 | 0 | All pass |
| Solidity | 17 | 17 | 0 | All pass |
| Move | 17 | 16 | 1 | TicTacToe builtin issue |
| Go | 22 | 21 | 1 | FunctionPatterns builtin issue |
| Rust | 22 | 18 | 4 | Return types + txPreimage |
| Python | 22 | 3 | 19 | Parser issues |
| Zig | 22 | 22 | 0 | All pass |
| Ruby | 21 | 19 | 2 | TicTacToe type annotations |
