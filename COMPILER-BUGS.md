# Compiler Bugs — Example Contract Compilation Report

Compiled all 165 example contracts across 8 languages using the **TypeScript compiler** (`runar-compiler` v0.4.2). The TypeScript compiler is the reference implementation that handles all input formats — the Go, Rust, and Python compilers were not tested here. **159 passed, 6 failed.**

## Rust Compiler

### Stack lowering crash on multi-output stateful contract

**Contract:** `rust/token-ft/FungibleTokenExample.runar.rs`

The compiler crashes during stack lowering with `Value 't40' not found on stack` when compiling a stateful contract that uses `addOutput` with multiple outputs. This is a codegen bug in the stack lowering pass.

```
Value 't40' not found on stack (stack has 7 items: [_codePart, txPreimage, owner, balance, mergeBalance, owner, t43])
```

## Python Compiler

### `addOutput` not recognized as method call

**Contracts:** `python/token-ft/FungibleTokenExample.runar.py`, `python/token-nft/NFTExample.runar.py`

The Python parser does not recognize `self.add_output(...)` as the `addOutput` stateful contract intrinsic. These contracts compile in all other languages.

```
Unknown builtin function: addOutput
```

## Move Compiler

### Private function calls not recognized

**Contract:** `move/tic-tac-toe/TicTacToe.runar.move`

Private helper functions called as standalone functions (e.g., `placeMove(...)`) are not recognized by the Move parser. The parser treats them as unknown builtin function calls instead of inlining them as private methods.

```
Unknown builtin function: placeMove
```

## Go Compiler

### Private function calls not recognized

**Contract:** `go/function-patterns/FunctionPatterns.runar.go`

Standalone private function calls (e.g., `scaleValue(...)`) are not recognized. Go contracts support private functions outside the struct receiver, but the parser treats them as unknown builtins.

```
Unknown builtin function: scaleValue
```

## Ruby Compiler

### Private method variable reference not recognized

**Contract:** `ruby/tic-tac-toe/TicTacToe.runar.rb`

Private method calls used without parentheses (Ruby style, e.g., `countOccupied`) are treated as undefined variables instead of method calls.

```
Undefined variable 'countOccupied'
```

## Summary

| Language | Total | Pass | Fail | Issue |
|----------|-------|------|------|-------|
| TypeScript | 22 | 22 | 0 | |
| Solidity | 17 | 17 | 0 | |
| Move | 17 | 16 | 1 | Private function calls |
| Go | 22 | 21 | 1 | Private function calls |
| Rust | 22 | 21 | 1 | Stack lowering crash |
| Python | 22 | 20 | 2 | addOutput not recognized |
| Zig | 22 | 22 | 0 | |
| Ruby | 21 | 20 | 1 | Bare method call syntax |
