# TSOP -- Smart Contract Operations Protocol for Bitcoin

**Write Bitcoin smart contracts in TypeScript, Go, Rust, Solidity, or Move. Compile to Bitcoin Script.**

<!-- Badges -->
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![npm version](https://img.shields.io/badge/npm-v0.1.0-orange)

---

## Write Once, Compile Anywhere

TSOP lets you write Bitcoin SV smart contracts in the language you already know. All formats compile through the same pipeline and produce identical Bitcoin Script.

<table>
<tr>
<td>

**TypeScript**
```typescript
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```
</td>
<td>

**Go**
```go
type P2PKH struct {
    tsop.SmartContract
    PubKeyHash tsop.Addr `tsop:"readonly"`
}

func (c *P2PKH) Unlock(sig tsop.Sig, pubKey tsop.PubKey) {
    tsop.Assert(tsop.Hash160(pubKey) == c.PubKeyHash)
    tsop.Assert(tsop.CheckSig(sig, pubKey))
}
```
</td>
</tr>
<tr>
<td>

**Rust**
```rust
#[tsop::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[tsop::methods(P2PKH)]
impl P2PKH {
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
```
</td>
<td>

**Solidity-like**
```solidity
pragma tsop ^0.1.0;

contract P2PKH is SmartContract {
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
```
</td>
</tr>
</table>

All four produce the same Bitcoin Script: `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`

---

## Why TSOP?

Bitcoin Script development today forces a choice between hand-writing opcodes (error-prone, unauditable) or adopting a framework with heavy decorator-based DSLs that obscure what happens on-chain. TSOP takes a different path:

- **No decorators** — uses native language keywords (`readonly`, `public`, `immutable`, `#[readonly]`)
- **Write in your language** — TypeScript, Go, Rust, Solidity-like, or Move-style
- **Test natively** — `vitest` for TS, `go test` for Go, `cargo test` for Rust
- **Three compilers** — TypeScript (reference), Go, Rust — all produce byte-identical output
- **Post-quantum ready** — WOTS+ and SLH-DSA (FIPS 205) signature verification in Bitcoin Script
- **Nanopass architecture** — 6 small passes, each auditable in a single sitting
- **Full IDE support** — type checking, autocompletion, go-to-definition in every language

---

## Quick Start

### TypeScript

```bash
pnpm add tsop-lang tsop-compiler tsop-cli
tsop compile MyContract.tsop.ts    # => artifacts/MyContract.json
```

### Go

```bash
# In your go.mod, add: require tsop v0.0.0
# Contracts are real Go — test with go test, compile with the TSOP Go compiler
go test ./...
```

### Rust

```bash
# In Cargo.toml: tsop = { path = "..." }
# Contracts are real Rust — test with cargo test, compile with the TSOP Rust compiler
cargo test
```

---

## Test Your Contracts

Every contract format has native testing support. Business logic tests run the contract as real code in the host language. TSOP compile checks verify the contract will produce valid Bitcoin Script.

**TypeScript** (vitest):
```typescript
import { TestContract } from 'tsop-testing';

const counter = TestContract.fromSource(source, { count: 0n });
counter.call('increment');
expect(counter.state.count).toBe(1n);
```

**Go** (go test):
```go
func TestCounter_Increment(t *testing.T) {
    c := &Counter{Count: 0}
    c.Increment()
    if c.Count != 1 { t.Errorf("expected 1, got %d", c.Count) }
}

func TestCounter_Compile(t *testing.T) {
    if err := tsop.CompileCheck("Counter.tsop.go"); err != nil {
        t.Fatalf("TSOP compile check failed: %v", err)
    }
}
```

**Rust** (cargo test):
```rust
#[path = "Counter.tsop.rs"]
mod contract;
use contract::*;

#[test]
fn test_increment() {
    let mut c = Counter { count: 0 };
    c.increment();
    assert_eq!(c.count, 1);
}

#[test]
fn test_compile() {
    tsop::compile_check(include_str!("Counter.tsop.rs"), "Counter.tsop.rs").unwrap();
}
```

---

## Supported Formats

| Format | Extension | Compilers | IDE Support | Status |
|--------|-----------|-----------|-------------|--------|
| TypeScript | `.tsop.ts` | TS, Go, Rust | Full (`tsc`) | **Stable** |
| Go | `.tsop.go` | Go | Full (`gopls`) | Experimental |
| Rust DSL | `.tsop.rs` | Rust | Full (`rust-analyzer`) | Experimental |
| Solidity-like | `.tsop.sol` | TS, Go, Rust | Syntax highlighting | Experimental |
| Move-style | `.tsop.move` | TS, Go, Rust | Syntax highlighting | Experimental |

All formats parse into the same `ContractNode` AST. From there, the pipeline is identical:

```
  .tsop.ts ──┐
  .tsop.sol ──┤
  .tsop.move ─┼──► ContractNode AST ──► Validate ──► TypeCheck ──► ANF ──► Stack ──► Bitcoin Script
  .tsop.go ───┤
  .tsop.rs ───┘
```

---

## Example Contracts

8 example contracts demonstrate all major patterns, each available in all supported formats:

| Contract | Pattern | Stateful | Multi-method |
|----------|---------|----------|-------------|
| [P2PKH](examples/ts/p2pkh/) | Pay-to-Public-Key-Hash | No | No |
| [Escrow](examples/ts/escrow/) | Multi-party authorization | No | Yes (4 paths) |
| [Counter](examples/ts/stateful-counter/) | Stateful state machine | Yes | Yes |
| [Auction](examples/ts/auction/) | Bidding with deadline | Yes | Yes |
| [CovenantVault](examples/ts/covenant-vault/) | Spending constraints | No | No |
| [OraclePriceFeed](examples/ts/oracle-price/) | Rabin signature oracle | No | No |
| [FungibleToken](examples/ts/token-ft/) | Token with split/merge | Yes | Yes (3 paths) |
| [SimpleNFT](examples/ts/token-nft/) | NFT with transfer/burn | Yes | Yes |
| [PostQuantumWallet](examples/ts/post-quantum-wallet/) | WOTS+ signature verification | No | No |
| [SPHINCSWallet](examples/ts/sphincs-wallet/) | SLH-DSA (FIPS 205) verification | No | No |

Each contract has tests in TypeScript, Go, Rust, Solidity, and Move:
```
examples/
  ts/p2pkh/          P2PKH.tsop.ts + P2PKH.test.ts
  go/p2pkh/          P2PKH.tsop.go + P2PKH_test.go
  rust/p2pkh/        P2PKH.tsop.rs + P2PKH_test.rs
  sol/p2pkh/         P2PKH.tsop.sol + P2PKH.test.ts
  move/p2pkh/        P2PKH.tsop.move + P2PKH.test.ts
```

---

## Architecture

### Compilation Pipeline

The compiler is structured as six small, composable nanopass transforms. Each pass does one thing, transforms one IR into the next, and is small enough to audit in a single sitting.

| Pass | Name | Input | Output |
|------|------|-------|--------|
| 1 | **Parse** | Source (any format) | TSOP AST |
| 2 | **Validate** | TSOP AST | Validated AST |
| 3 | **Type-check** | Validated AST | Typed AST |
| 4 | **ANF Lower** | Typed AST | ANF IR |
| 5 | **Stack Lower** | ANF IR | Stack IR |
| 6 | **Emit** | Stack IR | Bitcoin Script |

The optimizer (constant folding + dead binding elimination) runs between passes 4 and 5.

### Multi-Compiler Strategy

TSOP defines a **canonical IR conformance boundary** at the ANF level. Any compiler that produces byte-identical ANF IR for a given source file is conformant:

- The **TypeScript compiler** is the reference implementation
- The **Go compiler** produces identical output for all example contracts including post-quantum
- The **Rust compiler** produces identical output for all example contracts including post-quantum

The conformance suite in `conformance/` contains 9 golden-file tests (including WOTS+ and SLH-DSA). All three compilers must pass the same suite.

### Contract Model

- `SmartContract` — stateless, all properties `readonly`
- `StatefulSmartContract` — mutable state carried across transactions via OP_PUSH_TX
- `this.addOutput(satoshis, ...values)` — multi-output intrinsic for token splitting/merging
- Only TSOP built-in functions are allowed — the compiler rejects arbitrary function calls

### Language Subset

Only a strict subset of each language is valid TSOP. The compiler enforces this at parse, validate, and typecheck time:

**Allowed:** Class/struct declarations, readonly/mutable properties, public/private methods, const/let variables, if/else, bounded for loops, arithmetic/comparison/logical/bitwise operators, ternary expressions, TSOP built-in function calls.

**Disallowed:** Unbounded loops, recursion, async/await, closures, exceptions, dynamic arrays, arbitrary function calls (`Math.floor`, `console.log`, etc.).

---

## Project Structure

```
packages/
  tsop-lang/          # Language types and builtins (developer imports)
  tsop-compiler/      # TypeScript compiler (6 nanopass passes)
  tsop-ir-schema/     # Shared IR type definitions and JSON schemas
  tsop-testing/       # TestContract API, Script VM, interpreter
  tsop-sdk/           # Deployment SDK (providers, signers)
  tsop-cli/           # CLI tool
  tsop-go/            # Go mock package (types, mock crypto, CompileCheck)
  tsop-rs/            # Rust mock crate (prelude types, compile_check)
  tsop-rs-macros/     # Rust proc-macros (#[tsop::contract], #[public], etc.)
compilers/
  go/                 # Go compiler (tree-sitter + native Go frontend)
  rust/               # Rust compiler (SWC + native Rust frontend)
conformance/          # Cross-compiler conformance test suite
examples/
  ts/                 # TypeScript contracts + tests
  go/                 # Go contracts + tests
  rust/               # Rust contracts + tests
  sol/                # Solidity-like contracts + tests
  move/               # Move-style contracts + tests
spec/                 # Language specification
docs/                 # Documentation + format guides
```

---

## Development

### Prerequisites

- **Node.js** >= 20, **pnpm** 9.15+
- **Go** 1.26+ (for Go compiler and Go contract tests)
- **Rust** 1.75+ (for Rust compiler and Rust contract tests)

### Build & Test

```bash
git clone https://github.com/icellan/tsop.git && cd tsop
pnpm install && pnpm build

# TypeScript (packages + all format examples)
npx vitest run

# Go compiler + Go contract tests
cd compilers/go && go test ./...
cd examples/go && go test ./...

# Rust compiler + Rust contract tests
cd compilers/rust && cargo test
cd examples/rust && cargo test
```

---

## Academic Foundations

| Technique | Reference | Used In |
|-----------|-----------|---------|
| Nanopass compilation | Sarkar, Waddell & Dybvig (ICFP 2004) | 6-pass pipeline architecture |
| Administrative Normal Form | Flanagan, Sabry, Duba & Felleisen (PLDI 1993) | IR between typed AST and stack machine |
| Affine types | Walker (2005), Move language (2019) | Compile-time resource safety |
| Definitional interpreter | Reynolds (1972), Amin & Rompf (POPL 2017) | Reference interpreter oracle |
| Differential testing | Yang, Chen, Eide & Regehr (PLDI 2011, CSmith) | Cross-compiler fuzzing |
| Stack scheduling | Koopman (1989) | ANF → Bitcoin Script stack mapping |

---

## License

MIT
