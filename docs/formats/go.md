# Go Contract Format

**Status:** Experimental
**File extension:** `.tsop.go`
**Supported compilers:** Go only

---

## Overview

The Go format lets you write TSOP contracts as idiomatic Go code. Contracts are Go structs embedding `tsop.SmartContract` or `tsop.StatefulSmartContract`, with methods defined as receiver functions. The Go compiler parses these directly -- no intermediate conversion to TypeScript.

This format is **only supported by the Go compiler** (`compilers/go`). The TypeScript and Rust compilers cannot parse `.tsop.go` files. If you need cross-compiler portability, use the TypeScript format instead.

---

## Syntax

### Package and Imports

```go
package contracts

import "tsop"
```

The package name is ignored by the compiler. The `"tsop"` import provides the base types and built-in functions.

### Struct Declaration

```go
type P2PKH struct {
    tsop.SmartContract
    PubKeyHash tsop.Addr `tsop:"readonly"`
}
```

- Embed `tsop.SmartContract` or `tsop.StatefulSmartContract` as the first field (anonymous embed).
- Properties are struct fields with `tsop.Type` types.
- The `tsop:"readonly"` struct tag marks immutable properties.
- Fields without the `readonly` tag are mutable (stateful).

### Exported vs. Unexported

Go's visibility rules map to TSOP method visibility:

| Go convention | TSOP visibility |
|--------------|-----------------|
| `func (c *P2PKH) Unlock(...)` (exported) | `public` |
| `func (c *P2PKH) helper(...)` (unexported) | `private` |

Exported methods (capitalized first letter) are spending entry points. Unexported methods are inlined helpers.

### Methods

```go
func (c *P2PKH) Unlock(sig tsop.Sig, pubKey tsop.PubKey) {
    tsop.Assert(tsop.Hash160(pubKey) == c.PubKeyHash)
    tsop.Assert(tsop.CheckSig(sig, pubKey))
}
```

- The receiver is always a pointer to the contract struct (`*P2PKH`).
- The receiver variable name (`c` above) is conventional but any name works.
- Public methods must not return a value.
- Private methods may return a value.

### tsop.Assert

```go
tsop.Assert(condition)
```

Maps to `assert(condition)` in the AST. Fails the script if the condition is false.

### Property Access

```go
c.PubKeyHash       // access a readonly property
c.Count            // access a mutable property
```

Properties are accessed through the receiver variable. The parser strips the receiver prefix and creates `PropertyAccessExpr` nodes.

### State Mutation

```go
c.Count++
c.Count--
c.Count = newValue
c.HighestBidder = bidder
```

Go's `++` and `--` statements and assignment work as expected for mutable properties.

### Variable Declarations

```go
msg := tsop.Num2Bin(price, 8)     // short variable declaration (let)
var msg tsop.ByteString = expr     // explicit type (const if never reassigned)
```

Short variable declarations (`:=`) map to `let` bindings. The compiler infers mutability: if the variable is never reassigned, it is treated as `const`.

### addOutput

```go
c.AddOutput(satoshis, owner, balance)
```

Called as a method on the receiver. Arguments are positional, matching mutable properties in declaration order.

### For Loops

```go
for i := int64(0); i < 10; i++ {
    // body
}
```

The loop bound must be a compile-time constant. The loop is unrolled at compile time.

### If/Else

```go
if amount > threshold {
    // ...
} else if amount == 0 {
    // ...
} else {
    // ...
}
```

### Ternary

Go does not have a ternary operator. Use if/else blocks to achieve the same effect. The compiler may optimize simple if/else patterns to `OP_IF`/`OP_ELSE`/`OP_ENDIF`.

---

## Type Mapping

| Go type | TSOP type |
|---------|-----------|
| `int64` / `tsop.BigInt` | `bigint` |
| `bool` | `boolean` |
| `tsop.ByteString` | `ByteString` |
| `tsop.PubKey` | `PubKey` |
| `tsop.Sig` | `Sig` |
| `tsop.Sha256` | `Sha256` |
| `tsop.Ripemd160` | `Ripemd160` |
| `tsop.Addr` | `Addr` |
| `tsop.SigHashPreimage` | `SigHashPreimage` |
| `tsop.RabinSig` | `RabinSig` |
| `tsop.RabinPubKey` | `RabinPubKey` |

Integer literals are plain Go integers (`0`, `42`, `50000`). The parser treats them as `bigint` values (no `n` suffix needed).

---

## Built-in Functions

Built-in functions are accessed through the `tsop` package with PascalCase names:

| Go function | TSOP built-in |
|------------|---------------|
| `tsop.Assert(cond)` | `assert(cond)` |
| `tsop.CheckSig(sig, pk)` | `checkSig(sig, pk)` |
| `tsop.CheckMultiSig(sigs, pks)` | `checkMultiSig(sigs, pks)` |
| `tsop.Hash256(data)` | `hash256(data)` |
| `tsop.Hash160(data)` | `hash160(data)` |
| `tsop.Sha256(data)` | `sha256(data)` |
| `tsop.Ripemd160(data)` | `ripemd160(data)` |
| `tsop.Len(data)` | `len(data)` |
| `tsop.Num2Bin(n, size)` | `num2bin(n, size)` |
| `tsop.Pack(n)` | `pack(n)` |
| `tsop.Unpack(data)` | `unpack(data)` |
| `tsop.Abs(n)` | `abs(n)` |
| `tsop.Min(a, b)` | `min(a, b)` |
| `tsop.Max(a, b)` | `max(a, b)` |
| `tsop.Within(x, lo, hi)` | `within(x, lo, hi)` |
| `tsop.Safediv(a, b)` | `safediv(a, b)` |
| `tsop.Safemod(a, b)` | `safemod(a, b)` |
| `tsop.Clamp(val, lo, hi)` | `clamp(val, lo, hi)` |
| `tsop.Sign(n)` | `sign(n)` |
| `tsop.Pow(base, exp)` | `pow(base, exp)` |
| `tsop.MulDiv(a, b, c)` | `mulDiv(a, b, c)` |
| `tsop.PercentOf(amount, bps)` | `percentOf(amount, bps)` |
| `tsop.Sqrt(n)` | `sqrt(n)` |
| `tsop.Gcd(a, b)` | `gcd(a, b)` |
| `tsop.Divmod(a, b)` | `divmod(a, b)` |
| `tsop.Log2(n)` | `log2(n)` |
| `tsop.ToBool(n)` | `bool(n)` |
| `tsop.CheckPreimage(pre)` | `checkPreimage(pre)` |
| `tsop.ExtractLocktime(pre)` | `extractLocktime(pre)` |
| `tsop.ExtractOutputHash(pre)` | `extractOutputHash(pre)` |
| `tsop.ExtractAmount(pre)` | `extractAmount(pre)` |
| `tsop.VerifyRabinSig(msg, sig, pad, pk)` | `verifyRabinSig(msg, sig, pad, pk)` |

---

## Examples

### P2PKH

```go
package contracts

import "tsop"

type P2PKH struct {
    tsop.SmartContract
    PubKeyHash tsop.Addr `tsop:"readonly"`
}

func (c *P2PKH) Unlock(sig tsop.Sig, pubKey tsop.PubKey) {
    tsop.Assert(tsop.Hash160(pubKey) == c.PubKeyHash)
    tsop.Assert(tsop.CheckSig(sig, pubKey))
}
```

### Counter

```go
package contracts

import "tsop"

type Counter struct {
    tsop.StatefulSmartContract
    Count int64
}

func (c *Counter) Increment() {
    c.Count++
}

func (c *Counter) Decrement() {
    tsop.Assert(c.Count > 0)
    c.Count--
}
```

### Escrow

```go
package contracts

import "tsop"

type Escrow struct {
    tsop.SmartContract
    Buyer  tsop.PubKey `tsop:"readonly"`
    Seller tsop.PubKey `tsop:"readonly"`
    Arbiter tsop.PubKey `tsop:"readonly"`
}

func (c *Escrow) ReleaseBySeller(sig tsop.Sig) {
    tsop.Assert(tsop.CheckSig(sig, c.Seller))
}

func (c *Escrow) ReleaseByArbiter(sig tsop.Sig) {
    tsop.Assert(tsop.CheckSig(sig, c.Arbiter))
}

func (c *Escrow) RefundToBuyer(sig tsop.Sig) {
    tsop.Assert(tsop.CheckSig(sig, c.Buyer))
}

func (c *Escrow) RefundByArbiter(sig tsop.Sig) {
    tsop.Assert(tsop.CheckSig(sig, c.Arbiter))
}
```

### Auction

```go
package contracts

import "tsop"

type Auction struct {
    tsop.StatefulSmartContract
    Auctioneer    tsop.PubKey `tsop:"readonly"`
    HighestBidder tsop.PubKey
    HighestBid    int64
    Deadline      int64 `tsop:"readonly"`
}

func (c *Auction) Bid(bidder tsop.PubKey, bidAmount int64) {
    tsop.Assert(bidAmount > c.HighestBid)
    tsop.Assert(tsop.ExtractLocktime(c.TxPreimage) < c.Deadline)

    c.HighestBidder = bidder
    c.HighestBid = bidAmount
}

func (c *Auction) Close(sig tsop.Sig) {
    tsop.Assert(tsop.CheckSig(sig, c.Auctioneer))
    tsop.Assert(tsop.ExtractLocktime(c.TxPreimage) >= c.Deadline)
}
```

### OraclePriceFeed

```go
package contracts

import "tsop"

type OraclePriceFeed struct {
    tsop.SmartContract
    OraclePubKey tsop.RabinPubKey `tsop:"readonly"`
    Receiver     tsop.PubKey      `tsop:"readonly"`
}

func (c *OraclePriceFeed) Settle(price int64, rabinSig tsop.RabinSig, padding tsop.ByteString, sig tsop.Sig) {
    msg := tsop.Num2Bin(price, 8)
    tsop.Assert(tsop.VerifyRabinSig(msg, rabinSig, padding, c.OraclePubKey))
    tsop.Assert(price > 50000)
    tsop.Assert(tsop.CheckSig(sig, c.Receiver))
}
```

### CovenantVault

```go
package contracts

import "tsop"

type CovenantVault struct {
    tsop.SmartContract
    Owner     tsop.PubKey `tsop:"readonly"`
    Recipient tsop.Addr   `tsop:"readonly"`
    MinAmount int64       `tsop:"readonly"`
}

func (c *CovenantVault) Spend(sig tsop.Sig, amount int64, txPreimage tsop.SigHashPreimage) {
    tsop.Assert(tsop.CheckSig(sig, c.Owner))
    tsop.Assert(tsop.CheckPreimage(txPreimage))
    tsop.Assert(amount >= c.MinAmount)
}
```

### FungibleToken

```go
package contracts

import "tsop"

type FungibleToken struct {
    tsop.StatefulSmartContract
    Owner   tsop.PubKey      `tsop:""`
    Balance int64
    TokenId tsop.ByteString  `tsop:"readonly"`
}

func (c *FungibleToken) Transfer(sig tsop.Sig, to tsop.PubKey, amount int64, outputSatoshis int64) {
    tsop.Assert(tsop.CheckSig(sig, c.Owner))
    tsop.Assert(amount > 0)
    tsop.Assert(amount <= c.Balance)

    c.AddOutput(outputSatoshis, to, amount)
    c.AddOutput(outputSatoshis, c.Owner, c.Balance - amount)
}

func (c *FungibleToken) Send(sig tsop.Sig, to tsop.PubKey, outputSatoshis int64) {
    tsop.Assert(tsop.CheckSig(sig, c.Owner))
    c.AddOutput(outputSatoshis, to, c.Balance)
}

func (c *FungibleToken) Merge(sig tsop.Sig, totalBalance int64, outputSatoshis int64) {
    tsop.Assert(tsop.CheckSig(sig, c.Owner))
    tsop.Assert(totalBalance >= c.Balance)
    c.AddOutput(outputSatoshis, c.Owner, totalBalance)
}
```

### SimpleNFT

```go
package contracts

import "tsop"

type SimpleNFT struct {
    tsop.StatefulSmartContract
    Owner    tsop.PubKey     `tsop:""`
    TokenId  tsop.ByteString `tsop:"readonly"`
    Metadata tsop.ByteString `tsop:"readonly"`
}

func (c *SimpleNFT) Transfer(sig tsop.Sig, newOwner tsop.PubKey, outputSatoshis int64) {
    tsop.Assert(tsop.CheckSig(sig, c.Owner))
    c.AddOutput(outputSatoshis, newOwner)
}

func (c *SimpleNFT) Burn(sig tsop.Sig) {
    tsop.Assert(tsop.CheckSig(sig, c.Owner))
}
```

---

## Name Conventions

Go uses PascalCase for exported identifiers. The parser converts to camelCase for the AST:

| Go identifier | AST identifier |
|--------------|----------------|
| `PubKeyHash` (field) | `pubKeyHash` (property) |
| `HighestBidder` (field) | `highestBidder` (property) |
| `Unlock` (method) | `unlock` (method) |
| `ReleaseBySeller` (method) | `releaseBySeller` (method) |

Unexported identifiers (lowercase first letter) are kept as-is.

### Constructor

The constructor is auto-generated from the struct fields. The parser creates a constructor that:
1. Accepts all fields as parameters (in declaration order).
2. Calls `super(...)` with all parameters.
3. Assigns each parameter to the corresponding property.

There is no explicit constructor syntax in the Go format.
