# Simple Fungible Token

A basic fungible token contract demonstrating ownership transfer with stateful on-chain tracking.

## What it does

Represents a fungible token with a fixed supply and a transferable owner. The current owner can transfer ownership to a new public key, and the contract state is updated on-chain.

- **Transfer** -- the current owner signs to transfer the token to a new owner. The contract state is updated in the output UTXO.

## Design pattern

**Stateful ownership transfer** -- extends `StatefulSmartContract` and combines signature-based authorization (`checkSig`) with automatic state management. The `owner` field is mutable (non-`readonly`), while `supply` is immutable (`readonly`). Each transfer produces a new UTXO with the updated owner.

## TSOP features demonstrated

- `StatefulSmartContract` for automatic preimage verification and state continuation
- Mix of `readonly` (immutable) and mutable (stateful) properties
- Owner-authorized state transitions via `checkSig()`

## Compile and use

```bash
tsop compile FungibleTokenExample.tsop.ts
```

Deploy with an initial owner public key and a supply value. To transfer, the current owner signs the transaction and specifies the new owner's public key. The spending transaction must contain an output with the updated contract state.
