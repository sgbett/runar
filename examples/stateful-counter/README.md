# Stateful Counter

A simple counter contract that maintains mutable state across transactions using `StatefulSmartContract`.

## What it does

Maintains an on-chain counter that can be incremented or decremented. Each call produces a new UTXO containing the updated count value.

- **Increment** -- increases the count by 1
- **Decrement** -- decreases the count by 1 (requires count > 0)

## Design pattern

**Stateful contract** -- the `count` property is non-`readonly`, making it mutable state. By extending `StatefulSmartContract`, the compiler automatically verifies the sighash preimage at method entry and asserts that the transaction output carries the updated state at method exit. The developer only writes the business logic.

## TSOP features demonstrated

- `StatefulSmartContract` for automatic preimage verification and state continuation
- Non-`readonly` properties as mutable contract state
- BigInt literals (`0n`) for script-level numeric operations
- Automatic state serialization and output covenant enforcement

## Compile and use

```bash
tsop compile Counter.tsop.ts
```

Deploy with an initial count value. To interact, construct a transaction whose output contains the contract with the updated count. The SDK automatically provides the sighash preimage. The contract self-verifies that the output matches the expected next state.
