# runar-rs

**Deploy, call, and interact with compiled Runar smart contracts on BSV from Rust.**

The Rust SDK provides the runtime layer between compiled contract artifacts and the BSV blockchain. It handles transaction construction, signing, broadcasting, state management for stateful contracts, and UTXO tracking.

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
runar = { path = "../runar-rs" }  # or from registry when published
```

---

## Contract Lifecycle

A Runar contract goes through four stages:

```
  [1. Instantiate]     Load the compiled artifact and set constructor parameters.
         |
         v
  [2. Deploy]          Build a transaction with the locking script, sign, and broadcast.
         |
         v
  [3. Call]            Build an unlocking transaction to invoke a public method.
         |
         v
  [4. Read State]      (Stateful only) Read state from the contract's current UTXO.
```

### Full Example

```rust
use runar::sdk::*;

// 1. Load the artifact (compiled contract JSON)
let artifact: RunarArtifact = serde_json::from_str(&json)?;

// 2. Create the contract with constructor arguments
let mut contract = RunarContract::new(artifact, vec![
    SdkValue::Bytes(pub_key_hash),
]);

// 3. Set up provider and signer
//    Use ExternalSigner to wrap a real signing library
let signer = ExternalSigner::new(
    || Ok(pub_key_hex.clone()),
    || Ok(address.clone()),
    |tx_hex, input_index, subscript, satoshis, sig_hash_type| {
        // Delegate to your signing library here
        sign_with_rust_sv(tx_hex, input_index, subscript, satoshis, sig_hash_type)
    },
);
let mut provider = MockProvider::testnet();

// 4. Deploy
let (txid, tx) = contract.deploy(&mut provider, &signer, &DeployOptions {
    satoshis: 10_000,
    change_address: None,
})?;

// 5. Call a public method
let (txid2, tx2) = contract.call("unlock", &[
    SdkValue::Bytes(sig),
    SdkValue::Bytes(pub_key),
], &mut provider, &signer, None)?;
```

### Stateful Contract Example

```rust
// Create with initial state
let mut contract = RunarContract::new(counter_artifact, vec![SdkValue::Int(0)]);

// Deploy
let (txid, _) = contract.deploy(&mut provider, &signer, &DeployOptions {
    satoshis: 10_000,
    change_address: None,
})?;

// Read current state
println!("Count: {:?}", contract.state().get("count")); // Some(Int(0))

// Call increment with updated state
let mut new_state = HashMap::new();
new_state.insert("count".to_string(), SdkValue::Int(1));
let (txid2, _) = contract.call("increment", &[], &mut provider, &signer, Some(&CallOptions {
    satoshis: Some(9_500),
    change_address: None,
    new_state: Some(new_state),
}))?;
println!("Count: {:?}", contract.state().get("count")); // Some(Int(1))
```

### Reconnecting to a Deployed Contract

```rust
// Reconnect to an existing on-chain contract by txid
let contract = RunarContract::from_txid(artifact, &txid, 0, &provider)?;
println!("Current state: {:?}", contract.state());
```

---

## Providers

Providers handle communication with the BSV network: fetching UTXOs, broadcasting transactions, and querying transaction data.

### MockProvider

For unit testing without network access:

```rust
let mut provider = MockProvider::testnet();

// Pre-register UTXOs
provider.add_utxo("myAddress", Utxo {
    txid: "abc123...".to_string(),
    output_index: 0,
    satoshis: 10_000,
    script: "76a914...88ac".to_string(),
});

// Pre-register transactions
provider.add_transaction(Transaction { /* ... */ });

// Pre-register contract UTXOs for stateful lookup
provider.add_contract_utxo("scripthash...", Utxo { /* ... */ });

// Inspect broadcasts
let broadcasted = provider.get_broadcasted_txs();

// Override the fee rate (default 1 sat/byte)
provider.set_fee_rate(2);
```

### Custom Provider

Implement the `Provider` trait for other network APIs:

```rust
pub trait Provider {
    fn get_transaction(&self, txid: &str) -> Result<Transaction, String>;
    fn broadcast(&mut self, raw_tx: &str) -> Result<String, String>;
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String>;
    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String>;
    fn get_network(&self) -> &str;
    fn get_fee_rate(&self) -> Result<i64, String>;
}
```

Production providers are not included in this crate -- implement the trait using your preferred HTTP client.

---

## Signers

Signers handle private key operations: signing transactions and deriving public keys.

### MockSigner

For unit testing without real crypto:

```rust
let signer = MockSigner::new();
let pub_key = signer.get_public_key()?;  // 66-char hex
let address = signer.get_address()?;
let sig = signer.sign(tx_hex, 0, subscript, satoshis, None)?;
```

### ExternalSigner

Delegates signing to caller-provided closures. Use this to wrap real signing libraries:

```rust
let signer = ExternalSigner::new(
    || Ok("02aabb...".to_string()),           // get_public_key
    || Ok("1Address...".to_string()),          // get_address
    |tx_hex, idx, sub, sats, sht| {            // sign
        Ok(your_sign_fn(tx_hex, idx, sub, sats, sht))
    },
);
```

### Custom Signer

Implement the `Signer` trait:

```rust
pub trait Signer {
    fn get_public_key(&self) -> Result<String, String>;
    fn get_address(&self) -> Result<String, String>;
    fn sign(
        &self,
        tx_hex: &str,
        input_index: usize,
        subscript: &str,
        satoshis: i64,
        sig_hash_type: Option<u32>,
    ) -> Result<String, String>;
}
```

---

## Stateful Contract Support

### State Chaining

Stateful contracts maintain state across transactions using the OP_PUSH_TX pattern. The SDK manages this automatically:

1. **Deploy:** The initial state is serialized and appended after an OP_RETURN separator in the locking script.
2. **Call:** The SDK reads the current state from the existing UTXO, builds the unlocking script, and creates a new output with the updated locking script containing the new state.
3. **Read:** `contract.state()` returns the deserialized state from the UTXO's locking script.

### State Serialization Format

State is stored as a suffix of the locking script:

```
<code_part> OP_RETURN <field_0> <field_1> ... <field_n>
```

Type-specific encoding:
- `int`/`bigint`: OP_0 for zero, otherwise minimally-encoded Script integers (with sign byte)
- `bool`: OP_0 (`00`) for false, OP_1 (`51`) for true
- `bytes`/`ByteString`/`PubKey`/`Addr`/`Sha256`: direct pushdata

---

## Value Types

The `SdkValue` enum represents typed contract values:

```rust
pub enum SdkValue {
    Int(i64),
    Bool(bool),
    Bytes(String),  // hex-encoded
}
```

---

## Transaction Building Utilities

The SDK exports lower-level functions for custom transaction construction:

```rust
use runar::sdk::deployment::*;
use runar::sdk::calling::*;
use runar::sdk::state::*;

// Select UTXOs (largest-first strategy)
let selected = select_utxos(&utxos, target_satoshis, locking_script_byte_len, Some(fee_rate));

// Build an unsigned deploy transaction
let (tx_hex, input_count) = build_deploy_transaction(
    &locking_script, &utxos, satoshis, change_address, &change_script, Some(fee_rate),
);

// Build a method call transaction
let (tx_hex, input_count) = build_call_transaction(
    &current_utxo, &unlocking_script, new_locking_script, new_satoshis,
    Some(change_address), Some(&change_script), Some(&additional_utxos), Some(fee_rate),
);

// State serialization
let state_hex = serialize_state(&state_fields, &values);
let state = deserialize_state(&state_fields, &state_hex);
let state = extract_state_from_script(&artifact, &full_script);
```

---

## Design Decisions

- **No built-in network provider:** Rust applications typically use specific async runtimes (tokio, async-std) and HTTP clients. Implement the `Provider` trait with your stack.
- **No built-in crypto signer:** Use established crates like `rust-sv` or `secp256k1` for signing. The `ExternalSigner` closure pattern makes integration straightforward.
- **Synchronous API:** All methods are synchronous (`fn`, not `async fn`). This makes the SDK usable with any async runtime without imposing `Send`/`Sync` constraints.
- **`SdkValue` enum:** Unlike Go's `interface{}`, Rust uses a typed enum for state values, providing exhaustive matching and type safety.
