# Integration Tests

End-to-end integration tests that deploy and spend Runar contracts on a real Bitcoin node. Two node backends are supported:

- **SV Node** — Bitcoin SV node with built-in wallet (default)
- **Teranode** — BSV's microservices-based node implementation

## Quick Start

### SV Node

```bash
# Start node, run tests, stop node
pnpm integration:svnode:run

# Or step by step:
pnpm integration:svnode:start
pnpm integration:svnode
pnpm integration:svnode:stop
pnpm integration:svnode:clean    # remove all data
```

### Teranode

```bash
# Start node, run tests, stop node (clean start)
pnpm integration:teranode:run

# Or step by step:
pnpm integration:teranode:start   # starts Docker services + mines 10101 blocks
pnpm integration:teranode
pnpm integration:teranode:stop
pnpm integration:teranode:clean   # remove all data + volumes
```

## Node Setup Details

### SV Node

Uses the `bitcoinsv/bitcoin-sv:latest` Docker image. A single container runs the full node in regtest mode with:

- `genesisactivationheight=1` — post-Genesis rules from block 1
- `maxscriptsizepolicy=0` / `maxscriptnumlengthpolicy=0` — unlimited script sizes
- Built-in wallet for `sendtoaddress` funding

RPC: `http://localhost:18332` (user: `bitcoin`, pass: `bitcoin`)

### Teranode

Uses `ghcr.io/bsv-blockchain/teranode:v0.13.2` with 10+ microservices in Docker Compose:

- blockchain, validator, blockassembly, blockvalidation, subtreevalidation, propagation, rpc, asset, peer
- Infrastructure: PostgreSQL, Aerospike, Kafka (Redpanda)

Key differences from SV Node:

| Feature | SV Node | Teranode |
|---------|---------|----------|
| Genesis activation | Height 1 (configurable) | Height 10000 (hardcoded in go-chaincfg) |
| Wallet | Built-in (`sendtoaddress`) | None — uses raw coinbase UTXOs |
| `getrawtransaction` verbose | `true` (bool) | `1` (int) |
| `getrawtransaction` value | BTC (e.g. 50.0) | Satoshis (e.g. 5000000000) |
| `getblock` tx list | Populated | Empty (code commented out) |
| Block format | Standard | Extended (extra varint fields + subtree hashes) |

Because Teranode's Genesis activation is hardcoded at height 10000 for regtest, the `teranode.sh start` script pre-mines 10101 blocks (10000 for Genesis + 101 for coinbase maturity). This takes ~5 minutes on first start. Subsequent `start` commands (without `clean`) skip mining if blocks already exist.

## Test Structure

Tests are in `*_test.go` files with the `integration` build tag:

| Test File | Contract | What's Tested |
|-----------|----------|---------------|
| `p2pkh_test.go` | P2PKH | Valid unlock, wrong key, wrong signature |
| `escrow_test.go` | Escrow | Release/refund by seller/buyer/arbiter, wrong signer, invalid method |
| `counter_test.go` | Counter (stateful) | Increment, chain increments, decrement, wrong state, underflow |
| `oracle_price_test.go` | OraclePriceFeed | Valid settle with Rabin signature, below threshold, wrong receiver |
| `schnorr_zkp_test.go` | SchnorrZKP (875KB) | Valid proof with EC math, invalid scalar |
| `slhdsa_test.go` | SPHINCSWallet (188KB) | Valid SLH-DSA spend, tampered signature |
| `wots_test.go` | PostQuantumWallet (19KB) | Valid WOTS+ spend, tampered sig, wrong message |

## Helpers

The `helpers/` package provides node-agnostic utilities:

- **`rpc.go`** — RPC client, mining, `SendRawTransaction`, node type detection (`NODE_TYPE` env var)
- **`wallet.go`** — Wallet generation, `FundWallet` (auto-selects SV Node wallet or coinbase funding), UTXO lookup
- **`coinbase.go`** — Teranode coinbase wallet management, raw block parsing for UTXO extraction
- **`tx.go`** — Transaction building, signing (ECDSA + BIP-143 sighash), OP_PUSH_TX
- **`assert.go`** — `AssertTxAccepted`, `AssertTxRejected`, `AssertTxInBlock`
- **`compile.go`** — Contract compilation via the TypeScript compiler
- **`rabin.go`** — Rabin signature generation for oracle tests

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_TYPE` | `svnode` | Node backend: `svnode` or `teranode` |
| `RPC_URL` | auto | Override RPC endpoint URL |
| `RPC_USER` | `bitcoin` | RPC username |
| `RPC_PASS` | `bitcoin` | RPC password |

## Troubleshooting

**UTXO_SPENT errors**: Run `./teranode.sh clean && ./teranode.sh start` to reset all state. The coinbase UTXO counter resets each test run but Teranode remembers spent UTXOs.

**RPC timeout during mining**: The Teranode RPC timeout is set to 600s in `settings_local.conf`. The Go HTTP client also uses a 10-minute timeout.

**Tests pass on SV Node but fail on Teranode**: Check that the 10101 blocks were mined (Genesis activation). Run `./teranode.sh getblockchaininfo` to verify the block height.
