package contract

import runar "github.com/icellan/runar/packages/runar-go"

// PostQuantumWallet uses WOTS+ (Winternitz One-Time Signature).
//
// SHA-256-based hash chain verification with w=16, producing a ~10 KB
// Bitcoin Script locking script. Each UTXO can be spent exactly once
// with a valid WOTS+ signature — a natural fit for Bitcoin's UTXO model.
//
// Signature size: 2,144 bytes (67 chains x 32 bytes).
// Public key size: 32 bytes (SHA-256 of concatenated chain endpoints).
type PostQuantumWallet struct {
	runar.SmartContract
	Pubkey runar.ByteString `runar:"readonly"`
}

// Spend verifies a WOTS+ signature and allows the UTXO to be spent.
func (c *PostQuantumWallet) Spend(msg runar.ByteString, sig runar.ByteString) {
	runar.Assert(runar.VerifyWOTS(msg, sig, c.Pubkey))
}
