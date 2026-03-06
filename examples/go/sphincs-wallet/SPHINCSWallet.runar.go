package contract

import runar "github.com/icellan/runar/packages/runar-go"

// SPHINCSWallet uses SLH-DSA-SHA2-128s (SPHINCS+).
//
// NIST FIPS 205, 128-bit post-quantum security, stateless.
// Unlike WOTS+ (one-time), the same keypair can sign many messages.
//
// Public key: 32 bytes (PK.seed || PK.root).
// Signature: 7,856 bytes.
type SPHINCSWallet struct {
	runar.SmartContract
	Pubkey runar.ByteString `runar:"readonly"`
}

// Spend verifies an SLH-DSA-SHA2-128s signature and allows spending.
func (c *SPHINCSWallet) Spend(msg runar.ByteString, sig runar.ByteString) {
	runar.Assert(runar.VerifySLHDSA_SHA2_128s(msg, sig, c.Pubkey))
}
