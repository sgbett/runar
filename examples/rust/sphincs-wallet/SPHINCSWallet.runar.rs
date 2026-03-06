use runar::prelude::*;

/// Post-Quantum Wallet using SLH-DSA-SHA2-128s (SPHINCS+).
///
/// NIST FIPS 205, 128-bit post-quantum security, stateless.
/// Unlike WOTS+ (one-time), the same keypair can sign many messages.
///
/// Public key: 32 bytes (PK.seed || PK.root).
/// Signature: 7,856 bytes.
#[runar::contract]
pub struct SPHINCSWallet {
    #[readonly]
    pub pubkey: ByteString,
}

#[runar::methods(SPHINCSWallet)]
impl SPHINCSWallet {
    /// Verify an SLH-DSA-SHA2-128s signature and allow spending.
    #[public]
    pub fn spend(&self, msg: &ByteString, sig: &ByteString) {
        assert!(verify_slh_dsa_sha2_128s(msg, sig, &self.pubkey));
    }
}
