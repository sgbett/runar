use runar::prelude::*;

/// Post-Quantum Wallet using WOTS+ (Winternitz One-Time Signature).
///
/// SHA-256-based hash chain verification with w=16, producing a ~10 KB
/// Bitcoin Script locking script. Each UTXO can be spent exactly once
/// with a valid WOTS+ signature — a natural fit for Bitcoin's UTXO model.
///
/// Signature size: 2,144 bytes (67 chains x 32 bytes).
/// Public key size: 32 bytes (SHA-256 of concatenated chain endpoints).
#[runar::contract]
pub struct PostQuantumWallet {
    #[readonly]
    pub pubkey: ByteString,
}

#[runar::methods(PostQuantumWallet)]
impl PostQuantumWallet {
    /// Verify a WOTS+ signature and allow spending.
    #[public]
    pub fn spend(&self, msg: &ByteString, sig: &ByteString) {
        assert!(verify_wots(msg, sig, &self.pubkey));
    }
}
