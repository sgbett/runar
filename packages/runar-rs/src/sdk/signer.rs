//! Signer trait and implementations for transaction signing.

// ---------------------------------------------------------------------------
// Signer trait
// ---------------------------------------------------------------------------

/// Abstraction over transaction signing.
pub trait Signer {
    /// Get the hex-encoded compressed public key (33 bytes = 66 hex chars).
    fn get_public_key(&self) -> Result<String, String>;

    /// Get the BSV address.
    fn get_address(&self) -> Result<String, String>;

    /// Sign a transaction input.
    ///
    /// - `tx_hex`:       The full raw transaction hex being signed.
    /// - `input_index`:  Index of the input being signed.
    /// - `subscript`:    The locking script of the UTXO being spent (hex).
    /// - `satoshis`:     The satoshi value of the UTXO being spent.
    /// - `sig_hash_type`: Sighash flags (defaults to ALL | FORKID = 0x41).
    ///
    /// Returns the DER-encoded signature with sighash byte appended, hex-encoded.
    fn sign(
        &self,
        tx_hex: &str,
        input_index: usize,
        subscript: &str,
        satoshis: i64,
        sig_hash_type: Option<u32>,
    ) -> Result<String, String>;
}

// ---------------------------------------------------------------------------
// LocalSigner
// ---------------------------------------------------------------------------

/// A local signer wrapping a private key.
///
/// NOTE: This is a stub implementation. Full signing requires a secp256k1
/// library. For testing purposes, use MockSigner or ExternalSigner.
pub struct LocalSigner {
    private_key_hex: String,
}

impl LocalSigner {
    /// Create a new LocalSigner from a hex-encoded private key.
    pub fn new(private_key_hex: &str) -> Self {
        LocalSigner {
            private_key_hex: private_key_hex.to_string(),
        }
    }
}

impl Signer for LocalSigner {
    fn get_public_key(&self) -> Result<String, String> {
        // Stub: return a mock compressed public key
        // In a real implementation, derive from the private key using secp256k1
        Ok(format!("02{}", "00".repeat(32)))
    }

    fn get_address(&self) -> Result<String, String> {
        // Stub: return a deterministic mock address from the private key
        // In a real implementation, derive from the public key
        let mut bytes = [0u8; 20];
        for (i, c) in self.private_key_hex.bytes().enumerate() {
            bytes[i % 20] = (bytes[i % 20] ^ c).wrapping_mul(31).wrapping_add(17) & 0xff;
        }
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        Ok(hex)
    }

    fn sign(
        &self,
        _tx_hex: &str,
        _input_index: usize,
        _subscript: &str,
        _satoshis: i64,
        _sig_hash_type: Option<u32>,
    ) -> Result<String, String> {
        // Stub: return a mock DER signature (72 bytes) + sighash byte
        // In a real implementation, compute the sighash and sign with secp256k1
        Ok(format!("30{}41", "00".repeat(70)))
    }
}

// ---------------------------------------------------------------------------
// ExternalSigner
// ---------------------------------------------------------------------------

/// A signer that delegates to external callback functions.
///
/// Useful for integrating with hardware wallets, web wallet extensions,
/// or remote signing services.
pub struct ExternalSigner {
    public_key_fn: Box<dyn Fn() -> Result<String, String>>,
    address_fn: Box<dyn Fn() -> Result<String, String>>,
    sign_fn: Box<dyn Fn(&str, usize, &str, i64, Option<u32>) -> Result<String, String>>,
}

impl ExternalSigner {
    /// Create a new ExternalSigner with callback functions.
    pub fn new(
        public_key_fn: impl Fn() -> Result<String, String> + 'static,
        address_fn: impl Fn() -> Result<String, String> + 'static,
        sign_fn: impl Fn(&str, usize, &str, i64, Option<u32>) -> Result<String, String> + 'static,
    ) -> Self {
        ExternalSigner {
            public_key_fn: Box::new(public_key_fn),
            address_fn: Box::new(address_fn),
            sign_fn: Box::new(sign_fn),
        }
    }
}

impl Signer for ExternalSigner {
    fn get_public_key(&self) -> Result<String, String> {
        (self.public_key_fn)()
    }

    fn get_address(&self) -> Result<String, String> {
        (self.address_fn)()
    }

    fn sign(
        &self,
        tx_hex: &str,
        input_index: usize,
        subscript: &str,
        satoshis: i64,
        sig_hash_type: Option<u32>,
    ) -> Result<String, String> {
        (self.sign_fn)(tx_hex, input_index, subscript, satoshis, sig_hash_type)
    }
}

// ---------------------------------------------------------------------------
// MockSigner (for testing)
// ---------------------------------------------------------------------------

/// A mock signer that returns deterministic dummy values.
/// Suitable for unit tests where real signing is not needed.
pub struct MockSigner {
    pub public_key: String,
    pub address: String,
}

impl MockSigner {
    /// Create a MockSigner with sensible defaults.
    pub fn new() -> Self {
        MockSigner {
            public_key: format!("02{}", "00".repeat(32)),
            address: "00".repeat(20),
        }
    }
}

impl Default for MockSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer for MockSigner {
    fn get_public_key(&self) -> Result<String, String> {
        Ok(self.public_key.clone())
    }

    fn get_address(&self) -> Result<String, String> {
        Ok(self.address.clone())
    }

    fn sign(
        &self,
        _tx_hex: &str,
        _input_index: usize,
        _subscript: &str,
        _satoshis: i64,
        _sig_hash_type: Option<u32>,
    ) -> Result<String, String> {
        // Return a mock 72-byte DER signature + sighash byte
        Ok(format!("30{}41", "00".repeat(70)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_signer_returns_public_key() {
        let signer = LocalSigner::new("0000000000000000000000000000000000000000000000000000000000000001");
        let pk = signer.get_public_key().unwrap();
        assert_eq!(pk.len(), 66);
        assert!(pk.starts_with("02"));
    }

    #[test]
    fn local_signer_returns_address() {
        let signer = LocalSigner::new("0000000000000000000000000000000000000000000000000000000000000001");
        let addr = signer.get_address().unwrap();
        assert_eq!(addr.len(), 40);
    }

    #[test]
    fn local_signer_returns_signature() {
        let signer = LocalSigner::new("0000000000000000000000000000000000000000000000000000000000000001");
        let sig = signer.sign("deadbeef", 0, "51", 50_000, None).unwrap();
        assert!(!sig.is_empty());
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn mock_signer_returns_deterministic_values() {
        let signer = MockSigner::new();
        let pk = signer.get_public_key().unwrap();
        assert_eq!(pk.len(), 66);

        let addr = signer.get_address().unwrap();
        assert_eq!(addr.len(), 40);

        let sig = signer.sign("aabb", 0, "51", 1000, None).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn external_signer_delegates_to_callbacks() {
        let signer = ExternalSigner::new(
            || Ok("02aabb".to_string()),
            || Ok("myaddr".to_string()),
            |_tx, _idx, _sub, _sats, _sht| Ok("sig_hex".to_string()),
        );

        assert_eq!(signer.get_public_key().unwrap(), "02aabb");
        assert_eq!(signer.get_address().unwrap(), "myaddr");
        assert_eq!(signer.sign("tx", 0, "51", 100, None).unwrap(), "sig_hex");
    }
}
