package runar

// ---------------------------------------------------------------------------
// Signer interface
// ---------------------------------------------------------------------------

// Signer abstracts private key operations for signing transactions.
type Signer interface {
	// GetPublicKey returns the hex-encoded compressed public key (66 hex chars).
	GetPublicKey() (string, error)

	// GetAddress returns the BSV address.
	GetAddress() (string, error)

	// Sign signs a transaction input.
	// txHex is the full raw transaction hex being signed.
	// inputIndex is the index of the input being signed.
	// subscript is the locking script of the UTXO being spent (hex).
	// satoshis is the satoshi value of the UTXO being spent.
	// sigHashType is the sighash flags (nil defaults to ALL|FORKID = 0x41).
	// Returns the DER-encoded signature with sighash byte appended, hex-encoded.
	Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error)
}

// ---------------------------------------------------------------------------
// MockSigner — deterministic signer for testing
// ---------------------------------------------------------------------------

// MockSignerImpl is a mock signer that returns deterministic values for testing.
// It does not perform real cryptographic operations.
type MockSignerImpl struct {
	pubKey  string
	address string
}

// NewMockSigner creates a mock signer with the given public key hex and address.
// If empty strings are passed, defaults are used.
func NewMockSigner(pubKeyHex, address string) *MockSignerImpl {
	if pubKeyHex == "" {
		// Default: 33-byte compressed public key (02 + 32 zero bytes)
		pubKeyHex = "02" + repeatHex("00", 32)
	}
	if address == "" {
		address = repeatHex("00", 20) // 40-char hex as a mock address
	}
	return &MockSignerImpl{
		pubKey:  pubKeyHex,
		address: address,
	}
}

// GetPublicKey returns the mock public key.
func (s *MockSignerImpl) GetPublicKey() (string, error) {
	return s.pubKey, nil
}

// GetAddress returns the mock address.
func (s *MockSignerImpl) GetAddress() (string, error) {
	return s.address, nil
}

// Sign returns a mock DER-encoded signature (72 zero bytes as hex).
func (s *MockSignerImpl) Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
	// Return a deterministic 72-byte mock signature (all zeros) + sighash byte 0x41
	return repeatHex("00", 71) + "41", nil
}

// ---------------------------------------------------------------------------
// ExternalSigner — callback-based signer
// ---------------------------------------------------------------------------

// SignFunc is a callback function for signing.
type SignFunc func(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error)

// ExternalSigner wraps a callback function as a Signer.
type ExternalSigner struct {
	pubKey  string
	address string
	signFn  SignFunc
}

// NewExternalSigner creates a signer from callback functions.
func NewExternalSigner(pubKeyHex, address string, signFn SignFunc) *ExternalSigner {
	return &ExternalSigner{
		pubKey:  pubKeyHex,
		address: address,
		signFn:  signFn,
	}
}

// GetPublicKey returns the external public key.
func (s *ExternalSigner) GetPublicKey() (string, error) {
	return s.pubKey, nil
}

// GetAddress returns the external address.
func (s *ExternalSigner) GetAddress() (string, error) {
	return s.address, nil
}

// Sign delegates to the callback function.
func (s *ExternalSigner) Sign(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
	return s.signFn(txHex, inputIndex, subscript, satoshis, sigHashType)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func repeatHex(b string, count int) string {
	result := make([]byte, 0, len(b)*count)
	for i := 0; i < count; i++ {
		result = append(result, b...)
	}
	return string(result)
}
