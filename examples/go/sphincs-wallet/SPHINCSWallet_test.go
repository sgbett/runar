package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// deterministic seed for reproducible tests
var testSeed = func() []byte {
	s := make([]byte, 3*16) // 3*n for SLH-DSA-128s (n=16)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}()

var testKP = runar.SLHKeygen(runar.SLH_SHA2_128s, testSeed)

func TestSPHINCSWallet_Spend(t *testing.T) {
	c := &SPHINCSWallet{Pubkey: runar.ByteString(testKP.PK)}
	msg := []byte("test message")
	sig := runar.SLHSign(runar.SLH_SHA2_128s, msg, testKP.SK)
	c.Spend(runar.ByteString(msg), runar.ByteString(sig))
}

func TestSPHINCSWallet_Spend_MultipleMessages(t *testing.T) {
	// SLH-DSA is stateless — same keypair can sign many messages
	c := &SPHINCSWallet{Pubkey: runar.ByteString(testKP.PK)}
	msg1 := []byte("first message")
	sig1 := runar.SLHSign(runar.SLH_SHA2_128s, msg1, testKP.SK)
	c.Spend(runar.ByteString(msg1), runar.ByteString(sig1))

	msg2 := []byte("second message")
	sig2 := runar.SLHSign(runar.SLH_SHA2_128s, msg2, testKP.SK)
	c.Spend(runar.ByteString(msg2), runar.ByteString(sig2))
}

func TestSPHINCSWallet_Spend_WrongSig(t *testing.T) {
	c := &SPHINCSWallet{Pubkey: runar.ByteString(testKP.PK)}
	msg := []byte("test message")
	sig := runar.SLHSign(runar.SLH_SHA2_128s, msg, testKP.SK)
	sig[0] ^= 0xff // corrupt signature

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with corrupt signature")
		}
	}()
	c.Spend(runar.ByteString(msg), runar.ByteString(sig))
}

func TestSPHINCSWallet_Compile(t *testing.T) {
	if err := runar.CompileCheck("SPHINCSWallet.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
