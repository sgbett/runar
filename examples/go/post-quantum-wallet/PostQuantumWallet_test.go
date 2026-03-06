package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestPostQuantumWallet_Spend(t *testing.T) {
	seed := [32]byte{}
	for i := range seed {
		seed[i] = 0x42
	}
	pubSeed := [32]byte{}
	for i := range pubSeed {
		pubSeed[i] = 0x13
	}
	kp := runar.WotsKeygen(seed[:], pubSeed[:])

	c := &PostQuantumWallet{Pubkey: runar.ByteString(kp.PK)}
	msg := []byte("test message")
	sig := runar.WotsSign(msg, kp.SK, kp.PubSeed)
	c.Spend(runar.ByteString(msg), runar.ByteString(sig))
}

func TestPostQuantumWallet_Spend_WrongSig(t *testing.T) {
	seed := [32]byte{}
	for i := range seed {
		seed[i] = 0x42
	}
	pubSeed := [32]byte{}
	for i := range pubSeed {
		pubSeed[i] = 0x13
	}
	kp := runar.WotsKeygen(seed[:], pubSeed[:])

	c := &PostQuantumWallet{Pubkey: runar.ByteString(kp.PK)}
	msg := []byte("test message")
	sig := runar.WotsSign(msg, kp.SK, kp.PubSeed)
	sig[0] ^= 0xff // corrupt signature

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with corrupt signature")
		}
	}()
	c.Spend(runar.ByteString(msg), runar.ByteString(sig))
}

func TestPostQuantumWallet_Compile(t *testing.T) {
	if err := runar.CompileCheck("PostQuantumWallet.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
