package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestSchnorrZKP_ValidProof(t *testing.T) {
	privKey := int64(42)
	pubKey := runar.EcMulGen(privKey)

	r := int64(12345)
	rPoint := runar.EcMulGen(r)

	e := int64(7)
	// s = r + e*privKey (we keep this small enough for int64)
	s := r + e*privKey

	c := &SchnorrZKP{PubKey: pubKey}
	c.Verify(rPoint, s, e) // should not panic
}

func TestSchnorrZKP_WrongS(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong s value")
		}
	}()

	privKey := int64(42)
	pubKey := runar.EcMulGen(privKey)

	r := int64(12345)
	rPoint := runar.EcMulGen(r)

	e := int64(7)
	s := r + e*privKey

	c := &SchnorrZKP{PubKey: pubKey}
	c.Verify(rPoint, s+1, e)
}

func TestSchnorrZKP_WrongChallenge(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong challenge")
		}
	}()

	privKey := int64(42)
	pubKey := runar.EcMulGen(privKey)

	r := int64(12345)
	rPoint := runar.EcMulGen(r)

	e := int64(7)
	s := r + e*privKey

	c := &SchnorrZKP{PubKey: pubKey}
	c.Verify(rPoint, s, e+1)
}

func TestSchnorrZKP_LargerKey(t *testing.T) {
	privKey := int64(999999)
	pubKey := runar.EcMulGen(privKey)

	r := int64(54321)
	rPoint := runar.EcMulGen(r)

	e := int64(3)
	s := r + e*privKey

	c := &SchnorrZKP{PubKey: pubKey}
	c.Verify(rPoint, s, e)
}

func TestSchnorrZKP_Compile(t *testing.T) {
	if err := runar.CompileCheck("SchnorrZKP.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
