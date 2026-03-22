package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Parse a basic Python P2PKH contract
// ---------------------------------------------------------------------------

func TestParsePython_P2PKH(t *testing.T) {
	source := `
from runar import SmartContract, assert_, hash160, check_sig, Addr, Sig, PubKey

class P2PKH(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
`
	result := ParseSource([]byte(source), "P2PKH.runar.py")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		t.Fatal("expected non-nil contract")
	}

	c := result.Contract
	if c.Name != "P2PKH" {
		t.Errorf("expected contract name P2PKH, got %s", c.Name)
	}
	if c.ParentClass != "SmartContract" {
		t.Errorf("expected parentClass SmartContract, got %s", c.ParentClass)
	}
	if len(c.Properties) < 1 {
		t.Fatal("expected at least 1 property")
	}
	// Python snake_case pub_key_hash -> camelCase pubKeyHash
	if c.Properties[0].Name != "pubKeyHash" {
		t.Errorf("expected property name pubKeyHash, got %s", c.Properties[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Python contract verifies method params
// ---------------------------------------------------------------------------

func TestParsePython_MethodParams(t *testing.T) {
	source := `
from runar import SmartContract, assert_

class Adder(SmartContract):
    target: int

    def __init__(self, target: int):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, a: int, b: int):
        assert_(a + b == self.target)
`
	result := ParseSource([]byte(source), "Adder.runar.py")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Methods) < 1 {
		t.Fatal("expected at least 1 method")
	}
	m := c.Methods[0]
	if m.Name != "verify" {
		t.Errorf("expected method name verify, got %s", m.Name)
	}
	if m.Visibility != "public" {
		t.Errorf("expected method visibility public, got %s", m.Visibility)
	}
	// 'self' should be excluded from params
	for _, p := range m.Params {
		if p.Name == "self" {
			t.Error("self should not appear as a method param")
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Python stateful contract
// ---------------------------------------------------------------------------

func TestParsePython_StatefulContract(t *testing.T) {
	source := `
from runar import StatefulSmartContract

class Counter(StatefulSmartContract):
    count: int

    def __init__(self, count: int):
        super().__init__(count)
        self.count = count

    @public
    def increment(self):
        self.count = self.count + 1
`
	result := ParseSource([]byte(source), "Counter.runar.py")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if c.ParentClass != "StatefulSmartContract" {
		t.Errorf("expected parentClass StatefulSmartContract, got %s", c.ParentClass)
	}
	if c.Name != "Counter" {
		t.Errorf("expected name Counter, got %s", c.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Python contract with invalid syntax produces error
// ---------------------------------------------------------------------------

func TestParsePython_InvalidSyntax_Error(t *testing.T) {
	source := `
class (SmartContract):
    pass
`
	result := ParseSource([]byte(source), "bad.runar.py")
	if result.Contract != nil && len(result.Errors) == 0 {
		t.Error("expected errors for invalid Python syntax")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Python snake_case conversion to camelCase
// ---------------------------------------------------------------------------

func TestParsePython_SnakeToCamelConversion(t *testing.T) {
	source := `
from runar import SmartContract, assert_, hash160, Addr, PubKey

class HashCheck(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def check_hash(self, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
`
	result := ParseSource([]byte(source), "HashCheck.runar.py")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}

	// Property: pub_key_hash -> pubKeyHash
	if len(c.Properties) < 1 {
		t.Fatal("expected at least 1 property")
	}
	if c.Properties[0].Name != "pubKeyHash" {
		t.Errorf("expected property name pubKeyHash (camelCase), got %s", c.Properties[0].Name)
	}

	// Method: check_hash -> checkHash
	if len(c.Methods) < 1 {
		t.Fatal("expected at least 1 method")
	}
	if c.Methods[0].Name != "checkHash" {
		t.Errorf("expected method name checkHash (camelCase), got %s", c.Methods[0].Name)
	}
}
