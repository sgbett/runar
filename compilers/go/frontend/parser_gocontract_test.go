package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Parse a basic Go contract (P2PKH)
// ---------------------------------------------------------------------------

func TestParseGoContract_P2PKH(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type P2PKH struct {
	runar.SmartContract
	PubKeyHash runar.Addr ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
`
	result := ParseSource([]byte(source), "P2PKH.runar.go")
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
	// Go parser converts PubKeyHash -> pubKeyHash (camelCase)
	if c.Properties[0].Name != "pubKeyHash" {
		t.Errorf("expected property name pubKeyHash, got %s", c.Properties[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Go contract verifies methods and visibility
// ---------------------------------------------------------------------------

func TestParseGoContract_MethodVisibility(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type Checker struct {
	runar.SmartContract
	Target runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *Checker) Verify(a runar.Bigint, b runar.Bigint) {
	runar.Assert(a + b == c.Target)
}
`
	result := ParseSource([]byte(source), "Checker.runar.go")
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
	// Exported (capitalized) Go method -> public
	if m.Visibility != "public" {
		t.Errorf("expected method visibility public, got %s", m.Visibility)
	}
	// Method name should be lowered to camelCase: Verify -> verify
	if m.Name != "verify" {
		t.Errorf("expected method name verify, got %s", m.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Go stateful contract
// ---------------------------------------------------------------------------

func TestParseGoContract_Stateful(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *Counter) Increment() {
	c.Count = c.Count + 1
}
`
	result := ParseSource([]byte(source), "Counter.runar.go")
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
// Test: Parse Go source with no contract struct produces error
// ---------------------------------------------------------------------------

func TestParseGoContract_NoContract_Error(t *testing.T) {
	source := `
package main

type NotAContract struct {
	X int
}
`
	result := ParseSource([]byte(source), "bad.runar.go")
	if result.Contract != nil {
		t.Error("expected nil contract for non-runar struct")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors when no contract found")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Go contract with multiple properties
// ---------------------------------------------------------------------------

func TestParseGoContract_MultipleProperties(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type TwoProps struct {
	runar.SmartContract
	Addr runar.Addr ` + "`" + `runar:"readonly"` + "`" + `
	Key  runar.PubKey ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *TwoProps) Check(x runar.Bigint) {
	runar.Assert(x == 1)
}
`
	result := ParseSource([]byte(source), "TwoProps.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Properties) != 2 {
		t.Fatalf("expected 2 properties, got %d", len(c.Properties))
	}
}
