package compiler

import "github.com/icellan/runar/compilers/go/ir"

// CompileOptions controls optional compiler behavior.
type CompileOptions struct {
	// DisableConstantFolding skips the ANF constant folding pass.
	// Default (false) enables constant folding.
	DisableConstantFolding bool

	// ParseOnly stops compilation after the parse pass (pass 1).
	ParseOnly bool

	// ValidateOnly stops compilation after the validate pass (pass 2).
	ValidateOnly bool

	// TypecheckOnly stops compilation after the type-check pass (pass 3).
	TypecheckOnly bool

	// ConstructorArgs bakes property values into the locking script,
	// replacing OP_0 placeholders with real push data.
	// Keys are property names; values are string (hex bytes), int64, or bool.
	ConstructorArgs map[string]interface{}
}

func mergeOptions(opts []CompileOptions) CompileOptions {
	if len(opts) == 0 {
		return CompileOptions{}
	}
	return opts[0]
}

// applyConstructorArgs bakes constructor arg values into ANF property initialValues.
// This replaces OP_0 placeholders with real push data in the emitted script.
func applyConstructorArgs(program *ir.ANFProgram, args map[string]interface{}) {
	if len(args) == 0 || program == nil {
		return
	}
	for i := range program.Properties {
		if v, ok := args[program.Properties[i].Name]; ok {
			program.Properties[i].InitialValue = v
		}
	}
}
