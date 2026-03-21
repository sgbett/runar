package compiler

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
}

func mergeOptions(opts []CompileOptions) CompileOptions {
	if len(opts) == 0 {
		return CompileOptions{}
	}
	return opts[0]
}
