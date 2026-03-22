package frontend

import "fmt"

// Severity represents the level of a compiler diagnostic.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Diagnostic represents a single compiler diagnostic (error or warning).
type Diagnostic struct {
	Message  string
	Loc      *SourceLocation
	Severity Severity
}

// MakeDiagnostic creates a diagnostic with the given message, severity, and optional location.
func MakeDiagnostic(message string, severity Severity, loc *SourceLocation) Diagnostic {
	return Diagnostic{Message: message, Severity: severity, Loc: loc}
}

// FormatMessage returns the diagnostic message with optional file:line:column prefix.
func (d Diagnostic) FormatMessage() string {
	if d.Loc != nil && d.Loc.File != "" {
		if d.Loc.Column > 0 {
			return fmt.Sprintf("%s:%d:%d: %s", d.Loc.File, d.Loc.Line, d.Loc.Column, d.Message)
		}
		return fmt.Sprintf("%s:%d: %s", d.Loc.File, d.Loc.Line, d.Message)
	}
	return d.Message
}
