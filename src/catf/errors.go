package catf

import "errors"

// Kind is a stable category for programmatic error handling.
//
// These categories are intended to remain stable across versions.
// Callers should branch on Kind/RuleID rather than matching error strings.
//
// NOTE: Error() strings are intentionally kept human-readable and may evolve.
// Use errors.As to extract *Error for structured handling.
type Kind string

const (
	KindParse      Kind = "Parse"
	KindCanonical  Kind = "Canonical"
	KindValidation Kind = "Validation"
	KindRender     Kind = "Render"
	KindCrypto     Kind = "Crypto"
	KindCID        Kind = "CID"
	KindInternal   Kind = "Internal"
)

// Error is the library's structured error type.
//
// RuleID is a stable identifier (e.g., CATF-STR-001, CATF-CANON-004, CATF-VAL-101)
// that names the violated invariant or validation rule.
//
// Message is intended for humans; do not match on it.
type Error struct {
	Kind    Kind
	RuleID  string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func newError(kind Kind, ruleID, msg string) error {
	return &Error{Kind: kind, RuleID: ruleID, Message: msg}
}

func wrapError(kind Kind, ruleID, msg string, cause error) error {
	if cause == nil {
		return newError(kind, ruleID, msg)
	}
	return &Error{Kind: kind, RuleID: ruleID, Message: msg, Cause: cause}
}

// IsKind reports whether err is (or wraps) a *Error with the given Kind.
func IsKind(err error, kind Kind) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Kind == kind
}

// RuleID returns the stable RuleID for a structured error, or "" if unknown.
func RuleID(err error) string {
	var e *Error
	if !errors.As(err, &e) {
		return ""
	}
	return e.RuleID
}
