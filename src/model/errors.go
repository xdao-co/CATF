package model

import "fmt"

type ErrorCode string

const (
	ErrInvalidRequest ErrorCode = "INVALID_REQUEST"
	ErrInvalidCID     ErrorCode = "INVALID_CID"
	ErrMissingCAS     ErrorCode = "MISSING_CAS"
	ErrNotFound       ErrorCode = "NOT_FOUND"
	ErrCIDMismatch    ErrorCode = "CID_MISMATCH"
	ErrInternal       ErrorCode = "INTERNAL"
)

// CodedError is a stable error with a machine-readable code and a human message.
type CodedError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e *CodedError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewError(code ErrorCode, message string) *CodedError {
	return &CodedError{Code: code, Message: message}
}
