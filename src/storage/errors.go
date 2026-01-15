package storage

import "errors"

var (
	ErrNotFound    = errors.New("storage: not found")
	ErrInvalidCID  = errors.New("storage: invalid cid")
	ErrCIDMismatch = errors.New("storage: cid mismatch")
	ErrImmutable   = errors.New("storage: immutable object mismatch")
)

func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
