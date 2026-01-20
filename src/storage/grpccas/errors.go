package grpccas

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"xdao.co/catf/storage"
)

func mapRPC(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	switch st.Code() {
	case codes.NotFound:
		return storage.ErrNotFound
	case codes.InvalidArgument:
		// Server uses InvalidArgument for malformed/undefined CIDs.
		return storage.ErrInvalidCID
	case codes.DataLoss:
		// Server uses DataLoss when bytes do not match the requested CID.
		return storage.ErrCIDMismatch
	default:
		// Best-effort: if the server sent a known storage error message, preserve it.
		switch st.Message() {
		case storage.ErrNotFound.Error():
			return storage.ErrNotFound
		case storage.ErrInvalidCID.Error():
			return storage.ErrInvalidCID
		case storage.ErrCIDMismatch.Error():
			return storage.ErrCIDMismatch
		default:
			return err
		}
	}
}
