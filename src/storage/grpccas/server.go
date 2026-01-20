package grpccas

import (
	"context"

	"github.com/ipfs/go-cid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
)

// Server exposes a storage.CAS over the CAS gRPC service.
type Server struct {
	UnimplementedCASServer
	CAS storage.CAS
}

func (s *Server) Put(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.StringValue, error) {
	_ = ctx
	if s == nil || s.CAS == nil {
		return nil, status.Error(codes.FailedPrecondition, "missing CAS")
	}
	b := in.GetValue()
	// Enforce the repo's CID contract on the server side too.
	expected, err := cidutil.CIDv1RawSHA256CID(b)
	if err != nil {
		return nil, status.Error(codes.Internal, "cid computation failed")
	}
	id, err := s.CAS.Put(b)
	if err != nil {
		return nil, mapErr(err)
	}
	if id.String() != expected.String() {
		return nil, status.Error(codes.DataLoss, storage.ErrCIDMismatch.Error())
	}
	return wrapperspb.String(id.String()), nil
}

func (s *Server) Get(ctx context.Context, in *wrapperspb.StringValue) (*wrapperspb.BytesValue, error) {
	_ = ctx
	if s == nil || s.CAS == nil {
		return nil, status.Error(codes.FailedPrecondition, "missing CAS")
	}
	id, err := cid.Decode(in.GetValue())
	if err != nil || !id.Defined() {
		return nil, status.Error(codes.InvalidArgument, storage.ErrInvalidCID.Error())
	}
	b, err := s.CAS.Get(id)
	if err != nil {
		return nil, mapErr(err)
	}
	got, err := cidutil.CIDv1RawSHA256CID(b)
	if err != nil {
		return nil, status.Error(codes.Internal, "cid computation failed")
	}
	if got.String() != id.String() {
		return nil, status.Error(codes.DataLoss, storage.ErrCIDMismatch.Error())
	}
	return wrapperspb.Bytes(b), nil
}

func (s *Server) Has(ctx context.Context, in *wrapperspb.StringValue) (*wrapperspb.BoolValue, error) {
	_ = ctx
	if s == nil || s.CAS == nil {
		return nil, status.Error(codes.FailedPrecondition, "missing CAS")
	}
	id, err := cid.Decode(in.GetValue())
	if err != nil || !id.Defined() {
		return nil, status.Error(codes.InvalidArgument, storage.ErrInvalidCID.Error())
	}
	return wrapperspb.Bool(s.CAS.Has(id)), nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case err == storage.ErrNotFound:
		return status.Error(codes.NotFound, err.Error())
	case err == storage.ErrInvalidCID:
		return status.Error(codes.InvalidArgument, err.Error())
	case err == storage.ErrCIDMismatch:
		return status.Error(codes.DataLoss, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
