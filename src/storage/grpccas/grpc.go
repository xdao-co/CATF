package grpccas

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// CASServer is the server API for the CAS gRPC service.
//
// We intentionally use protobuf well-known wrapper types so this package does
// not require a protoc/codegen toolchain.
//
// Proto definition: cas.proto.
type CASServer interface {
	Put(context.Context, *wrapperspb.BytesValue) (*wrapperspb.StringValue, error)
	Get(context.Context, *wrapperspb.StringValue) (*wrapperspb.BytesValue, error)
	Has(context.Context, *wrapperspb.StringValue) (*wrapperspb.BoolValue, error)
}

// UnimplementedCASServer can be embedded to have forward compatible implementations.
type UnimplementedCASServer struct{}

func (UnimplementedCASServer) Put(context.Context, *wrapperspb.BytesValue) (*wrapperspb.StringValue, error) {
	return nil, status.Error(codes.Unimplemented, "method Put not implemented")
}
func (UnimplementedCASServer) Get(context.Context, *wrapperspb.StringValue) (*wrapperspb.BytesValue, error) {
	return nil, status.Error(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedCASServer) Has(context.Context, *wrapperspb.StringValue) (*wrapperspb.BoolValue, error) {
	return nil, status.Error(codes.Unimplemented, "method Has not implemented")
}

// RegisterCASServer registers the CAS service on a gRPC server.
func RegisterCASServer(s grpc.ServiceRegistrar, srv CASServer) {
	s.RegisterService(&CAS_ServiceDesc, srv)
}

// CASClient is the client API for the CAS gRPC service.
type CASClient interface {
	Put(ctx context.Context, in *wrapperspb.BytesValue, opts ...grpc.CallOption) (*wrapperspb.StringValue, error)
	Get(ctx context.Context, in *wrapperspb.StringValue, opts ...grpc.CallOption) (*wrapperspb.BytesValue, error)
	Has(ctx context.Context, in *wrapperspb.StringValue, opts ...grpc.CallOption) (*wrapperspb.BoolValue, error)
}

type casClient struct{ cc grpc.ClientConnInterface }

func NewCASClient(cc grpc.ClientConnInterface) CASClient { return &casClient{cc: cc} }

func (c *casClient) Put(ctx context.Context, in *wrapperspb.BytesValue, opts ...grpc.CallOption) (*wrapperspb.StringValue, error) {
	out := new(wrapperspb.StringValue)
	err := c.cc.Invoke(ctx, "/xdao.catf.storage.grpccas.v1.CAS/Put", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *casClient) Get(ctx context.Context, in *wrapperspb.StringValue, opts ...grpc.CallOption) (*wrapperspb.BytesValue, error) {
	out := new(wrapperspb.BytesValue)
	err := c.cc.Invoke(ctx, "/xdao.catf.storage.grpccas.v1.CAS/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *casClient) Has(ctx context.Context, in *wrapperspb.StringValue, opts ...grpc.CallOption) (*wrapperspb.BoolValue, error) {
	out := new(wrapperspb.BoolValue)
	err := c.cc.Invoke(ctx, "/xdao.catf.storage.grpccas.v1.CAS/Has", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func _CAS_Put_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(wrapperspb.BytesValue)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CASServer).Put(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/xdao.catf.storage.grpccas.v1.CAS/Put"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CASServer).Put(ctx, req.(*wrapperspb.BytesValue))
	}
	return interceptor(ctx, in, info, handler)
}

func _CAS_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(wrapperspb.StringValue)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CASServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/xdao.catf.storage.grpccas.v1.CAS/Get"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CASServer).Get(ctx, req.(*wrapperspb.StringValue))
	}
	return interceptor(ctx, in, info, handler)
}

func _CAS_Has_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(wrapperspb.StringValue)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CASServer).Has(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/xdao.catf.storage.grpccas.v1.CAS/Has"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CASServer).Has(ctx, req.(*wrapperspb.StringValue))
	}
	return interceptor(ctx, in, info, handler)
}

// CAS_ServiceDesc is the grpc.ServiceDesc for CAS service.
var CAS_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "xdao.catf.storage.grpccas.v1.CAS",
	HandlerType: (*CASServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Put", Handler: _CAS_Put_Handler},
		{MethodName: "Get", Handler: _CAS_Get_Handler},
		{MethodName: "Has", Handler: _CAS_Has_Handler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cas.proto",
}
