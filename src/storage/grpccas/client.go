package grpccas

import (
	"context"
	"time"

	"github.com/ipfs/go-cid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
)

// Client implements storage.CAS over a CAS gRPC service.
type Client struct {
	cc     *grpc.ClientConn
	client CASClient

	// Timeout applies per RPC when non-zero.
	Timeout time.Duration
}

type DialOptions struct {
	// Timeout applies to the initial dial when non-zero.
	Timeout time.Duration

	// MaxMsgBytes sets both send/recv max sizes when non-zero.
	MaxMsgBytes int
}

func Dial(target string, opts DialOptions) (*Client, error) {
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if opts.MaxMsgBytes > 0 {
		dialOpts = append(dialOpts,
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(opts.MaxMsgBytes),
				grpc.MaxCallSendMsgSize(opts.MaxMsgBytes),
			),
		)
	}

	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	cc, err := grpc.DialContext(ctx, target, dialOpts...)
	if err != nil {
		return nil, err
	}
	return &Client{cc: cc, client: NewCASClient(cc), Timeout: 0}, nil
}

func (c *Client) Close() error {
	if c == nil || c.cc == nil {
		return nil
	}
	return c.cc.Close()
}

func (c *Client) Put(data []byte) (cid.Cid, error) {
	if c == nil || c.client == nil {
		return cid.Undef, storage.ErrNotFound
	}
	expected, err := cidutil.CIDv1RawSHA256CID(data)
	if err != nil {
		return cid.Undef, err
	}

	ctx, cancel := c.ctx()
	defer cancel()

	reply, err := c.client.Put(ctx, wrapperspb.Bytes(data))
	if err != nil {
		return cid.Undef, mapRPC(err)
	}
	id, err := cid.Decode(reply.GetValue())
	if err != nil || !id.Defined() {
		return cid.Undef, storage.ErrInvalidCID
	}
	if id.String() != expected.String() {
		return cid.Undef, storage.ErrCIDMismatch
	}
	return id, nil
}

func (c *Client) Get(id cid.Cid) ([]byte, error) {
	if !id.Defined() {
		return nil, storage.ErrInvalidCID
	}
	ctx, cancel := c.ctx()
	defer cancel()

	reply, err := c.client.Get(ctx, wrapperspb.String(id.String()))
	if err != nil {
		return nil, mapRPC(err)
	}
	b := reply.GetValue()
	got, err := cidutil.CIDv1RawSHA256CID(b)
	if err != nil {
		return nil, err
	}
	if got.String() != id.String() {
		return nil, storage.ErrCIDMismatch
	}
	return b, nil
}

func (c *Client) Has(id cid.Cid) bool {
	if !id.Defined() {
		return false
	}
	ctx, cancel := c.ctx()
	defer cancel()

	reply, err := c.client.Has(ctx, wrapperspb.String(id.String()))
	if err != nil {
		return false
	}
	return reply.GetValue()
}

func (c *Client) ctx() (context.Context, context.CancelFunc) {
	if c.Timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), c.Timeout)
}
