package grpccas

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
)

type memCAS struct {
	mu sync.RWMutex
	m  map[string][]byte
}

func newMemCAS() *memCAS {
	return &memCAS{m: map[string][]byte{}}
}

func (c *memCAS) Put(b []byte) (cid.Cid, error) {
	id, err := cidutil.CIDv1RawSHA256CID(b)
	if err != nil {
		return cid.Undef, err
	}
	if !id.Defined() {
		return cid.Undef, storage.ErrInvalidCID
	}
	k := id.String()

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.m[k]; ok {
		if string(existing) != string(b) {
			return cid.Undef, storage.ErrImmutable
		}
		return id, nil
	}
	c.m[k] = append([]byte(nil), b...)
	return id, nil
}

func (c *memCAS) Get(id cid.Cid) ([]byte, error) {
	if !id.Defined() {
		return nil, storage.ErrInvalidCID
	}
	k := id.String()
	c.mu.RLock()
	b, ok := c.m[k]
	c.mu.RUnlock()
	if !ok {
		return nil, storage.ErrNotFound
	}
	out := append([]byte(nil), b...)
	got, err := cidutil.CIDv1RawSHA256CID(out)
	if err != nil {
		return nil, err
	}
	if got != id {
		return nil, storage.ErrCIDMismatch
	}
	return out, nil
}

func (c *memCAS) Has(id cid.Cid) bool {
	if !id.Defined() {
		return false
	}
	k := id.String()
	c.mu.RLock()
	_, ok := c.m[k]
	c.mu.RUnlock()
	return ok
}

func TestGRPCCAS_MemCAS_RoundTrip(t *testing.T) {
	cas := newMemCAS()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	RegisterCASServer(srv, &Server{CAS: cas})

	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	dialer := func(ctx context.Context, s string) (net.Conn, error) { return lis.Dial() }
	cc, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer cc.Close()

	client := &Client{cc: cc, client: NewCASClient(cc), Timeout: 2 * time.Second}

	payload := []byte("hello grpccas")
	id, err := client.Put(payload)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !id.Defined() {
		t.Fatalf("expected defined CID")
	}
	if !client.Has(id) {
		t.Fatalf("Has: expected true")
	}
	got, err := client.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}
