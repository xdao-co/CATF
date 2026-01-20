package grpccas

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"xdao.co/catf/storage/localfs"
)

func TestGRPCCAS_LocalFS_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cas, err := localfs.New(dir)
	if err != nil {
		t.Fatalf("localfs.New: %v", err)
	}

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
