# Extending gRPC CAS Storage (Pluggable Modules)

This guide explains how to implement a **pluggable CAS module** and expose it over the repo’s **CAS gRPC** protocol.

The project’s “plugin framework” for CAS is deliberately small:

- A **single Go interface**: `xdao.co/catf/storage.CAS`
- Optional transport wrappers:
  - Server wrapper: `xdao.co/catf/storage/grpccas.Server` (exposes any `storage.CAS` over gRPC)
  - Client wrapper: `xdao.co/catf/storage/grpccas.Client` (implements `storage.CAS` by calling a remote gRPC service)

This keeps the core resolver deterministic and storage-provider agnostic.

---

## 1) What “pluggable” means here

A CAS backend is “pluggable” if it implements:

```go
// src/storage/cas.go
package storage

type CAS interface {
  Put(bytes []byte) (cid.Cid, error)
  Get(id cid.Cid) ([]byte, error)
  Has(id cid.Cid) bool
}
```

If you satisfy that interface, you can:

- Use the backend directly in Go (`model.ResolveAndRenderCROF`, `model.ResolveResult`, etc.)
- Wrap it behind the CAS gRPC server (`grpccas.Server`)
- Compose it with other backends using `storage.MultiCAS`

---

## 2) CAS contract requirements (non-negotiable)

Your backend MUST follow these semantics:

- `Put` MUST be idempotent.
- Stored objects MUST be immutable.
- CIDs MUST be derived from the bytes written.
- `Get` MUST return `storage.ErrNotFound` when the CID is absent.
- `Get` SHOULD validate returned bytes hash to the requested CID and return `storage.ErrCIDMismatch` on mismatch.

Note: CATF/CROF workflows assume the repo’s CID contract (`CIDv1 raw + sha2-256`) when using the reference codepaths.

---

## 3) Implement a new CAS backend (example skeleton)

Create a new package (either inside this repo or in your own Go module).

Example: `xdao.co/catf/storage/mycas` (your code):

```go
package mycas

import (
  "sync"

  "github.com/ipfs/go-cid"

  "xdao.co/catf/cidutil"
  "xdao.co/catf/storage"
)

type CAS struct {
  mu sync.RWMutex
  m  map[string][]byte
}

func New() *CAS {
  return &CAS{m: make(map[string][]byte)}
}

func (c *CAS) Put(b []byte) (cid.Cid, error) {
  id, err := cidutil.CIDv1RawSHA256CID(b)
  if err != nil {
    return cid.Undef, err
  }
  if !id.Defined() {
    return cid.Undef, storage.ErrInvalidCID
  }

  c.mu.Lock()
  defer c.mu.Unlock()

  k := id.String()
  if existing, ok := c.m[k]; ok {
    // Idempotent + immutable: same CID must map to identical bytes.
    if string(existing) != string(b) {
      return cid.Undef, storage.ErrImmutable
    }
    return id, nil
  }

  // Store a copy; treat as immutable.
  bb := append([]byte(nil), b...)
  c.m[k] = bb
  return id, nil
}

func (c *CAS) Get(id cid.Cid) ([]byte, error) {
  if !id.Defined() {
    return nil, storage.ErrInvalidCID
  }

  c.mu.RLock()
  b, ok := c.m[id.String()]
  c.mu.RUnlock()
  if !ok {
    return nil, storage.ErrNotFound
  }

  // Validate and return a copy.
  got, err := cidutil.CIDv1RawSHA256CID(b)
  if err != nil {
    return nil, err
  }
  if got.String() != id.String() {
    return nil, storage.ErrCIDMismatch
  }
  return append([]byte(nil), b...), nil
}

func (c *CAS) Has(id cid.Cid) bool {
  if !id.Defined() {
    return false
  }
  c.mu.RLock()
  _, ok := c.m[id.String()]
  c.mu.RUnlock()
  return ok
}
```

If you add this inside the repo, consider adding `storage/testkit` conformance coverage.

---

## 4) Expose your backend over CAS gRPC

### Option A (recommended): wrap it in-process

In your server process:

```go
lis, _ := net.Listen("tcp", "127.0.0.1:7777")

backend := mycas.New()

s := grpc.NewServer()
grpccas.RegisterCASServer(s, &grpccas.Server{CAS: backend})
_ = s.Serve(lis)
```

### Option B: use the reference daemon

This repo includes a small reference daemon that exposes either LocalFS or IPFS over gRPC:

- binary: `./bin/xdao-casgrpcd`
- source: `src/cmd/xdao-casgrpcd`

Example:

```sh
./bin/xdao-casgrpcd --listen 127.0.0.1:7777 --backend localfs --localfs-dir /tmp/xdao-cas
```

---

## 5) Consume a remote backend as a local `storage.CAS`

Anywhere you accept a `storage.CAS`, you can dial the gRPC CAS service and use the returned client:

```go
cas, err := grpccas.Dial("127.0.0.1:7777", grpccas.DialOptions{})
if err != nil { /* ... */ }
defer cas.Close()

// cas implements storage.CAS.
id, _ := cas.Put([]byte("hello"))
_ = id
```

---

## 6) Verification: are LocalFS and IPFS “plugins”?

Yes.

- LocalFS backend lives in `xdao.co/catf/storage/localfs` and implements `storage.CAS`.
- IPFS backend lives in `xdao.co/catf/storage/ipfs` and implements `storage.CAS`.

Because they implement the common interface, they are interchangeable in:

- the resolver (Go integration)
- the CAS gRPC server wrapper (`grpccas.Server`)
- the CAS gRPC client wrapper (`grpccas.Client`)
- CLI tooling (`xdao-cascli`, `xdao-casgrpcd`) by selecting the backend

---

## 7) End-to-end “CAS compliant storage” demos

From the repo root:

- LocalFS via gRPC:

```sh
make walkthrough-grpc-localfs
```

- IPFS via gRPC (requires Kubo `ipfs`):

```sh
make walkthrough-grpc-ipfs
```
