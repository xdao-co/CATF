package casregistry

import (
	"flag"
	"fmt"
	"sort"
	"sync"

	"xdao.co/catf/storage"
)

// Backend is a build-time plugin that can open a storage.CAS implementation.
//
// Backends typically register themselves in init():
//
//	casregistry.MustRegister(casregistry.Backend{ ... })
//
// The binary must import the backend package for registration to occur.
type Backend struct {
	Name        string
	Description string
	Usage       Usage

	// RegisterFlags adds backend-specific flags to fs.
	// It must be safe to call exactly once per process.
	RegisterFlags func(fs *flag.FlagSet)

	// Open constructs the CAS using values parsed into flags registered by RegisterFlags.
	// It returns an optional close function.
	Open func() (storage.CAS, func() error, error)
}

var (
	mu       sync.RWMutex
	backends = map[string]Backend{}
)

// Register registers a backend.
func Register(b Backend) error {
	if b.Name == "" {
		return fmt.Errorf("casregistry: backend name is required")
	}
	if b.RegisterFlags == nil {
		return fmt.Errorf("casregistry: backend %q missing RegisterFlags", b.Name)
	}
	if b.Open == nil {
		return fmt.Errorf("casregistry: backend %q missing Open", b.Name)
	}
	if b.Usage == 0 {
		return fmt.Errorf("casregistry: backend %q missing Usage", b.Name)
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := backends[b.Name]; exists {
		return fmt.Errorf("casregistry: backend %q already registered", b.Name)
	}
	backends[b.Name] = b
	return nil
}

// MustRegister is like Register but panics on error.
func MustRegister(b Backend) {
	if err := Register(b); err != nil {
		panic(err)
	}
}

// List returns backends matching usage, sorted by name.
func List(usage Usage) []Backend {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Backend, 0, len(backends))
	for _, b := range backends {
		if b.Usage.allows(usage) {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns backend names matching usage, sorted.
func Names(usage Usage) []string {
	bs := List(usage)
	n := make([]string, 0, len(bs))
	for _, b := range bs {
		n = append(n, b.Name)
	}
	return n
}

// RegisterFlags registers flags for all backends matching usage.
//
// This enables single-pass flag parsing (Go's flag package rejects unknown flags).
func RegisterFlags(fs *flag.FlagSet, usage Usage) {
	for _, b := range List(usage) {
		b.RegisterFlags(fs)
	}
}

// Open opens the named backend if it exists and matches usage.
func Open(name string, usage Usage) (storage.CAS, func() error, error) {
	mu.RLock()
	b, ok := backends[name]
	mu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("unknown backend %q", name)
	}
	if !b.Usage.allows(usage) {
		return nil, nil, fmt.Errorf("backend %q not supported in this binary", name)
	}
	return b.Open()
}
