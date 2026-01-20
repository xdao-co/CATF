package casconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"xdao.co/catf/storage"
	"xdao.co/catf/storage/casregistry"
)

// Config describes how to open one or more CAS backends via casregistry.
//
// This provides "config-driven" runtime backend selection.
// Callers still need to link desired backend plugins via blank imports.
//
// WritePolicy values:
// - "first" (default): write only to the first backend; reads fall back in order
// - "all": write to all backends and require CID equality (see storage.ReplicatingCAS)
//
// Example:
//
//	{
//	  "write_policy": "all",
//	  "backends": [
//	    {"name":"localfs", "config":{"localfs-dir":"/tmp/cas"}},
//	    {"name":"ipfs", "config":{"ipfs-path":"/tmp/ipfs", "pin":"true"}}
//	  ]
//	}
//
// Note: Config values are backend-specific.
// Each backend may document accepted keys (usually mirroring CLI flag names).
type Config struct {
	WritePolicy string          `json:"write_policy,omitempty"`
	Backends    []BackendConfig `json:"backends"`
}

type BackendConfig struct {
	// Name is the casregistry backend name to open (e.g. "grpc", "localfs", "ipfs").
	Name string `json:"name"`
	// ID is an optional stable alias used for identification and per-backend CID maps.
	// If empty, Name is used.
	ID     string            `json:"id,omitempty"`
	Config map[string]string `json:"config,omitempty"`
}

func LoadFile(path string) (Config, error) {
	var cfg Config
	if path == "" {
		return cfg, errors.New("casconfig: empty config path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if len(c.Backends) == 0 {
		return errors.New("casconfig: at least one backend is required")
	}
	seen := make(map[string]struct{}, len(c.Backends))
	for _, b := range c.Backends {
		if b.Name == "" {
			return errors.New("casconfig: backend name is required")
		}
		id := b.Name
		if b.ID != "" {
			id = b.ID
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("casconfig: duplicate backend id %q", id)
		}
		seen[id] = struct{}{}
	}
	switch c.WritePolicy {
	case "", "first", "all":
		return nil
	default:
		return fmt.Errorf("casconfig: invalid write_policy %q", c.WritePolicy)
	}
}

// Open opens a CAS per config.
//
// If preferredBackend is non-empty, backends are reordered so preferredBackend
// is first (and thus used for writes when WritePolicy=="first").
func (c Config) Open(usage casregistry.Usage, preferredBackend string) (storage.CAS, func() error, error) {
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}

	ordered := append([]BackendConfig(nil), c.Backends...)
	if preferredBackend != "" {
		idx := -1
		for i := range ordered {
			if ordered[i].Name == preferredBackend || ordered[i].ID == preferredBackend {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, nil, fmt.Errorf("casconfig: preferred backend %q not found in config", preferredBackend)
		}
		if idx != 0 {
			b := ordered[idx]
			copy(ordered[1:idx+1], ordered[0:idx])
			ordered[0] = b
		}
	}

	named := make([]storage.NamedCAS, 0, len(ordered))
	closers := make([]func() error, 0, len(ordered))
	for _, b := range ordered {
		cas, closeFn, err := casregistry.OpenWithConfig(b.Name, usage, b.Config)
		if err != nil {
			for i := len(closers) - 1; i >= 0; i-- {
				_ = closers[i]()
			}
			return nil, nil, err
		}
		name := b.Name
		if b.ID != "" {
			name = b.ID
		}
		named = append(named, storage.NamedCAS{Name: name, CAS: cas})
		if closeFn != nil {
			closers = append(closers, closeFn)
		}
	}

	closeAll := func() error {
		var firstErr error
		for i := len(closers) - 1; i >= 0; i-- {
			if err := closers[i](); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}

	if len(named) == 1 {
		return named[0].CAS, closeAll, nil
	}

	switch c.WritePolicy {
	case "", "first":
		adapters := make([]storage.CAS, 0, len(named))
		for _, n := range named {
			adapters = append(adapters, n.CAS)
		}
		return storage.MultiCAS{Adapters: adapters}, closeAll, nil
	case "all":
		return storage.ReplicatingCAS{Backends: named}, closeAll, nil
	default:
		return nil, nil, fmt.Errorf("casconfig: invalid write_policy %q", c.WritePolicy)
	}
}
