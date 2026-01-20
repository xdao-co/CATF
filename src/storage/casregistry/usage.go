package casregistry

// Usage restricts which programs should accept a given backend.

// In Go, "plugins" are linked at build time: a backend registers itself via init(),
// and is enabled in a binary by importing the backend package (often as a blank import).
type Usage uint8

const (
	// UsageCLI indicates the backend should be available in CLI programs (e.g. cascli).
	UsageCLI Usage = 1 << iota
	// UsageDaemon indicates the backend should be available in long-running daemons (e.g. casgrpcd).
	UsageDaemon
)

func (u Usage) allows(want Usage) bool { return u&want != 0 }
