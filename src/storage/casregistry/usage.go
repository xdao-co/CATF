package casregistry
package casregistry

// Usage restricts which programs should accept a given backend.




















func (u Usage) allows(want Usage) bool { return u&want != 0 })	UsageDaemon	UsageCLI Usage = 1 << iotaconst (type Usage uint8// Note: Usage is a bitmask.//// - grpc client: UsageCLI// - localfs: UsageCLI | UsageDaemon// Examples://// Usage lets a backend opt into specific binaries (e.g. cascli vs casgrpcd).//// (often as a blank import).// init() and then be enabled in a binary by importing the backend package// In Go, "plugins" are linked at build-time. A backend can register itself via//
