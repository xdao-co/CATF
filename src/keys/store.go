package keys

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// KeyStore represents a simple local-first key management system.
//
// EXPERIMENTAL (GAP-07): this filesystem-backed storage surface is not part of the
// stable protocol core API and may change in MINOR releases.
//
// Features:
// - Supports Ed25519 keys only
// - Stores keys on the local filesystem
// - Generates deterministic subkeys based on roles
// - No external dependencies
//
// This package is designed to be straightforward and explicit.
type KeyStore struct {
	Directory string
}

type KeyEntry struct {
	Identifier  string
	Permissions []string
}

func GetDefaultDirectory() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".xdao", "keys"), nil
}

func CreateKeyStore(directory string) (*KeyStore, error) {
	if directory == "" {
		var err error
		directory, err = GetDefaultDirectory()
		if err != nil {
			return nil, err
		}
	}
	return &KeyStore{Directory: directory}, nil
}

func (ks *KeyStore) getRootKeyFilePath(identifier string) string {
	return filepath.Join(ks.Directory, identifier, "root.key")
}

func (ks *KeyStore) getRoleKeyFilePath(identifier, role string) string {
	return filepath.Join(ks.Directory, identifier, "roles", role+".key")
}

func CheckKeyName(identifier string) error {
	if identifier == "" {
		return errors.New("identifier cannot be empty")
	}
	for _, char := range identifier {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return fmt.Errorf("invalid character %q in identifier", char)
	}
	return nil
}

func CheckRole(role string) error {
	if role == "" {
		return errors.New("role cannot be empty")
	}
	for _, char := range role {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return fmt.Errorf("invalid character %q in role", char)
	}
	return nil
}

func ParseSeedHex(seedHex string) ([]byte, error) {
	seedHex = strings.TrimSpace(seedHex)
	seedHex = strings.TrimPrefix(seedHex, "0x")
	data, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	if len(data) != ed25519.SeedSize {
		return nil, fmt.Errorf("expected seed length of %d bytes, got %d", ed25519.SeedSize, len(data))
	}
	return data, nil
}

func (ks *KeyStore) saveSeedToFile(filePath string, seed []byte, overwrite bool) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("expected seed length of %d bytes", ed25519.SeedSize)
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE
	if overwrite {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	file, err := os.OpenFile(filePath, flags, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(hex.EncodeToString(seed) + "\n"); err != nil {
		return err
	}
	return file.Close()
}

func (ks *KeyStore) loadSeedFromFile(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ParseSeedHex(strings.TrimSpace(string(data)))
}

func (ks *KeyStore) InitializeRootKey(identifier string, seed []byte, overwrite bool) (issuerKey string, filePath string, err error) {
	if err := CheckKeyName(identifier); err != nil {
		return "", "", err
	}
	filePath = ks.getRootKeyFilePath(identifier)
	if err := ks.saveSeedToFile(filePath, seed, overwrite); err != nil {
		return "", "", err
	}
	return GenerateIssuerKeyFromSeed(seed), filePath, nil
}

func (ks *KeyStore) DeriveKeyFromRole(from, role string, overwrite bool) (issuerKey string, filePath string, err error) {
	if err := CheckKeyName(from); err != nil {
		return "", "", err
	}
	if err := CheckRole(role); err != nil {
		return "", "", err
	}
	rootSeed, err := ks.loadSeedFromFile(ks.getRootKeyFilePath(from))
	if err != nil {
		return "", "", err
	}
	roleSeed, err := DeriveRoleSeed(rootSeed, role)
	if err != nil {
		return "", "", err
	}
	filePath = ks.getRoleKeyFilePath(from, role)
	if err := ks.saveSeedToFile(filePath, roleSeed, overwrite); err != nil {
		return "", "", err
	}
	return GenerateIssuerKeyFromSeed(roleSeed), filePath, nil
}

func (ks *KeyStore) ExportKey(identifier string, role string) (string, error) {
	if err := CheckKeyName(identifier); err != nil {
		return "", err
	}
	var seed []byte
	var err error
	if role == "" {
		seed, err = ks.loadSeedFromFile(ks.getRootKeyFilePath(identifier))
	} else {
		if err := CheckRole(role); err != nil {
			return "", err
		}
		seed, err = ks.loadSeedFromFile(ks.getRoleKeyFilePath(identifier, role))
	}
	if err != nil {
		return "", err
	}
	return GenerateIssuerKeyFromSeed(seed), nil
}

func (ks *KeyStore) LoadSeed(seedHex, signerName, signerRole, keyFile string) ([]byte, error) {
	if seedHex != "" {
		return ParseSeedHex(seedHex)
	}
	if keyFile != "" {
		return ks.loadSeedFromFile(keyFile)
	}
	if signerName != "" {
		if err := CheckKeyName(signerName); err != nil {
			return nil, err
		}
		if signerRole == "" {
			return ks.loadSeedFromFile(ks.getRootKeyFilePath(signerName))
		}
		if err := CheckRole(signerRole); err != nil {
			return nil, err
		}
		return ks.loadSeedFromFile(ks.getRoleKeyFilePath(signerName, signerRole))
	}
	return nil, errors.New("no signer provided")
}

func (ks *KeyStore) ListKeys() ([]KeyEntry, error) {
	entries, err := os.ReadDir(ks.Directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var identifiers []string
	for _, entry := range entries {
		if entry.IsDir() {
			identifiers = append(identifiers, entry.Name())
		}
	}
	sort.Strings(identifiers)

	var result []KeyEntry
	for _, identifier := range identifiers {
		rolesDir := filepath.Join(ks.Directory, identifier, "roles")
		roleEntries, rerr := os.ReadDir(rolesDir)
		var roles []string
		if rerr == nil {
			for _, roleEntry := range roleEntries {
				if roleEntry.IsDir() {
					continue
				}
				if strings.HasSuffix(roleEntry.Name(), ".key") {
					roles = append(roles, strings.TrimSuffix(roleEntry.Name(), ".key"))
				}
			}
			sort.Strings(roles)
		}
		result = append(result, KeyEntry{Identifier: identifier, Permissions: roles})
	}
	return result, nil
}
