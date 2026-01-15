package ipfs_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"xdao.co/catf/storage"
	"xdao.co/catf/storage/ipfs"
	"xdao.co/catf/storage/testkit"
)

func TestIPFS_CAS_Conformance(t *testing.T) {
	if os.Getenv("XDAO_TEST_IPFS") != "1" {
		t.Skip("set XDAO_TEST_IPFS=1 to run IPFS CAS conformance")
	}
	if _, err := exec.LookPath("ipfs"); err != nil {
		t.Skip("ipfs binary not found on PATH")
	}

	repoDir := filepath.Join(t.TempDir(), "ipfsrepo")
	env := append(os.Environ(), "IPFS_PATH="+repoDir)

	initCmd := exec.Command("ipfs", "init")
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Skipf("ipfs init failed: %v: %s", err, string(out))
	}

	testkit.RunCASConformance(t, func(t *testing.T) storage.CAS {
		return ipfs.New(ipfs.Options{Env: env})
	})
}
