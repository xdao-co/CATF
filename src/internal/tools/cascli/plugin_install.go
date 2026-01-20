package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type pluginSpec struct {
	Name   string
	Owner  string
	Repo   string
	Binary string
}

var knownPlugins = map[string]pluginSpec{
	"ipfs": {
		Name:   "ipfs",
		Owner:  "xdao-co",
		Repo:   "CATF-ipfs",
		Binary: "xdao-casgrpcd-ipfs",
	},
	"localfs": {
		Name:   "localfs",
		Owner:  "xdao-co",
		Repo:   "CATF-localfs",
		Binary: "xdao-casgrpcd-localfs",
	},
}

func cmdPlugin(args []string, out io.Writer, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: cascli plugin <subcommand> ...")
		fmt.Fprintln(errOut, "subcommands: install")
		return 2
	}
	switch args[0] {
	case "install":
		return cmdPluginInstall(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown plugin subcommand: %s\n", args[0])
		return 2
	}
}

type githubRelease struct {
	TagName string               `json:"tag_name"`
	Assets  []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func cmdPluginInstall(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("plugin install", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var pluginName string
	var version string
	var installDir string
	var goos string
	var goarch string
	var overwrite bool
	var token string
	var repoOverride string
	var binaryOverride string
	var noVerify bool

	fs.StringVar(&pluginName, "plugin", "", "Plugin to install: localfs|ipfs")
	fs.StringVar(&version, "version", "", "Release tag to install (e.g. v1.2.3). If empty, installs latest.")
	fs.StringVar(&installDir, "install-dir", "", "Install directory (default ~/.local/bin)")
	fs.StringVar(&goos, "os", runtime.GOOS, "Target OS (goos)")
	fs.StringVar(&goarch, "arch", runtime.GOARCH, "Target arch (goarch)")
	fs.BoolVar(&overwrite, "overwrite", false, "Overwrite if the destination binary already exists")
	fs.StringVar(&token, "github-token", "", "GitHub token (optional; defaults to GITHUB_TOKEN env var)")
	fs.StringVar(&repoOverride, "repo", "", "Override repo as owner/name (advanced)")
	fs.StringVar(&binaryOverride, "binary", "", "Override binary name (advanced)")
	fs.BoolVar(&noVerify, "no-verify", false, "Skip checksum verification")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "usage: cascli plugin install --plugin localfs|ipfs [flags]")
		return 2
	}
	if pluginName == "" {
		fmt.Fprintln(errOut, "missing --plugin")
		return 2
	}
	if installDir == "" {
		installDir = defaultInstallDir()
	}
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if goos == "windows" {
		fmt.Fprintln(errOut, "windows is not supported by current plugin releases")
		return 2
	}

	spec, ok := knownPlugins[pluginName]
	if !ok {
		fmt.Fprintf(errOut, "unknown plugin %q (supported: localfs, ipfs)\n", pluginName)
		return 2
	}
	owner := spec.Owner
	repo := spec.Repo
	binary := spec.Binary
	if repoOverride != "" {
		parts := strings.Split(repoOverride, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			fmt.Fprintln(errOut, "--repo must be in the form owner/name")
			return 2
		}
		owner, repo = parts[0], parts[1]
	}
	if binaryOverride != "" {
		binary = binaryOverride
	}

	assetBase := fmt.Sprintf("%s_%s_%s.tar.gz", binary, goos, goarch)
	checksumName := assetBase + ".sha256"
	apiURL := githubReleaseAPIURL(owner, repo, version)

	rel, err := fetchGitHubRelease(apiURL, token)
	if err != nil {
		fmt.Fprintf(errOut, "fetch release: %v\n", err)
		return 1
	}
	if version == "" {
		version = rel.TagName
	}

	tarURL, ok := findAssetURL(rel.Assets, assetBase)
	if !ok {
		fmt.Fprintf(errOut, "release %s missing asset %q\n", version, assetBase)
		return 1
	}
	shaURL, shaOK := findAssetURL(rel.Assets, checksumName)
	if !shaOK && !noVerify {
		fmt.Fprintf(errOut, "release %s missing checksum asset %q (use --no-verify to skip)\n", version, checksumName)
		return 1
	}

	if err := os.MkdirAll(installDir, 0o755); err != nil {
		fmt.Fprintf(errOut, "mkdir %s: %v\n", installDir, err)
		return 1
	}
	destPath := filepath.Join(installDir, binary)
	if !overwrite {
		if _, err := os.Stat(destPath); err == nil {
			fmt.Fprintf(errOut, "destination exists: %s (use --overwrite)\n", destPath)
			return 2
		}
	}

	client := &http.Client{Timeout: 5 * time.Minute}

	var expectedSHA256 string
	if !noVerify {
		b, err := downloadBytes(client, shaURL, token)
		if err != nil {
			fmt.Fprintf(errOut, "download checksum: %v\n", err)
			return 1
		}
		expectedSHA256, err = parseSHA256File(string(b))
		if err != nil {
			fmt.Fprintf(errOut, "parse checksum: %v\n", err)
			return 1
		}
	}

	tarGzBytes, err := downloadBytes(client, tarURL, token)
	if err != nil {
		fmt.Fprintf(errOut, "download artifact: %v\n", err)
		return 1
	}
	if !noVerify {
		got := sha256.Sum256(tarGzBytes)
		gotHex := hex.EncodeToString(got[:])
		if !strings.EqualFold(gotHex, expectedSHA256) {
			fmt.Fprintf(errOut, "checksum mismatch for %s: got %s want %s\n", assetBase, gotHex, expectedSHA256)
			return 1
		}
	}

	expectedInnerName := fmt.Sprintf("%s_%s_%s", binary, goos, goarch)
	binBytes, err := extractSingleFileFromTarGz(tarGzBytes, expectedInnerName)
	if err != nil {
		fmt.Fprintf(errOut, "extract: %v\n", err)
		return 1
	}

	tmpPath := destPath + ".tmp"
	if err := os.WriteFile(tmpPath, binBytes, 0o755); err != nil {
		fmt.Fprintf(errOut, "write %s: %v\n", tmpPath, err)
		return 1
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		fmt.Fprintf(errOut, "install %s: %v\n", destPath, err)
		return 1
	}

	_, _ = fmt.Fprintf(out, "installed %s (%s) to %s\n", pluginName, version, destPath)
	return 0
}

func defaultInstallDir() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return "."
	}
	return filepath.Join(h, ".local", "bin")
}

func githubReleaseAPIURL(owner, repo, version string) string {
	if version == "" {
		return fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	}
	return fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, version)
}

func fetchGitHubRelease(url string, token string) (*githubRelease, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "xdao-cascli")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("github api %s: %s (%s)", url, resp.Status, strings.TrimSpace(string(b)))
	}
	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("missing tag_name in GitHub release")
	}
	return &rel, nil
}

func findAssetURL(assets []githubReleaseAsset, name string) (string, bool) {
	for _, a := range assets {
		if a.Name == name {
			return a.BrowserDownloadURL, true
		}
	}
	return "", false
}

func downloadBytes(client *http.Client, url string, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xdao-cascli")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("download %s: %s (%s)", url, resp.Status, strings.TrimSpace(string(b)))
	}
	return io.ReadAll(resp.Body)
}

func parseSHA256File(s string) (string, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", errors.New("empty sha256 file")
	}
	sha := fields[0]
	if len(sha) != 64 {
		return "", fmt.Errorf("unexpected sha256 length: %d", len(sha))
	}
	_, err := hex.DecodeString(sha)
	if err != nil {
		return "", fmt.Errorf("invalid sha256 hex: %w", err)
	}
	return sha, nil
}

func extractSingleFileFromTarGz(tarGz []byte, wantName string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Base(h.Name)
		if name != wantName {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, errors.New("extracted binary is empty")
		}
		return b, nil
	}
	return nil, fmt.Errorf("binary %q not found in archive", wantName)
}
