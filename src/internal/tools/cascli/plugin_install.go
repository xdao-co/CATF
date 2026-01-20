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
	"sort"
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
		fmt.Fprintln(errOut, "subcommands: install, list, verify")
		return 2
	}
	switch args[0] {
	case "install":
		return cmdPluginInstall(args[1:], out, errOut)
	case "list":
		return cmdPluginList(args[1:], out, errOut)
	case "verify":
		return cmdPluginVerify(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown plugin subcommand: %s\n", args[0])
		return 2
	}
}

func cmdPluginList(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("plugin list", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var pluginName string
	var goos string
	var goarch string
	var token string
	var withLatest bool
	var asJSON bool

	fs.StringVar(&pluginName, "plugin", "", "Plugin to show (optional; default all)")
	fs.StringVar(&goos, "os", runtime.GOOS, "Target OS (goos; used for asset checks when --with-latest)")
	fs.StringVar(&goarch, "arch", runtime.GOARCH, "Target arch (goarch; used for asset checks when --with-latest)")
	fs.StringVar(&token, "github-token", "", "GitHub token (optional; defaults to GITHUB_TOKEN env var)")
	fs.BoolVar(&withLatest, "with-latest", false, "Query GitHub releases/latest and show asset availability")
	fs.BoolVar(&asJSON, "json", false, "Emit JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "usage: cascli plugin list [--plugin <name>] [--with-latest] [--os <goos>] [--arch <goarch>] [--json]")
		return 2
	}
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if goos == "windows" {
		fmt.Fprintln(errOut, "windows is not supported by current plugin releases")
		return 2
	}
	if pluginName != "" {
		if _, ok := knownPlugins[pluginName]; !ok {
			fmt.Fprintf(errOut, "unknown plugin %q (supported: %s)\n", pluginName, strings.Join(sortedPluginNames(), ", "))
			return 2
		}
	}

	type pluginListItem struct {
		Name          string `json:"name"`
		Repo          string `json:"repo"`
		Binary        string `json:"binary"`
		LatestVersion string `json:"latest_version,omitempty"`
		AssetOK       bool   `json:"asset_ok,omitempty"`
		ChecksumOK    bool   `json:"checksum_ok,omitempty"`
	}

	items := make([]pluginListItem, 0, len(knownPlugins))
	for _, name := range sortedPluginNames() {
		if pluginName != "" && name != pluginName {
			continue
		}
		spec := knownPlugins[name]
		item := pluginListItem{
			Name:   spec.Name,
			Repo:   fmt.Sprintf("%s/%s", spec.Owner, spec.Repo),
			Binary: spec.Binary,
		}
		if withLatest {
			apiURL := githubReleaseAPIURL(spec.Owner, spec.Repo, "")
			rel, err := fetchGitHubRelease(apiURL, token)
			if err != nil {
				fmt.Fprintf(errOut, "fetch latest for %s: %v\n", spec.Name, err)
				return 1
			}
			item.LatestVersion = rel.TagName
			assetBase := fmt.Sprintf("%s_%s_%s.tar.gz", spec.Binary, goos, goarch)
			checksumName := assetBase + ".sha256"
			_, item.AssetOK = findAssetURL(rel.Assets, assetBase)
			_, item.ChecksumOK = findAssetURL(rel.Assets, checksumName)
		}
		items = append(items, item)
	}

	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(items); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		return 0
	}

	for _, it := range items {
		if !withLatest {
			_, _ = fmt.Fprintf(out, "%s\t%s\t%s\n", it.Name, it.Repo, it.Binary)
			continue
		}
		_, _ = fmt.Fprintf(out, "%s\t%s\t%s\tlatest=%s\tasset=%v\tchecksum=%v\n", it.Name, it.Repo, it.Binary, it.LatestVersion, it.AssetOK, it.ChecksumOK)
	}
	return 0
}

func cmdPluginVerify(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("plugin verify", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var pluginName string
	var version string
	var installDir string
	var binaryPath string
	var goos string
	var goarch string
	var token string
	var repoOverride string
	var binaryOverride string
	var noVerify bool

	fs.StringVar(&pluginName, "plugin", "", "Plugin to verify: localfs|ipfs")
	fs.StringVar(&version, "version", "", "Release tag to verify against (e.g. v1.2.3). If empty, uses latest.")
	fs.StringVar(&installDir, "install-dir", "", "Install directory (default ~/.local/bin; ignored if --binary-path is set)")
	fs.StringVar(&binaryPath, "binary-path", "", "Path to installed binary (optional; overrides --install-dir)")
	fs.StringVar(&goos, "os", runtime.GOOS, "Target OS (goos)")
	fs.StringVar(&goarch, "arch", runtime.GOARCH, "Target arch (goarch)")
	fs.StringVar(&token, "github-token", "", "GitHub token (optional; defaults to GITHUB_TOKEN env var)")
	fs.StringVar(&repoOverride, "repo", "", "Override repo as owner/name (advanced)")
	fs.StringVar(&binaryOverride, "binary", "", "Override binary name (advanced)")
	fs.BoolVar(&noVerify, "no-verify", false, "Skip checksum verification")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "usage: cascli plugin verify --plugin localfs|ipfs [flags]")
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

	owner, repo, binary, err := resolvePlugin(pluginName, repoOverride, binaryOverride)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	localPath := binaryPath
	if localPath == "" {
		localPath = filepath.Join(installDir, binary)
	}
	localBytes, err := os.ReadFile(localPath)
	if err != nil {
		fmt.Fprintf(errOut, "read %s: %v\n", localPath, err)
		return 1
	}
	if len(localBytes) == 0 {
		fmt.Fprintf(errOut, "installed binary is empty: %s\n", localPath)
		return 1
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
	expectedBinBytes, err := extractSingleFileFromTarGz(tarGzBytes, expectedInnerName)
	if err != nil {
		fmt.Fprintf(errOut, "extract: %v\n", err)
		return 1
	}

	if !bytes.Equal(localBytes, expectedBinBytes) {
		fmt.Fprintf(errOut, "binary mismatch for %s (%s)\n", pluginName, version)
		fmt.Fprintf(errOut, "  installed: %s sha256=%s\n", localPath, sha256Hex(localBytes))
		fmt.Fprintf(errOut, "  expected:  release(%s) sha256=%s\n", assetBase, sha256Hex(expectedBinBytes))
		return 1
	}

	_, _ = fmt.Fprintf(out, "verified %s (%s): %s matches %s\n", pluginName, version, localPath, assetBase)
	return 0
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

func sortedPluginNames() []string {
	names := make([]string, 0, len(knownPlugins))
	for name := range knownPlugins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func resolvePlugin(pluginName, repoOverride, binaryOverride string) (owner string, repo string, binary string, err error) {
	spec, ok := knownPlugins[pluginName]
	if !ok {
		return "", "", "", fmt.Errorf("unknown plugin %q (supported: %s)", pluginName, strings.Join(sortedPluginNames(), ", "))
	}
	owner = spec.Owner
	repo = spec.Repo
	binary = spec.Binary

	if repoOverride != "" {
		parts := strings.Split(repoOverride, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", "", errors.New("--repo must be in the form owner/name")
		}
		owner, repo = parts[0], parts[1]
	}
	if binaryOverride != "" {
		binary = binaryOverride
	}
	return owner, repo, binary, nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
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
