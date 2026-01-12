package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xdao.co/catf/catf"
	"xdao.co/catf/cidutil"
	"xdao.co/catf/crof"
	"xdao.co/catf/resolver"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out io.Writer, errOut io.Writer) int {
	if len(args) == 0 {
		printUsage(errOut)
		return 2
	}

	switch args[0] {
	case "attest":
		return cmdAttest(args[1:], out, errOut)
	case "doc-cid":
		return cmdDocCID(args[1:], out, errOut)
	case "ipfs":
		return cmdIPFS(args[1:], out, errOut)
	case "key":
		return cmdKey(args[1:], out, errOut)
	case "resolve":
		return cmdResolve(args[1:], out, errOut)
	case "resolve-name":
		return cmdResolveName(args[1:], out, errOut)
	case "help", "-h", "--help":
		printUsage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "unknown command: %s\n\n", args[0])
		printUsage(errOut)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "xdao-catf: minimum CATF/TPDL/Resolver CLI")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  xdao-catf doc-cid <file>")
	fmt.Fprintln(w, "  xdao-catf ipfs put [--pin] [--init] <file>")
	fmt.Fprintln(w, "  xdao-catf key init --name <name> [--seed-hex <64hex>] [--force]")
	fmt.Fprintln(w, "  xdao-catf key derive --from <name> --role <role> [--force]")
	fmt.Fprintln(w, "  xdao-catf key list")
	fmt.Fprintln(w, "  xdao-catf key export --name <name> [--role <role>]")
	fmt.Fprintln(w, "  xdao-catf attest --subject <CID> --description <text> (--seed-hex <64hex> | --signer <name> [--signer-role <role>] | --key-file <path>) [--type <t>] [--role <r>] [--claim Key=Value ...]")
	fmt.Fprintln(w, "  xdao-catf resolve --subject <CID> --policy <tpdl.txt> --att <a1.catf> [--att ...]")
	fmt.Fprintln(w, "  xdao-catf resolve-name --name <Name> [--version <v>] --policy <tpdl.txt> --att <a1.catf> [--att ...]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - --seed-hex must be 32 bytes (64 hex chars) ed25519 seed")
	fmt.Fprintln(w, "  - KMS-lite stores keys under ~/.xdao/keys/<name> (0600 private key files)")
	fmt.Fprintln(w, "  - ipfs put stores raw bytes in your local IPFS repo and prints the CID")
	fmt.Fprintln(w, "  - IPFS smoke test:")
	fmt.Fprintln(w, "      CID=$(xdao-catf ipfs put --init <file>)")
	fmt.Fprintln(w, "      xdao-catf doc-cid <file>  # should match CID")
	fmt.Fprintln(w, "      ipfs block get $CID > /tmp/out && cmp <file> /tmp/out")
	fmt.Fprintln(w, "  - approval attestations require Effective-Date; defaults to now (UTC)")
	fmt.Fprintln(w, "  - attest writes canonical CATF bytes to stdout (no trailing newline)")
	fmt.Fprintln(w, "  - resolve/resolve-name print canonical CROF to stdout")
}

func cmdIPFS(args []string, out io.Writer, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: xdao-catf ipfs <subcommand> ...")
		fmt.Fprintln(errOut, "subcommands: put")
		return 2
	}
	switch args[0] {
	case "put":
		return cmdIPFSPut(args[1:], out, errOut)
	default:
		fmt.Fprintf(errOut, "unknown ipfs subcommand: %s\n", args[0])
		return 2
	}
}

func cmdIPFSPut(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("ipfs put", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var pin bool
	var initRepo bool
	var allowMismatch bool
	fs.BoolVar(&pin, "pin", true, "Pin the block in the local IPFS repo")
	fs.BoolVar(&initRepo, "init", false, "Initialize ~/.ipfs if missing (runs 'ipfs init')")
	fs.BoolVar(&allowMismatch, "allow-mismatch", false, "Print CID even if it does not match doc-cid")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: xdao-catf ipfs put [--pin] [--init] <file>")
		return 2
	}
	path := fs.Arg(0)

	if _, err := exec.LookPath("ipfs"); err != nil {
		fmt.Fprintln(errOut, "ipfs not found on PATH (install Kubo 'ipfs' CLI)")
		return 1
	}

	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(errOut, "read %s: %v\n", filepath.Base(path), err)
		return 1
	}
	expectedCID := cidutil.CIDv1RawSHA256(b)
	if expectedCID == "" {
		fmt.Fprintln(errOut, "failed to compute CID")
		return 1
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(errOut, "home dir: %v\n", err)
		return 1
	}
	repoDir := filepath.Join(home, ".ipfs")
	if _, statErr := os.Stat(repoDir); statErr != nil {
		if !errors.Is(statErr, os.ErrNotExist) {
			fmt.Fprintf(errOut, "stat ~/.ipfs: %v\n", statErr)
			return 1
		}
		if !initRepo {
			fmt.Fprintln(errOut, "IPFS repo not found at ~/.ipfs")
			fmt.Fprintln(errOut, "Run: ipfs init")
			fmt.Fprintln(errOut, "Or:  xdao-catf ipfs put --init <file>")
			return 2
		}
		cmd := exec.Command("ipfs", "init")
		cmd.Stdout = errOut
		cmd.Stderr = errOut
		if runErr := cmd.Run(); runErr != nil {
			fmt.Fprintf(errOut, "ipfs init: %v\n", runErr)
			return 1
		}
	}

	// Store the raw bytes as a raw block so the returned CID matches doc-cid.
	// Different Kubo versions use different flag names; try a couple.
	base := []string{"block", "put"}
	if pin {
		base = append(base, "--pin")
	}
	variants := [][]string{
		append(append([]string{}, base...), "--cid-codec=raw", "--mhtype=sha2-256", path),
		append(append([]string{}, base...), "--format=raw", "--mhtype=sha2-256", path),
		append(append([]string{}, base...), "--cid-version=1", "--format=raw", "--mhtype=sha2-256", path),
	}

	var lastErr error
	var stdout, stderr string
	var actualCID string
	for _, argv := range variants {
		cmd := exec.Command("ipfs", argv...)
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		runErr := cmd.Run()
		stdout = strings.TrimSpace(outBuf.String())
		stderr = strings.TrimSpace(errBuf.String())
		if runErr != nil {
			lastErr = fmt.Errorf("ipfs %s: %v", strings.Join(argv, " "), runErr)
			continue
		}
		// Output is usually the CID; if extra text appears, take first token.
		fields := strings.Fields(stdout)
		if len(fields) == 0 {
			lastErr = fmt.Errorf("ipfs %s: empty output", strings.Join(argv, " "))
			continue
		}
		actualCID = fields[0]
		lastErr = nil
		break
	}
	if lastErr != nil {
		if stderr != "" {
			fmt.Fprintf(errOut, "%v\n%s\n", lastErr, stderr)
			return 1
		}
		fmt.Fprintf(errOut, "%v\n", lastErr)
		return 1
	}

	if actualCID != expectedCID {
		fmt.Fprintf(errOut, "warning: ipfs returned CID does not match doc-cid\n")
		fmt.Fprintf(errOut, "  doc-cid: %s\n", expectedCID)
		fmt.Fprintf(errOut, "  ipfs:    %s\n", actualCID)
		if !allowMismatch {
			fmt.Fprintln(errOut, "refusing to continue without --allow-mismatch")
			return 1
		}
	}

	_, _ = fmt.Fprintln(out, actualCID)
	return 0
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func cmdAttest(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var subjectCID string
	var description string
	var seedHex string
	var signerName string
	var signerRole string
	var keyFile string
	var claimType string
	var role string
	var effectiveDate string
	var supersedes string
	var targetAttestation string
	var name string
	var version string
	var pointsTo string
	var claimsKV stringList
	var printIssuerKey bool

	fs.StringVar(&subjectCID, "subject", "", "Subject CID")
	fs.StringVar(&description, "description", "", "Subject description")
	fs.StringVar(&seedHex, "seed-hex", "", "ed25519 seed as 64 hex chars")
	fs.StringVar(&signerName, "signer", "", "Use a stored key by name (from 'xdao-catf key init')")
	fs.StringVar(&signerRole, "signer-role", "", "When using --signer, optionally use a derived role key")
	fs.StringVar(&keyFile, "key-file", "", "Path to a seed file (hex) created by 'xdao-catf key init/derive'")
	fs.StringVar(&claimType, "type", "", "Core claim Type (e.g. authorship, approval, revocation, supersedes, name-binding)")
	fs.StringVar(&role, "role", "", "Core claim Role (required for authorship/approval)")
	fs.StringVar(&effectiveDate, "effective-date", "", "Core claim Effective-Date (required for approval; defaults to now UTC)")
	fs.StringVar(&supersedes, "supersedes", "", "Set Type=supersedes and CLAIMS: Supersedes=<CID>")
	fs.StringVar(&targetAttestation, "target-attestation", "", "Set Type=revocation and CLAIMS: Target-Attestation=<CID>")
	fs.StringVar(&name, "name", "", "For Type=name-binding: CLAIMS: Name")
	fs.StringVar(&version, "version", "", "For Type=name-binding: CLAIMS: Version")
	fs.StringVar(&pointsTo, "points-to", "", "For Type=name-binding: CLAIMS: Points-To")
	fs.Var(&claimsKV, "claim", "Claim key/value as Key=Value (repeatable)")
	fs.BoolVar(&printIssuerKey, "print-issuer-key", true, "Print Issuer-Key to stderr")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if subjectCID == "" {
		fmt.Fprintln(errOut, "missing --subject")
		return 2
	}
	if description == "" {
		fmt.Fprintln(errOut, "missing --description")
		return 2
	}
	if seedHex == "" && signerName == "" && keyFile == "" {
		fmt.Fprintln(errOut, "missing signer: use --seed-hex, --signer, or --key-file")
		return 2
	}
	if seedHex != "" && (signerName != "" || keyFile != "") {
		fmt.Fprintln(errOut, "conflicting signer flags: --seed-hex cannot be combined with --signer or --key-file")
		return 2
	}
	if signerName != "" && keyFile != "" {
		fmt.Fprintln(errOut, "conflicting signer flags: --signer cannot be combined with --key-file")
		return 2
	}

	seed, err := loadSeed(seedHex, signerName, signerRole, keyFile)
	if err != nil {
		fmt.Fprintf(errOut, "invalid signer: %v\n", err)
		return 2
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	issuerKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)
	if printIssuerKey {
		fmt.Fprintf(errOut, "Issuer-Key: %s\n", issuerKey)
	}

	claims, err := parseKVClaims(claimsKV)
	if err != nil {
		fmt.Fprintf(errOut, "invalid --claim: %v\n", err)
		return 2
	}

	// Apply sugar flags that map to v1 core claims.
	if claimType != "" {
		if existing := claims["Type"]; existing != "" && existing != claimType {
			fmt.Fprintf(errOut, "conflicting Type: --type=%q vs --claim Type=%q\n", claimType, existing)
			return 2
		}
		claims["Type"] = claimType
	}
	if role != "" {
		if existing := claims["Role"]; existing != "" && existing != role {
			fmt.Fprintf(errOut, "conflicting Role: --role=%q vs --claim Role=%q\n", role, existing)
			return 2
		}
		claims["Role"] = role
	}
	if effectiveDate != "" {
		if existing := claims["Effective-Date"]; existing != "" && existing != effectiveDate {
			fmt.Fprintf(errOut, "conflicting Effective-Date: --effective-date=%q vs --claim Effective-Date=%q\n", effectiveDate, existing)
			return 2
		}
		claims["Effective-Date"] = effectiveDate
	}
	if supersedes != "" {
		if existing := claims["Type"]; existing != "" && existing != "supersedes" {
			fmt.Fprintf(errOut, "conflicting Type: supersedes requires Type=supersedes, got %q\n", existing)
			return 2
		}
		claims["Type"] = "supersedes"
		claims["Supersedes"] = supersedes
	}
	if targetAttestation != "" {
		if existing := claims["Type"]; existing != "" && existing != "revocation" {
			fmt.Fprintf(errOut, "conflicting Type: revocation requires Type=revocation, got %q\n", existing)
			return 2
		}
		claims["Type"] = "revocation"
		claims["Target-Attestation"] = targetAttestation
	}
	if name != "" || version != "" || pointsTo != "" {
		if existing := claims["Type"]; existing != "" && existing != "name-binding" {
			fmt.Fprintf(errOut, "conflicting Type: name-binding requires Type=name-binding, got %q\n", existing)
			return 2
		}
		claims["Type"] = "name-binding"
		if name != "" {
			claims["Name"] = name
		}
		if version != "" {
			claims["Version"] = version
		}
		if pointsTo != "" {
			claims["Points-To"] = pointsTo
		}
	}

	if claims["Type"] == "" {
		fmt.Fprintln(errOut, "missing required claim: Type (use --type ... or --claim Type=...)")
		return 2
	}
	if claims["Type"] == "approval" && claims["Effective-Date"] == "" {
		fmt.Fprintln(errOut, "missing required claim: Effective-Date for Type=approval (provide --effective-date or --claim Effective-Date=...)")
		return 2
	}

	doc := catf.Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": subjectCID, "Description": description},
		Claims:  claims,
		Crypto: map[string]string{
			"Hash-Alg":      "sha256",
			"Issuer-Key":    issuerKey,
			"Signature":     "0",
			"Signature-Alg": "ed25519",
		},
	}

	pre, err := catf.Render(doc)
	if err != nil {
		fmt.Fprintf(errOut, "render pre: %v\n", err)
		return 1
	}
	parsed, err := catf.Parse(pre)
	if err != nil {
		fmt.Fprintf(errOut, "parse pre: %v\n", err)
		return 1
	}

	doc.Crypto["Signature"] = catf.SignEd25519SHA256(parsed.Signed, priv)
	finalBytes, err := catf.Render(doc)
	if err != nil {
		fmt.Fprintf(errOut, "render final: %v\n", err)
		return 1
	}
	finalAtt, err := catf.Parse(finalBytes)
	if err != nil {
		fmt.Fprintf(errOut, "parse final: %v\n", err)
		return 1
	}
	if err := finalAtt.Verify(); err != nil {
		fmt.Fprintf(errOut, "verify final: %v\n", err)
		return 1
	}
	if err := catf.ValidateCoreClaims(finalAtt); err != nil {
		fmt.Fprintf(errOut, "invalid core claims: %v\n", err)
		return 2
	}

	fmt.Fprintf(errOut, "Attestation-CID: %s\n", finalAtt.CID())
	_, _ = out.Write(finalBytes)
	return 0
}

func cmdKey(args []string, out io.Writer, errOut io.Writer) int {
	if len(args) == 0 {
		printKeyUsage(errOut)
		return 2
	}
	switch args[0] {
	case "init":
		return cmdKeyInit(args[1:], out, errOut)
	case "derive":
		return cmdKeyDerive(args[1:], out, errOut)
	case "list":
		return cmdKeyList(args[1:], out, errOut)
	case "export":
		return cmdKeyExport(args[1:], out, errOut)
	case "help", "-h", "--help":
		printKeyUsage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "unknown key subcommand: %s\n\n", args[0])
		printKeyUsage(errOut)
		return 2
	}
}

func printKeyUsage(w io.Writer) {
	fmt.Fprintln(w, "xdao-catf key: minimal local key management (KMS-lite)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  xdao-catf key init --name <name> [--seed-hex <64hex>] [--force]")
	fmt.Fprintln(w, "  xdao-catf key derive --from <name> --role <role> [--force]")
	fmt.Fprintln(w, "  xdao-catf key list")
	fmt.Fprintln(w, "  xdao-catf key export --name <name> [--role <role>]")
}

func cmdKeyInit(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("key init", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var name string
	var seedHex string
	var force bool

	fs.StringVar(&name, "name", "", "Key name (directory under ~/.xdao/keys)")
	fs.StringVar(&seedHex, "seed-hex", "", "Optional ed25519 seed as 64 hex chars (for reproducible demos)")
	fs.BoolVar(&force, "force", false, "Overwrite existing key files")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if name == "" {
		fmt.Fprintln(errOut, "missing --name")
		return 2
	}
	if err := validateKeyName(name); err != nil {
		fmt.Fprintf(errOut, "invalid --name: %v\n", err)
		return 2
	}

	var seed []byte
	if seedHex != "" {
		var derr error
		seed, derr = decodeSeedHex(seedHex)
		if derr != nil {
			fmt.Fprintf(errOut, "invalid --seed-hex: %v\n", derr)
			return 2
		}
	} else {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			fmt.Fprintf(errOut, "rand: %v\n", err)
			return 1
		}
	}

	rootPath, err := rootKeyPath(name)
	if err != nil {
		fmt.Fprintf(errOut, "key path: %v\n", err)
		return 1
	}
	if err := writeSeedFile(rootPath, seed, force); err != nil {
		fmt.Fprintf(errOut, "write key: %v\n", err)
		return 1
	}

	issuerKey := issuerKeyFromSeed(seed)
	fmt.Fprintf(out, "Created root key: %s\n", issuerKey)
	fmt.Fprintf(out, "Stored at: %s\n", rootPath)
	return 0
}

func cmdKeyDerive(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("key derive", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var from string
	var role string
	var force bool

	fs.StringVar(&from, "from", "", "Root key name")
	fs.StringVar(&role, "role", "", "Role identifier (e.g. author, reviewer)")
	fs.BoolVar(&force, "force", false, "Overwrite existing key files")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if from == "" {
		fmt.Fprintln(errOut, "missing --from")
		return 2
	}
	if role == "" {
		fmt.Fprintln(errOut, "missing --role")
		return 2
	}
	if err := validateKeyName(from); err != nil {
		fmt.Fprintf(errOut, "invalid --from: %v\n", err)
		return 2
	}
	if err := validateRole(role); err != nil {
		fmt.Fprintf(errOut, "invalid --role: %v\n", err)
		return 2
	}

	rootPath, err := rootKeyPath(from)
	if err != nil {
		fmt.Fprintf(errOut, "key path: %v\n", err)
		return 1
	}
	rootSeed, err := readSeedFile(rootPath)
	if err != nil {
		fmt.Fprintf(errOut, "read root key: %v\n", err)
		return 1
	}
	roleSeed, err := deriveRoleSeed(rootSeed, role)
	if err != nil {
		fmt.Fprintf(errOut, "derive role seed: %v\n", err)
		return 1
	}

	rolePath, err := roleKeyPath(from, role)
	if err != nil {
		fmt.Fprintf(errOut, "key path: %v\n", err)
		return 1
	}
	if err := writeSeedFile(rolePath, roleSeed, force); err != nil {
		fmt.Fprintf(errOut, "write role key: %v\n", err)
		return 1
	}

	issuerKey := issuerKeyFromSeed(roleSeed)
	fmt.Fprintf(out, "Created role key: %s\n", issuerKey)
	fmt.Fprintf(out, "Stored at: %s\n", rolePath)
	return 0
}

func cmdKeyExport(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("key export", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var name string
	var role string

	fs.StringVar(&name, "name", "", "Key name")
	fs.StringVar(&role, "role", "", "Optional role (if set, exports derived role key)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if name == "" {
		fmt.Fprintln(errOut, "missing --name")
		return 2
	}
	if err := validateKeyName(name); err != nil {
		fmt.Fprintf(errOut, "invalid --name: %v\n", err)
		return 2
	}
	var path string
	var err error
	if role == "" {
		path, err = rootKeyPath(name)
	} else {
		if err := validateRole(role); err != nil {
			fmt.Fprintf(errOut, "invalid --role: %v\n", err)
			return 2
		}
		path, err = roleKeyPath(name, role)
	}
	if err != nil {
		fmt.Fprintf(errOut, "key path: %v\n", err)
		return 1
	}
	seed, err := readSeedFile(path)
	if err != nil {
		fmt.Fprintf(errOut, "read key: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(out, issuerKeyFromSeed(seed))
	return 0
}

func cmdKeyList(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("key list", flag.ContinueOnError)
	fs.SetOutput(errOut)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	base, err := keysBaseDir()
	if err != nil {
		fmt.Fprintf(errOut, "keys dir: %v\n", err)
		return 1
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		fmt.Fprintf(errOut, "read keys dir: %v\n", err)
		return 1
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(out, "%s\n", name)
		// roles are optional
		rolesDir := filepath.Join(base, name, "roles")
		roleEntries, rerr := os.ReadDir(rolesDir)
		if rerr != nil {
			continue
		}
		var roles []string
		for _, re := range roleEntries {
			if re.IsDir() {
				continue
			}
			if strings.HasSuffix(re.Name(), ".key") {
				roles = append(roles, strings.TrimSuffix(re.Name(), ".key"))
			}
		}
		sort.Strings(roles)
		for _, r := range roles {
			fmt.Fprintf(out, "  - %s\n", r)
		}
	}
	return 0
}

func cmdDocCID(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("doc-cid", flag.ContinueOnError)
	fs.SetOutput(errOut)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: xdao-catf doc-cid <file>")
		return 2
	}
	path := fs.Arg(0)
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(errOut, "read %s: %v\n", filepath.Base(path), err)
		return 1
	}
	_, _ = fmt.Fprintln(out, cidutil.CIDv1RawSHA256(b))
	return 0
}

func cmdResolve(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var subjectCID string
	var policyPath string
	var attPaths stringList
	var resolverID string
	var resolvedAt string

	fs.StringVar(&subjectCID, "subject", "", "Subject CID")
	fs.StringVar(&policyPath, "policy", "", "TPDL policy file")
	fs.Var(&attPaths, "att", "CATF attestation file (repeatable)")
	fs.StringVar(&resolverID, "resolver-id", "xdao-resolver-reference", "Resolver-ID recorded in CROF")
	fs.StringVar(&resolvedAt, "resolved-at", "", "Optional RFC3339 timestamp for CROF META Resolved-At (omit for deterministic output)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if subjectCID == "" {
		fmt.Fprintln(errOut, "missing --subject")
		return 2
	}
	if policyPath == "" {
		fmt.Fprintln(errOut, "missing --policy")
		return 2
	}
	if len(attPaths) == 0 {
		fmt.Fprintln(errOut, "missing --att")
		return 2
	}

	var resolvedAtTime time.Time
	if resolvedAt != "" {
		t, perr := time.Parse(time.RFC3339, resolvedAt)
		if perr != nil {
			fmt.Fprintf(errOut, "invalid --resolved-at (expected RFC3339): %v\n", perr)
			return 2
		}
		resolvedAtTime = t
	}

	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Fprintf(errOut, "read policy: %v\n", err)
		return 1
	}

	attBytes := make([][]byte, 0, len(attPaths))
	attCIDs := make([]string, 0, len(attPaths))
	for _, p := range attPaths {
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			fmt.Fprintf(errOut, "read att %s: %v\n", p, rerr)
			return 1
		}
		attBytes = append(attBytes, b)
		a, perr := catf.Parse(b)
		if perr != nil {
			fmt.Fprintf(errOut, "invalid CATF attestation %s: %v\n", p, perr)
			return 2
		}
		attCIDs = append(attCIDs, a.CID())
	}

	res, err := resolver.Resolve(attBytes, policyBytes, subjectCID)
	if err != nil {
		fmt.Fprintf(errOut, "resolve: %v\n", err)
		return 1
	}

	crofBytes := crof.Render(
		res,
		crof.PolicyCID(policyBytes),
		attCIDs,
		crof.RenderOptions{ResolverID: resolverID, ResolvedAt: resolvedAtTime},
	)

	_, _ = out.Write(crofBytes)
	return 0
}

func cmdResolveName(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("resolve-name", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var name string
	var version string
	var policyPath string
	var attPaths stringList
	var resolverID string
	var resolvedAt string

	fs.StringVar(&name, "name", "", "Symbolic name")
	fs.StringVar(&version, "version", "", "Optional version")
	fs.StringVar(&policyPath, "policy", "", "TPDL policy file")
	fs.Var(&attPaths, "att", "CATF attestation file (repeatable)")
	fs.StringVar(&resolverID, "resolver-id", "xdao-resolver-reference", "Resolver-ID recorded in CROF")
	fs.StringVar(&resolvedAt, "resolved-at", "", "Optional RFC3339 timestamp for CROF META Resolved-At (omit for deterministic output)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if name == "" {
		fmt.Fprintln(errOut, "missing --name")
		return 2
	}
	if policyPath == "" {
		fmt.Fprintln(errOut, "missing --policy")
		return 2
	}
	if len(attPaths) == 0 {
		fmt.Fprintln(errOut, "missing --att")
		return 2
	}

	var resolvedAtTime time.Time
	if resolvedAt != "" {
		t, perr := time.Parse(time.RFC3339, resolvedAt)
		if perr != nil {
			fmt.Fprintf(errOut, "invalid --resolved-at (expected RFC3339): %v\n", perr)
			return 2
		}
		resolvedAtTime = t
	}

	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Fprintf(errOut, "read policy: %v\n", err)
		return 1
	}

	attBytes := make([][]byte, 0, len(attPaths))
	attCIDs := make([]string, 0, len(attPaths))
	for _, p := range attPaths {
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			fmt.Fprintf(errOut, "read att %s: %v\n", p, rerr)
			return 1
		}
		attBytes = append(attBytes, b)
		a, perr := catf.Parse(b)
		if perr != nil {
			fmt.Fprintf(errOut, "invalid CATF attestation %s: %v\n", p, perr)
			return 2
		}
		attCIDs = append(attCIDs, a.CID())
	}

	nameRes, err := resolver.ResolveName(attBytes, policyBytes, name, version)
	if err != nil {
		fmt.Fprintf(errOut, "resolve-name: %v\n", err)
		return 1
	}

	subject := "name:" + name
	if version != "" {
		subject += "@" + version
	}
	res := &resolver.Resolution{
		SubjectCID: subject,
		State:      nameRes.State,
		Confidence: nameRes.Confidence,
		Exclusions: nameRes.Exclusions,
	}
	if len(nameRes.Bindings) > 0 {
		res.Paths = append(res.Paths, resolver.Path{ID: "path-1", CIDs: append([]string(nil), nameRes.Bindings...)})
	}
	if len(nameRes.Forks) > 0 {
		res.Forks = append(res.Forks, resolver.Fork{ID: "fork-1", ConflictingPath: []string{"path-1"}})
	}

	crofBytes := crof.Render(
		res,
		crof.PolicyCID(policyBytes),
		attCIDs,
		crof.RenderOptions{ResolverID: resolverID, ResolvedAt: resolvedAtTime},
	)
	_, _ = out.Write(crofBytes)
	return 0
}

func parseKVClaims(items []string) (map[string]string, error) {
	claims := make(map[string]string)
	if len(items) == 0 {
		return claims, nil
	}
	for _, it := range items {
		k, v, ok := strings.Cut(it, "=")
		if !ok {
			return nil, fmt.Errorf("expected Key=Value, got %q", it)
		}
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, errors.New("empty key")
		}
		if _, exists := claims[k]; exists {
			return nil, fmt.Errorf("duplicate claim key %q", k)
		}
		claims[k] = v
	}
	return claims, nil
}

func decodeSeedHex(seedHex string) ([]byte, error) {
	seedHex = strings.TrimSpace(seedHex)
	seedHex = strings.TrimPrefix(seedHex, "0x")
	b, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(b))
	}
	return b, nil
}

func keysBaseDir() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".xdao", "keys"), nil
}

func rootKeyPath(name string) (string, error) {
	base, err := keysBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, name, "root.key"), nil
}

func roleKeyPath(name, role string) (string, error) {
	base, err := keysBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, name, "roles", role+".key"), nil
}

func writeSeedFile(path string, seed []byte, force bool) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed must be %d bytes", ed25519.SeedSize)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(seed) + "\n"); err != nil {
		return err
	}
	return f.Close()
}

func readSeedFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seedHex := strings.TrimSpace(string(b))
	return decodeSeedHex(seedHex)
}

func issuerKeyFromSeed(seed []byte) string {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

func deriveRoleSeed(rootSeed []byte, role string) ([]byte, error) {
	if len(rootSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("root seed must be %d bytes", ed25519.SeedSize)
	}
	if err := validateRole(role); err != nil {
		return nil, err
	}
	// Deterministic, domain-separated derivation for role keys.
	// This is intentionally local-first and offline; it is not a global identity system.
	h := sha256.New()
	_, _ = h.Write(rootSeed)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte("xdao-catf-kms-lite-v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte("role:"))
	_, _ = h.Write([]byte(role))
	sum := h.Sum(nil)
	if len(sum) < ed25519.SeedSize {
		return nil, errors.New("kdf output too short")
	}
	return sum[:ed25519.SeedSize], nil
}

func validateKeyName(name string) error {
	if name == "" {
		return errors.New("empty")
	}
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return fmt.Errorf("invalid character %q", ch)
	}
	return nil
}

func validateRole(role string) error {
	if role == "" {
		return errors.New("empty")
	}
	for _, ch := range role {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return fmt.Errorf("invalid character %q", ch)
	}
	return nil
}

func loadSeed(seedHex, signerName, signerRole, keyFile string) ([]byte, error) {
	if seedHex != "" {
		return decodeSeedHex(seedHex)
	}
	if keyFile != "" {
		return readSeedFile(keyFile)
	}
	if signerName != "" {
		if err := validateKeyName(signerName); err != nil {
			return nil, err
		}
		var path string
		var err error
		if signerRole == "" {
			path, err = rootKeyPath(signerName)
		} else {
			if err := validateRole(signerRole); err != nil {
				return nil, err
			}
			path, err = roleKeyPath(signerName, signerRole)
		}
		if err != nil {
			return nil, err
		}
		return readSeedFile(path)
	}
	return nil, errors.New("no signer provided")
}
