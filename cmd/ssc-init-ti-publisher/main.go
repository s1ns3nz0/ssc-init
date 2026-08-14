// Command ssc-init-ti-publisher builds unsigned TI publication artifacts from
// explicit pinned local snapshots. Signing remains a separate CI operation.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/tipublish"
)

const (
	manifestFileLimit = 64 << 10
	bundleFileLimit   = 16 << 20
	privateKeyLimit   = 1 << 10
)

var (
	afterSigningInputsReadForRun = func() {}
	signingNowForRun             = func() time.Time { return time.Now().UTC() }
	productionKeysForVerify      = bundle.ProductionKeys
)

type stringList []string

func (values *stringList) String() string { return fmt.Sprint([]string(*values)) }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "sign" {
		return runSign(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "verify" {
		return runVerify(args[1:], stdout, stderr)
	}
	return runPublish(args, stdout, stderr)
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ssc-init-ti-publisher verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var manifestPath, manifestSignaturePath, bundlePath, bundleSignaturePath string
	flags.StringVar(&manifestPath, "manifest-file", "", "absolute ti-manifest.json path")
	flags.StringVar(&manifestSignaturePath, "manifest-signature", "", "absolute ti-manifest.sig path")
	flags.StringVar(&bundlePath, "bundle-file", "", "absolute ti-bundle.json path")
	flags.StringVar(&bundleSignaturePath, "bundle-signature", "", "absolute ti-bundle.sig path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !publicationVerificationPaths(manifestPath, manifestSignaturePath, bundlePath, bundleSignaturePath) {
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	manifestRaw, err := readRegularBoundedFile(manifestPath, manifestFileLimit)
	if err != nil {
		fmt.Fprintln(stderr, "publication verification failed")
		return 1
	}
	manifestSig, err := readRegularBoundedFile(manifestSignaturePath, 1<<10)
	if err != nil {
		fmt.Fprintln(stderr, "publication verification failed")
		return 1
	}
	bundleRaw, err := readRegularBoundedFile(bundlePath, bundleFileLimit)
	if err != nil {
		fmt.Fprintln(stderr, "publication verification failed")
		return 1
	}
	bundleSig, err := readRegularBoundedFile(bundleSignaturePath, 1<<10)
	if err != nil {
		fmt.Fprintln(stderr, "publication verification failed")
		return 1
	}
	now := signingNowForRun().UTC()
	keys := productionKeysForVerify()
	verifiedManifest, err := bundle.VerifyManifest(manifestRaw, manifestSig, keys, now)
	if err != nil {
		fmt.Fprintln(stderr, "publication verification failed")
		return 1
	}
	verifiedBundle, err := (bundle.Verifier{Keys: keys}).Verify(bundleRaw, bundleSig, now)
	if err != nil || verifiedBundle.Envelope.Sequence != verifiedManifest.Manifest.Sequence || verifiedBundle.Envelope.KeyID != verifiedManifest.Manifest.KeyID || hex.EncodeToString(verifiedBundle.Digest[:]) != verifiedManifest.Manifest.SHA256 {
		fmt.Fprintln(stderr, "publication verification failed")
		return 1
	}
	fmt.Fprintf(stdout, "verified TI release %s with compiled key %s\n", verifiedManifest.Manifest.ReleaseTag, verifiedManifest.Manifest.KeyID)
	return 0
}

func publicationVerificationPaths(paths ...string) bool {
	if len(paths) != 4 {
		return false
	}
	directory := filepath.Dir(paths[0])
	want := []string{"ti-manifest.json", "ti-manifest.sig", "ti-bundle.json", "ti-bundle.sig"}
	for index, value := range paths {
		if !cleanAbsolute(value) || filepath.Dir(value) != directory || filepath.Base(value) != want[index] {
			return false
		}
	}
	return true
}

func readRegularBoundedFile(path string, limit int64) ([]byte, error) {
	snapshot, err := openRegularSnapshot(path, limit)
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	raw := append([]byte(nil), snapshot.Bytes()...)
	if !snapshot.Unchanged() {
		return nil, fmt.Errorf("artifact changed")
	}
	return raw, nil
}

func runPublish(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ssc-init-ti-publisher", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var osvPaths, openSSFPaths stringList
	var osvLicense, osvBaseURL, openSSFLicense, openSSFBaseURL string
	var version, sequence, keyID, generatedAt, validFrom, validUntil, outputDirectory string
	flags.Var(&osvPaths, "osv-source", "absolute local OSV snapshot path (repeatable)")
	flags.StringVar(&osvLicense, "osv-license", "", "approved SPDX license for every OSV source")
	flags.StringVar(&osvBaseURL, "osv-base-url", "", "public HTTPS OSV record base")
	flags.Var(&openSSFPaths, "openssf-source", "absolute local OpenSSF snapshot path (repeatable)")
	flags.StringVar(&openSSFLicense, "openssf-license", "", "approved SPDX license for every OpenSSF source")
	flags.StringVar(&openSSFBaseURL, "openssf-base-url", "", "public HTTPS OpenSSF record base")
	flags.StringVar(&version, "version", "", "bundle version")
	flags.StringVar(&sequence, "sequence", "", "positive bundle sequence")
	flags.StringVar(&keyID, "key-id", "", "publication key id")
	flags.StringVar(&generatedAt, "generated-at", "", "RFC3339 generation time")
	flags.StringVar(&validFrom, "valid-from", "", "RFC3339 validity start")
	flags.StringVar(&validUntil, "valid-until", "", "RFC3339 validity end")
	flags.StringVar(&outputDirectory, "output-dir", "", "absolute existing output directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || len(osvPaths)+len(openSSFPaths) == 0 || !cleanAbsolute(outputDirectory) || !absolutePaths(osvPaths) || !absolutePaths(openSSFPaths) {
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	sequenceValue, err := strconv.ParseUint(sequence, 10, 64)
	generatedTime, generatedErr := parseUTC(generatedAt)
	validFromTime, validFromErr := parseUTC(validFrom)
	validUntilTime, validUntilErr := parseUTC(validUntil)
	if err != nil || generatedErr != nil || validFromErr != nil || validUntilErr != nil {
		fmt.Fprintln(stderr, "invalid publication metadata")
		return 2
	}
	input := tipublish.Input{
		OSV:         sources(osvPaths, osvLicense, osvBaseURL),
		OpenSSF:     sources(openSSFPaths, openSSFLicense, openSSFBaseURL),
		Version:     version,
		Sequence:    sequenceValue,
		KeyID:       keyID,
		GeneratedAt: generatedTime,
		ValidFrom:   validFromTime,
		ValidUntil:  validUntilTime,
	}
	bundleBytes, report, err := tipublish.Build(input)
	if err != nil {
		fmt.Fprintln(stderr, "publication input is invalid")
		return 1
	}
	reportBytes, err := tipublish.EncodeReport(report)
	if err != nil {
		fmt.Fprintln(stderr, "attribution report cannot be encoded")
		return 1
	}
	bundleDigest := sha256.Sum256(bundleBytes)
	manifestBytes, err := json.Marshal(bundle.Manifest{
		SchemaVersion: bundle.ManifestSchemaVersion,
		Family:        bundle.FamilyTI,
		Version:       version,
		Sequence:      sequenceValue,
		KeyID:         keyID,
		GeneratedAt:   generatedTime,
		ValidFrom:     validFromTime,
		ValidUntil:    validUntilTime,
		Length:        int64(len(bundleBytes)),
		SHA256:        hex.EncodeToString(bundleDigest[:]),
		ReleaseTag:    fmt.Sprintf("ti-%08d", sequenceValue),
		Artifact:      "ti-bundle.json",
	})
	if err != nil {
		fmt.Fprintln(stderr, "manifest cannot be encoded")
		return 1
	}
	manifestBytes = append(manifestBytes, '\n')
	if _, err := bundle.LoadManifest(manifestBytes, generatedTime); err != nil {
		fmt.Fprintln(stderr, "manifest cannot be encoded")
		return 1
	}
	bundlePath := filepath.Join(outputDirectory, "ti-bundle.json")
	manifestPath := filepath.Join(outputDirectory, "ti-manifest.json")
	reportPath := filepath.Join(outputDirectory, "attribution-report.json")
	if exists(bundlePath) || exists(manifestPath) || exists(reportPath) {
		fmt.Fprintln(stderr, "publication artifacts already exist")
		return 1
	}
	if err := writeExclusive(bundlePath, bundleBytes); err != nil {
		fmt.Fprintln(stderr, "publication artifacts cannot be written")
		return 1
	}
	if err := writeExclusive(manifestPath, manifestBytes); err != nil {
		_ = os.Remove(bundlePath)
		fmt.Fprintln(stderr, "publication artifacts cannot be written")
		return 1
	}
	if err := writeExclusive(reportPath, reportBytes); err != nil {
		_ = os.Remove(bundlePath)
		_ = os.Remove(manifestPath)
		fmt.Fprintln(stderr, "publication artifacts cannot be written")
		return 1
	}
	fmt.Fprintf(stdout, "published sequence %d: %d records (%d malicious, %d vulnerable)\n", report.Sequence, report.Records, report.Malicious, report.Vulnerable)
	return 0
}

func runSign(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ssc-init-ti-publisher sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var manifestPath, bundlePath, privateKeyPath, keyID, outputDirectory string
	flags.StringVar(&manifestPath, "manifest-file", "", "absolute ti-manifest.json path")
	flags.StringVar(&bundlePath, "bundle-file", "", "absolute ti-bundle.json path")
	flags.StringVar(&privateKeyPath, "private-key-file", "", "absolute protected Ed25519 private-key path")
	flags.StringVar(&keyID, "key-id", "", "publication key id")
	flags.StringVar(&outputDirectory, "output-dir", "", "absolute existing output directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !signingPaths(manifestPath, bundlePath, privateKeyPath, outputDirectory) || keyID == "" || len(keyID) > 128 {
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	if !validSigningKeyID(keyID) || strings.HasPrefix(strings.ToLower(keyID), "test") {
		fmt.Fprintln(stderr, "signing input is invalid")
		return 1
	}
	privateKeyBytes, err := readPrivateKey(privateKeyPath)
	if err != nil || len(privateKeyBytes) != ed25519.PrivateKeySize {
		fmt.Fprintln(stderr, "signing input is invalid")
		return 1
	}
	defer clear(privateKeyBytes)
	manifestSnapshot, err := openRegularSnapshot(manifestPath, manifestFileLimit)
	if err != nil {
		fmt.Fprintln(stderr, "signing input is invalid")
		return 1
	}
	defer manifestSnapshot.Close()
	manifestBytes := manifestSnapshot.Bytes()
	signingNow := signingNowForRun()
	manifest, err := bundle.LoadManifest(manifestBytes, signingNow)
	if err != nil || manifest.KeyID != keyID {
		fmt.Fprintln(stderr, "signing input is invalid")
		return 1
	}
	bundleSnapshot, err := openRegularSnapshot(bundlePath, bundleFileLimit)
	if err != nil {
		fmt.Fprintln(stderr, "signing input is invalid")
		return 1
	}
	defer bundleSnapshot.Close()
	bundleBytes := bundleSnapshot.Bytes()
	afterSigningInputsReadForRun()
	envelope, err := bundle.Load(bundleBytes, signingNow)
	digest := sha256.Sum256(bundleBytes)
	if err != nil || envelope.Family != bundle.FamilyTI || envelope.KeyID != keyID || envelope.Sequence != manifest.Sequence || envelope.Version != manifest.Version ||
		!envelope.GeneratedAt.Equal(manifest.GeneratedAt) || !envelope.ValidFrom.Equal(manifest.ValidFrom) || !envelope.ValidUntil.Equal(manifest.ValidUntil) ||
		int64(len(bundleBytes)) != manifest.Length || hex.EncodeToString(digest[:]) != manifest.SHA256 {
		fmt.Fprintln(stderr, "signing input is invalid")
		return 1
	}
	manifestSignature, bundleSignature, err := signPublicationBytes(manifestBytes, bundleBytes, privateKeyBytes)
	if err != nil {
		fmt.Fprintln(stderr, "signing input is invalid")
		return 1
	}
	if !manifestSnapshot.Unchanged() || !bundleSnapshot.Unchanged() {
		fmt.Fprintln(stderr, "signing input is invalid")
		return 1
	}
	manifestSignaturePath := filepath.Join(outputDirectory, "ti-manifest.sig")
	bundleSignaturePath := filepath.Join(outputDirectory, "ti-bundle.sig")
	if exists(manifestSignaturePath) || exists(bundleSignaturePath) {
		fmt.Fprintln(stderr, "signature artifacts already exist")
		return 1
	}
	if err := writeSignaturePair(outputDirectory, manifestSignature, bundleSignature, writeExclusive); err != nil {
		fmt.Fprintln(stderr, "signature artifacts cannot be written")
		return 1
	}
	fmt.Fprintf(stdout, "signed TI release %s with key %s\n", manifest.ReleaseTag, keyID)
	return 0
}

func writeSignaturePair(outputDirectory string, manifestSignature, bundleSignature []byte, writer func(string, []byte) error) error {
	manifestPath := filepath.Join(outputDirectory, "ti-manifest.sig")
	if err := writer(manifestPath, manifestSignature); err != nil {
		return err
	}
	if err := writer(filepath.Join(outputDirectory, "ti-bundle.sig"), bundleSignature); err != nil {
		_ = os.Remove(manifestPath)
		return err
	}
	return nil
}

func signPublicationBytes(manifestBytes, bundleBytes, privateKeyBytes []byte) ([]byte, []byte, error) {
	defer clear(privateKeyBytes)
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid private key")
	}
	privateKey := ed25519.PrivateKey(privateKeyBytes)
	bundleSignature, err := bundle.Sign(bundleBytes, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return ed25519.Sign(privateKey, manifestBytes), bundleSignature, nil
}

func validSigningKeyID(keyID string) bool {
	if len(keyID) < len("ti-a") || len(keyID) > 128 || !strings.HasPrefix(keyID, "ti-") || keyID[len(keyID)-1] == '-' {
		return false
	}
	for _, character := range keyID {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func signingPaths(manifestPath, bundlePath, privateKeyPath, outputDirectory string) bool {
	return cleanAbsolute(manifestPath) && cleanAbsolute(bundlePath) && cleanAbsolute(privateKeyPath) && cleanAbsolute(outputDirectory) &&
		filepath.Base(manifestPath) == "ti-manifest.json" && filepath.Base(bundlePath) == "ti-bundle.json" &&
		filepath.Dir(manifestPath) == outputDirectory && filepath.Dir(bundlePath) == outputDirectory
}

func readPrivateKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > privateKeyLimit {
		return nil, fmt.Errorf("invalid private key file")
	}
	return readOpenedBounded(path, info, privateKeyLimit, true)
}

type regularSnapshot struct {
	path   string
	file   *os.File
	opened os.FileInfo
	raw    []byte
	limit  int64
}

func openRegularSnapshot(path string, limit int64) (*regularSnapshot, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("invalid regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("file identity changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit || opened.Size() != int64(len(raw)) {
		_ = file.Close()
		return nil, fmt.Errorf("invalid regular file size")
	}
	return &regularSnapshot{path: path, file: file, opened: opened, raw: raw, limit: limit}, nil
}

func (snapshot *regularSnapshot) Bytes() []byte { return snapshot.raw }

func (snapshot *regularSnapshot) Close() { _ = snapshot.file.Close() }

func (snapshot *regularSnapshot) Unchanged() bool {
	pathBefore, err := os.Lstat(snapshot.path)
	currentBefore, statErr := snapshot.file.Stat()
	if err != nil || statErr != nil || !pathBefore.Mode().IsRegular() || !os.SameFile(snapshot.opened, pathBefore) || !sameSnapshotInfo(snapshot.opened, currentBefore) {
		return false
	}
	if _, err := snapshot.file.Seek(0, io.SeekStart); err != nil {
		return false
	}
	currentRaw, err := io.ReadAll(io.LimitReader(snapshot.file, snapshot.limit+1))
	currentAfter, statErr := snapshot.file.Stat()
	pathAfter, pathErr := os.Lstat(snapshot.path)
	return err == nil && statErr == nil && pathErr == nil && int64(len(currentRaw)) <= snapshot.limit && bytes.Equal(snapshot.raw, currentRaw) &&
		pathAfter.Mode().IsRegular() && os.SameFile(snapshot.opened, pathAfter) && sameSnapshotInfo(snapshot.opened, currentAfter)
}

func sameSnapshotInfo(left, right os.FileInfo) bool {
	return left.Size() == right.Size() && left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}

func readOpenedBounded(path string, expected os.FileInfo, limit int64, private bool) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) || private && opened.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("file identity changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("file exceeds limit")
	}
	if opened.Size() != int64(len(raw)) {
		return nil, fmt.Errorf("file size changed")
	}
	return raw, nil
}

func sources(paths []string, license, baseURL string) []tipublish.Source {
	result := make([]tipublish.Source, len(paths))
	for index, path := range paths {
		result[index] = tipublish.Source{Path: path, License: license, PublicURLBase: baseURL}
	}
	return result
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("time must be UTC RFC3339")
	}
	return parsed, nil
}

func absolutePaths(paths []string) bool {
	for _, path := range paths {
		if !cleanAbsolute(path) {
			return false
		}
	}
	return true
}

func cleanAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

func writeExclusive(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	writeErr := func() error {
		defer file.Close()
		if _, err := file.Write(raw); err != nil {
			return err
		}
		return file.Sync()
	}()
	if writeErr != nil {
		_ = os.Remove(path)
	}
	return writeErr
}
