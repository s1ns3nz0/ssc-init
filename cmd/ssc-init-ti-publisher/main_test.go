package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
)

func TestRunWritesUnsignedBundleAndPublicAttributionReport(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	code := run([]string{
		"--osv-source", filepath.Join(repositoryRoot, "internal", "tipublish", "testdata", "osv-vulnerable.json"),
		"--osv-license", "CC-BY-4.0",
		"--osv-base-url", "https://osv.dev/vulnerability/",
		"--openssf-source", filepath.Join(repositoryRoot, "internal", "tipublish", "testdata", "openssf-malicious.json"),
		"--openssf-license", "CC-BY-4.0",
		"--openssf-base-url", "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/",
		"--version", "2026.08.14", "--sequence", "42", "--key-id", "ti-production-2026",
		"--generated-at", "2026-08-14T00:00:00Z", "--valid-from", "2026-08-13T23:00:00Z", "--valid-until", "2026-08-21T00:00:00Z",
		"--output-dir", output,
	}, stdout, stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(output, "ti-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC))
	if err != nil || envelope.Sequence != 42 || len(envelope.TI.Records) != 4 {
		t.Fatalf("envelope=%+v err=%v", envelope, err)
	}
	report, err := os.ReadFile(filepath.Join(output, "attribution-report.json"))
	var summary struct {
		Malicious  int `json:"malicious"`
		Vulnerable int `json:"vulnerable"`
	}
	decodeErr := json.Unmarshal(report, &summary)
	if err != nil || decodeErr != nil || summary.Malicious != 2 || summary.Vulnerable != 2 || report[len(report)-1] != '\n' {
		t.Fatalf("report=%s err=%v", report, err)
	}
	if _, err := os.Stat(filepath.Join(output, "ti-bundle.sig")); !os.IsNotExist(err) {
		t.Fatalf("publisher unexpectedly signed output: %v", err)
	}
}

func TestPublisherSignsExactManifestAndBundleBytes(t *testing.T) {
	useSigningNow(t)
	output := t.TempDir()
	if code := run(validArgs(t, output), new(bytes.Buffer), new(bytes.Buffer)); code != 0 {
		t.Fatalf("publish code=%d", code)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(output, "ti-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundleRaw, err := os.ReadFile(filepath.Join(output, "ti-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("publisher signing fixture"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	keyPath := filepath.Join(t.TempDir(), "signing-key")
	if err := os.WriteFile(keyPath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(signArgs(output, keyPath, "ti-production-2026"), &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || strings.Contains(stdout.String(), keyPath) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	manifestSignature, err := os.ReadFile(filepath.Join(output, "ti-manifest.sig"))
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), manifestRaw, manifestSignature) {
		t.Fatalf("manifest signature err=%v", err)
	}
	bundleSignature, err := os.ReadFile(filepath.Join(output, "ti-bundle.sig"))
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), bundleRaw, bundleSignature) {
		t.Fatalf("bundle signature err=%v", err)
	}
	keys := bundle.KeyRegistry{bundle.FamilyTI: {"ti-production-2026": privateKey.Public().(ed25519.PublicKey)}}
	if _, err := bundle.VerifyManifest(manifestRaw, manifestSignature, keys, time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("signed manifest verification: %v", err)
	}
	if _, err := (bundle.Verifier{Keys: keys}).Verify(bundleRaw, bundleSignature, time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("signed bundle verification: %v", err)
	}
}

func TestPublisherSignsRejectsUnsafeKeysAndKeyConfusionWithoutLeaks(t *testing.T) {
	for name, test := range map[string]struct {
		prepare func(t *testing.T) string
	}{
		"public permissions": {func(t *testing.T) string { return privateKeyFile(t, 0o644, 64) }},
		"oversize key":       {func(t *testing.T) string { return privateKeyFile(t, 0o600, 1025) }},
		"symlink key": {func(t *testing.T) string {
			target := privateKeyFile(t, 0o600, 64)
			path := filepath.Join(t.TempDir(), "key-link")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	} {
		t.Run(name, func(t *testing.T) {
			output := t.TempDir()
			if code := run(validArgs(t, output), new(bytes.Buffer), new(bytes.Buffer)); code != 0 {
				t.Fatalf("publish code=%d", code)
			}
			keyPath := test.prepare(t)
			var stdout, stderr bytes.Buffer
			if code := run(signArgs(output, keyPath, "ti-production-2026"), &stdout, &stderr); code != 1 || strings.Contains(stdout.String()+stderr.String(), keyPath) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			for _, name := range []string{"ti-manifest.sig", "ti-bundle.sig"} {
				if _, err := os.Stat(filepath.Join(output, name)); !os.IsNotExist(err) {
					t.Fatalf("unsafe signing left %s: %v", name, err)
				}
			}
		})
	}
}

func TestPublisherSignsRejectsTestAndMismatchedKeyIDs(t *testing.T) {
	useSigningNow(t)
	for _, test := range [][3]string{
		{"test key id", "test-ti-2026", "test-ti-2026"},
		{"mismatched key id", "ti-production-2026", "ti-production-2027"},
	} {
		t.Run(test[0], func(t *testing.T) {
			output := t.TempDir()
			args := validArgs(t, output)
			for index := range args {
				if args[index] == "--key-id" {
					args[index+1] = test[1]
				}
			}
			if code := run(args, new(bytes.Buffer), new(bytes.Buffer)); code != 0 {
				t.Fatalf("publish code=%d", code)
			}
			keyPath := privateKeyFile(t, 0o600, ed25519.PrivateKeySize)
			if code := run(signArgs(output, keyPath, test[2]), new(bytes.Buffer), new(bytes.Buffer)); code != 1 {
				t.Fatalf("sign code=%d", code)
			}
		})
	}
}

func TestPublisherSignsRejectsExpiredReleaseAtSigningTime(t *testing.T) {
	useSigningNow(t)
	output := t.TempDir()
	args := validArgs(t, output)
	replaceFlagValue(args, "--generated-at", "2020-01-02T00:00:00Z")
	replaceFlagValue(args, "--valid-from", "2020-01-01T00:00:00Z")
	replaceFlagValue(args, "--valid-until", "2020-01-03T00:00:00Z")
	if code := run(args, new(bytes.Buffer), new(bytes.Buffer)); code != 0 {
		t.Fatalf("publish code=%d", code)
	}
	keyPath := privateKeyFile(t, 0o600, ed25519.PrivateKeySize)
	if code := run(signArgs(output, keyPath, "ti-production-2026"), new(bytes.Buffer), new(bytes.Buffer)); code != 1 {
		t.Fatalf("expired release sign code=%d", code)
	}
}

func TestPublisherSignsRejectsNoncanonicalKeyIDBeforeOutput(t *testing.T) {
	output := t.TempDir()
	args := validArgs(t, output)
	replaceFlagValue(args, "--key-id", "ti production 2026")
	if code := run(args, new(bytes.Buffer), new(bytes.Buffer)); code != 0 {
		t.Fatalf("publish code=%d", code)
	}
	keyPath := privateKeyFile(t, 0o600, ed25519.PrivateKeySize)
	var stdout, stderr bytes.Buffer
	if code := run(signArgs(output, keyPath, "ti production 2026"), &stdout, &stderr); code != 1 || stdout.Len() != 0 || strings.Contains(stderr.String(), "ti production 2026") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestSignPublicationBytesClearsCallerPrivateKey(t *testing.T) {
	output := t.TempDir()
	if code := run(validArgs(t, output), new(bytes.Buffer), new(bytes.Buffer)); code != 0 {
		t.Fatalf("publish code=%d", code)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(output, "ti-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundleRaw, err := os.ReadFile(filepath.Join(output, "ti-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("clear private signing bytes"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	manifestSignature, bundleSignature, err := signPublicationBytes(manifestRaw, bundleRaw, privateKey)
	if err != nil || !ed25519.Verify(publicKey, manifestRaw, manifestSignature) || !ed25519.Verify(publicKey, bundleRaw, bundleSignature) {
		t.Fatalf("signatures invalid: %v", err)
	}
	for index, value := range privateKey {
		if value != 0 {
			t.Fatalf("private key byte %d retained", index)
		}
	}
}

func TestPublisherSignsRejectsArtifactChangedAfterRead(t *testing.T) {
	useSigningNow(t)
	output := t.TempDir()
	if code := run(validArgs(t, output), new(bytes.Buffer), new(bytes.Buffer)); code != 0 {
		t.Fatalf("publish code=%d", code)
	}
	bundlePath := filepath.Join(output, "ti-bundle.json")
	oldHook := afterSigningInputsReadForRun
	t.Cleanup(func() { afterSigningInputsReadForRun = oldHook })
	afterSigningInputsReadForRun = func() {
		raw, err := os.ReadFile(bundlePath)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-2] ^= 1
		if err := os.WriteFile(bundlePath, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := privateKeyFile(t, 0o600, ed25519.PrivateKeySize)
	if code := run(signArgs(output, keyPath, "ti-production-2026"), new(bytes.Buffer), new(bytes.Buffer)); code != 1 {
		t.Fatalf("changed artifact sign code=%d", code)
	}
	for _, name := range []string{"ti-manifest.sig", "ti-bundle.sig"} {
		if _, err := os.Stat(filepath.Join(output, name)); !os.IsNotExist(err) {
			t.Fatalf("changed artifact left %s: %v", name, err)
		}
	}
}

func TestWriteSignaturePairFailureLeavesNoPartialSignedPublication(t *testing.T) {
	output := t.TempDir()
	for _, name := range []string{"ti-manifest.json", "ti-bundle.json"} {
		if err := os.WriteFile(filepath.Join(output, name), []byte("unsigned"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	writer := func(path string, raw []byte) error {
		writes++
		if writes == 2 {
			return errors.New("injected second signature failure")
		}
		return writeExclusive(path, raw)
	}
	if err := writeSignaturePair(output, []byte("manifest signature"), []byte("bundle signature"), writer); err == nil {
		t.Fatal("second signature failure accepted")
	}
	for _, name := range []string{"ti-manifest.sig", "ti-bundle.sig"} {
		if _, err := os.Stat(filepath.Join(output, name)); !os.IsNotExist(err) {
			t.Fatalf("partial signed publication left %s: %v", name, err)
		}
	}
}

func replaceFlagValue(args []string, flag, value string) {
	for index := range args {
		if args[index] == flag {
			args[index+1] = value
			return
		}
	}
}

func useSigningNow(t *testing.T) {
	t.Helper()
	old := signingNowForRun
	signingNowForRun = func() time.Time { return time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { signingNowForRun = old })
}

func signArgs(output, keyPath, keyID string) []string {
	return []string{"sign", "--manifest-file", filepath.Join(output, "ti-manifest.json"), "--bundle-file", filepath.Join(output, "ti-bundle.json"), "--private-key-file", keyPath, "--key-id", keyID, "--output-dir", output}
}

func privateKeyFile(t *testing.T, mode os.FileMode, size int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-key")
	if err := os.WriteFile(path, bytes.Repeat([]byte("s"), size), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunRejectsImplicitOrNonAbsolutePaths(t *testing.T) {
	for name, args := range map[string][]string{
		"no sources":      {"--version", "2026.08.14"},
		"relative source": {"--osv-source", "source.json"},
		"relative output": {"--output-dir", "output"},
	} {
		t.Run(name, func(t *testing.T) {
			if code := run(args, new(bytes.Buffer), new(bytes.Buffer)); code != 2 {
				t.Fatalf("code=%d", code)
			}
		})
	}
}

func TestRunRefusesToOverwritePublicationArtifacts(t *testing.T) {
	output := t.TempDir()
	if err := os.WriteFile(filepath.Join(output, "ti-bundle.json"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run(validArgs(t, output), new(bytes.Buffer), new(bytes.Buffer)); code != 1 {
		t.Fatalf("code=%d", code)
	}
	raw, err := os.ReadFile(filepath.Join(output, "ti-bundle.json"))
	if err != nil || string(raw) != "existing" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
}

func validArgs(t *testing.T, output string) []string {
	t.Helper()
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		"--osv-source", filepath.Join(repositoryRoot, "internal", "tipublish", "testdata", "osv-vulnerable.json"),
		"--osv-license", "CC-BY-4.0", "--osv-base-url", "https://osv.dev/vulnerability/",
		"--version", "2026.08.14", "--sequence", "42", "--key-id", "ti-production-2026",
		"--generated-at", "2026-08-14T00:00:00Z", "--valid-from", "2026-08-13T23:00:00Z", "--valid-until", "2026-08-21T00:00:00Z",
		"--output-dir", output,
	}
}
