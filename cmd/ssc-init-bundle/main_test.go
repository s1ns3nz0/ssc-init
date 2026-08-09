package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestRunSignsExactValidatedBytesWithEnvironmentOwnedSeed(t *testing.T) {
	seed := sha256.Sum256([]byte("publisher command fixture"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	t.Setenv("SSC_INIT_TI_BUNDLE_SIGNING_SEED_BASE64", base64.StdEncoding.EncodeToString(seed[:]))
	raw := []byte(`{"schemaVersion":"ssc-init.bundle.v1","family":"ti","version":"2026.08.10","sequence":1,"keyId":"publisher","generatedAt":"2026-08-10T00:00:00Z","validFrom":"2026-08-10T00:00:00Z","validUntil":"2026-08-20T00:00:00Z","payload":{"records":[]}}`)
	directory := t.TempDir()
	source, signaturePath := filepath.Join(directory, "bundle.json"), filepath.Join(directory, "bundle.sig")
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"sign", "--family", "ti", "--from", source, "--signature", signaturePath}); code != 0 {
		t.Fatalf("code=%d", code)
	}
	signature, err := os.ReadFile(signaturePath)
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), raw, signature) {
		t.Fatalf("signature invalid err=%v", err)
	}
}
